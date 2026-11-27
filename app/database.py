"""Changeable SQLite audit repository for pipeline executions."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.config import AppConfig
from app.models import ExecutionRecord, ExecutionStatus, LocalUserRecord

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pipeline_executions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    event_name TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    project_name TEXT NOT NULL,
    project_namespace TEXT NOT NULL,
    git_ssh_url TEXT NOT NULL,
    branch_name TEXT NOT NULL,
    tag_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    commit_title TEXT NOT NULL,
    commit_message TEXT NOT NULL,
    triggered_by_name TEXT NOT NULL,
    triggered_by_username TEXT NOT NULL,
    triggered_by_email TEXT NOT NULL,
    mr_iid INTEGER,
    mr_title TEXT NOT NULL DEFAULT '',
    mr_source_branch TEXT NOT NULL DEFAULT '',
    mr_target_branch TEXT NOT NULL DEFAULT '',
    changed_files_json TEXT NOT NULL DEFAULT '[]',
    commits_json TEXT NOT NULL DEFAULT '[]',
    variables_json TEXT NOT NULL DEFAULT '{}',
    steps_json TEXT NOT NULL DEFAULT '[]',
    pipeline_config_source TEXT NOT NULL DEFAULT '',
    temp_workspace_path TEXT NOT NULL DEFAULT '',
    cleanup_verified INTEGER NOT NULL DEFAULT 0,
    clone_duration_ms INTEGER NOT NULL DEFAULT 0,
    total_duration_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    raw_payload_json TEXT NOT NULL DEFAULT '{}',
    config_snapshot_json TEXT NOT NULL DEFAULT '{}',
    rerun_of_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_executions_created_at ON pipeline_executions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_executions_status ON pipeline_executions (status);
CREATE INDEX IF NOT EXISTS idx_executions_object_kind ON pipeline_executions (object_kind);
CREATE INDEX IF NOT EXISTS idx_executions_branch ON pipeline_executions (branch_name);

CREATE TABLE IF NOT EXISTS auth_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_users (
    username TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'operator',
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class AbstractAuditRepository(ABC):
    """Repository interface allowing interchangeable database backends."""

    @abstractmethod
    def initialize(self) -> None:
        """Create schema and verify database readiness."""

    @abstractmethod
    def create_execution(self, record: ExecutionRecord) -> None:
        """Persist a newly queued execution audit record."""

    @abstractmethod
    def update_execution(self, record: ExecutionRecord) -> None:
        """Update an existing execution record with progress or final audit results."""

    @abstractmethod
    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        """Retrieve a single execution record by ID."""

    @abstractmethod
    def list_executions(
        self,
        status: str = "all",
        event_kind: str = "all",
        search: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionRecord]:
        """Query execution history with filtering and search."""

    @abstractmethod
    def get_summary_stats(self) -> dict[str, Any]:
        """Compute aggregate dashboard KPIs."""

    @abstractmethod
    def get_database_info(self) -> dict[str, Any]:
        """Return active database metadata (path, size, row count)."""

    @abstractmethod
    def switch_database(self, new_db_path: Path) -> None:
        """Switch the active database path cleanly at runtime."""

    @abstractmethod
    def get_auth_setting(self, key: str) -> str | None:
        """Retrieve a persisted authentication setting by key."""

    @abstractmethod
    def set_auth_setting(self, key: str, value: str) -> None:
        """Store or update an authentication setting by key."""

    @abstractmethod
    def list_local_users(self) -> list[LocalUserRecord]:
        """Return all configured local users ordered by username."""

    @abstractmethod
    def get_local_user(self, username: str) -> LocalUserRecord | None:
        """Retrieve a local user by username (case-insensitive)."""

    @abstractmethod
    def create_local_user(
        self,
        username: str,
        display_name: str,
        email: str,
        role: str,
        password_hash: str,
    ) -> LocalUserRecord:
        """Insert a new local user with salted password hash."""

    @abstractmethod
    def update_local_user_password(self, username: str, password_hash: str) -> bool:
        """Update a local user's password hash."""

    @abstractmethod
    def set_local_user_active(self, username: str, is_active: bool) -> bool:
        """Enable or disable a local user account."""

    @abstractmethod
    def delete_local_user(self, username: str) -> bool:
        """Delete a local user account."""

    @abstractmethod
    def has_any_local_user(self) -> bool:
        """Return True if at least one local user exists."""


class SQLiteAuditRepository(AbstractAuditRepository):
    """Thread-safe SQLite implementation of the pipeline audit repository."""

    def __init__(self, db_path: Path, wal_mode: bool = True) -> None:
        self._db_path = db_path
        self._wal_mode = wal_mode
        self._lock = threading.RLock()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        if self._wal_mode:
            conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def initialize(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.executescript(SCHEMA_SQL)
                cols = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(pipeline_executions)").fetchall()
                }
                if "config_snapshot_json" not in cols:
                    conn.execute(
                        "ALTER TABLE pipeline_executions ADD COLUMN config_snapshot_json TEXT NOT NULL DEFAULT '{}'"
                    )
                if "rerun_of_id" not in cols:
                    conn.execute(
                        "ALTER TABLE pipeline_executions ADD COLUMN rerun_of_id TEXT NOT NULL DEFAULT ''"
                    )

                user_cnt_row = conn.execute("SELECT COUNT(*) AS cnt FROM local_users").fetchone()
                if user_cnt_row and int(user_cnt_row["cnt"]) == 0:
                    hash_row = conn.execute(
                        "SELECT value FROM auth_settings WHERE key = 'local_admin_hash'"
                    ).fetchone()
                    name_row = conn.execute(
                        "SELECT value FROM auth_settings WHERE key = 'local_admin_username'"
                    ).fetchone()
                    if hash_row and hash_row["value"]:
                        admin_name = str(name_row["value"]) if name_row and name_row["value"] else "admin"
                        now = ExecutionRecord.utc_now_iso()
                        conn.execute(
                            """
                            INSERT INTO local_users (
                                username, display_name, email, role, password_hash, is_active, created_at, updated_at
                            ) VALUES (?, ?, '', 'admin', ?, 1, ?, ?)
                            """,
                            (admin_name, admin_name, str(hash_row["value"]), now, now),
                        )
                conn.commit()

    def switch_database(self, new_db_path: Path) -> None:
        with self._lock:
            self._db_path = new_db_path
            self.initialize()

    def create_execution(self, record: ExecutionRecord) -> None:
        sql = """
        INSERT INTO pipeline_executions (
            id, status, event_name, object_kind, project_name, project_namespace,
            git_ssh_url, branch_name, tag_name, commit_sha, commit_title, commit_message,
            triggered_by_name, triggered_by_username, triggered_by_email,
            mr_iid, mr_title, mr_source_branch, mr_target_branch,
            changed_files_json, commits_json, variables_json, steps_json,
            pipeline_config_source, temp_workspace_path, cleanup_verified,
            clone_duration_ms, total_duration_ms, error_message, raw_payload_json,
            config_snapshot_json, rerun_of_id,
            created_at, started_at, finished_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?
        )
        """
        params = (
            record.id,
            record.status.value,
            record.event_name,
            record.object_kind,
            record.project_name,
            record.project_namespace,
            record.git_ssh_url,
            record.branch_name,
            record.tag_name,
            record.commit_sha,
            record.commit_title,
            record.commit_message,
            record.triggered_by_name,
            record.triggered_by_username,
            record.triggered_by_email,
            record.mr_iid,
            record.mr_title,
            record.mr_source_branch,
            record.mr_target_branch,
            json.dumps(record.changed_files),
            json.dumps(record.commits),
            json.dumps(record.variables),
            json.dumps(record.steps),
            record.pipeline_config_source,
            record.temp_workspace_path,
            1 if record.cleanup_verified else 0,
            record.clone_duration_ms,
            record.total_duration_ms,
            record.error_message,
            json.dumps(record.raw_payload),
            json.dumps(record.config_snapshot),
            record.rerun_of_id,
            record.created_at,
            record.started_at,
            record.finished_at,
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(sql, params)
                conn.commit()

    def update_execution(self, record: ExecutionRecord) -> None:
        sql = """
        UPDATE pipeline_executions SET
            status = ?,
            changed_files_json = ?,
            commits_json = ?,
            variables_json = ?,
            steps_json = ?,
            pipeline_config_source = ?,
            temp_workspace_path = ?,
            cleanup_verified = ?,
            clone_duration_ms = ?,
            total_duration_ms = ?,
            error_message = ?,
            started_at = ?,
            finished_at = ?
        WHERE id = ?
        """
        params = (
            record.status.value,
            json.dumps(record.changed_files),
            json.dumps(record.commits),
            json.dumps(record.variables),
            json.dumps(record.steps),
            record.pipeline_config_source,
            record.temp_workspace_path,
            1 if record.cleanup_verified else 0,
            record.clone_duration_ms,
            record.total_duration_ms,
            record.error_message,
            record.started_at,
            record.finished_at,
            record.id,
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(sql, params)
                conn.commit()

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        sql = "SELECT * FROM pipeline_executions WHERE id = ?"
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(sql, (execution_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def list_executions(
        self,
        status: str = "all",
        event_kind: str = "all",
        search: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionRecord]:
        clauses: list[str] = []
        params: list[Any] = []

        norm_status = status.strip().lower()
        if norm_status and norm_status != "all":
            clauses.append("status = ?")
            params.append(norm_status)

        norm_event = event_kind.strip().lower()
        if norm_event and norm_event != "all":
            clauses.append("object_kind = ?")
            params.append(norm_event)

        norm_search = search.strip()
        if norm_search:
            like = f"%{norm_search}%"
            clauses.append(
                "(id LIKE ? OR project_name LIKE ? OR branch_name LIKE ? OR tag_name LIKE ? "
                "OR commit_title LIKE ? OR commit_sha LIKE ? OR triggered_by_name LIKE ? "
                "OR triggered_by_username LIKE ? OR changed_files_json LIKE ? OR mr_title LIKE ?)"
            )
            params.extend([like] * 10)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
        SELECT * FROM pipeline_executions
        {where_sql}
        ORDER BY created_at DESC, rowid DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(sql, params).fetchall()

        return [self._row_to_record(row) for row in rows]

    def get_summary_stats(self) -> dict[str, Any]:
        sql = """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status IN ('queued', 'cloning', 'running') THEN 1 ELSE 0 END) AS active,
            AVG(CASE WHEN total_duration_ms > 0 THEN total_duration_ms END) AS avg_duration_ms
        FROM pipeline_executions
        """
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(sql).fetchone()

        total = int(row["total"] or 0) if row else 0
        succeeded = int(row["succeeded"] or 0) if row else 0
        failed = int(row["failed"] or 0) if row else 0
        active = int(row["active"] or 0) if row else 0
        avg_ms = round(float(row["avg_duration_ms"])) if row and row["avg_duration_ms"] is not None else 0
        return {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "active": active,
            "avg_duration_ms": avg_ms,
        }

    def get_database_info(self) -> dict[str, Any]:
        with self._lock:
            exists = self._db_path.exists()
            size_bytes = self._db_path.stat().st_size if exists else 0
            row_count = 0
            if exists:
                with self._connect() as conn:
                    res = conn.execute("SELECT COUNT(*) AS cnt FROM pipeline_executions").fetchone()
                    row_count = int(res["cnt"]) if res else 0

        return {
            "engine": "sqlite",
            "path": str(self._db_path),
            "exists": exists,
            "size_bytes": size_bytes,
            "size_human": _format_bytes(size_bytes),
            "row_count": row_count,
            "wal_mode": self._wal_mode,
        }

    def get_auth_setting(self, key: str) -> str | None:
        sql = "SELECT value FROM auth_settings WHERE key = ?"
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(sql, (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_auth_setting(self, key: str, value: str) -> None:
        sql = """
        INSERT INTO auth_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """
        now = ExecutionRecord.utc_now_iso()
        with self._lock:
            with self._connect() as conn:
                conn.execute(sql, (key, value, now))
                conn.commit()

    def list_local_users(self) -> list[LocalUserRecord]:
        sql = "SELECT * FROM local_users ORDER BY LOWER(username) ASC"
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(sql).fetchall()
        return [self._row_to_local_user(row) for row in rows]

    def get_local_user(self, username: str) -> LocalUserRecord | None:
        sql = "SELECT * FROM local_users WHERE LOWER(username) = LOWER(?)"
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(sql, (username.strip(),)).fetchone()
        return self._row_to_local_user(row) if row else None

    def create_local_user(
        self,
        username: str,
        display_name: str,
        email: str,
        role: str,
        password_hash: str,
    ) -> LocalUserRecord:
        now = ExecutionRecord.utc_now_iso()
        sql = """
        INSERT INTO local_users (
            username, display_name, email, role, password_hash, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """
        with self._lock:
            with self._connect() as conn:
                conn.execute(sql, (username, display_name, email, role, password_hash, now, now))
                conn.commit()
        return LocalUserRecord(
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            password_hash=password_hash,
            is_active=True,
            created_at=now,
            updated_at=now,
        )

    def update_local_user_password(self, username: str, password_hash: str) -> bool:
        now = ExecutionRecord.utc_now_iso()
        sql = "UPDATE local_users SET password_hash = ?, updated_at = ? WHERE LOWER(username) = LOWER(?)"
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(sql, (password_hash, now, username.strip()))
                conn.commit()
                return cur.rowcount > 0

    def set_local_user_active(self, username: str, is_active: bool) -> bool:
        now = ExecutionRecord.utc_now_iso()
        sql = "UPDATE local_users SET is_active = ?, updated_at = ? WHERE LOWER(username) = LOWER(?)"
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(sql, (1 if is_active else 0, now, username.strip()))
                conn.commit()
                return cur.rowcount > 0

    def delete_local_user(self, username: str) -> bool:
        sql = "DELETE FROM local_users WHERE LOWER(username) = LOWER(?)"
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(sql, (username.strip(),))
                conn.commit()
                return cur.rowcount > 0

    def has_any_local_user(self) -> bool:
        sql = "SELECT COUNT(*) AS cnt FROM local_users WHERE is_active = 1"
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(sql).fetchone()
        return bool(row and int(row["cnt"]) > 0)

    @staticmethod
    def _row_to_local_user(row: sqlite3.Row) -> LocalUserRecord:
        return LocalUserRecord(
            username=row["username"],
            display_name=row["display_name"] or row["username"],
            email=row["email"] or "",
            role=row["role"] or "operator",
            password_hash=row["password_hash"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ExecutionRecord:
        row_keys = row.keys()
        snapshot_raw = row["config_snapshot_json"] if "config_snapshot_json" in row_keys else "{}"
        rerun_of_raw = row["rerun_of_id"] if "rerun_of_id" in row_keys else ""
        return ExecutionRecord(
            id=row["id"],
            status=ExecutionStatus(row["status"]),
            event_name=row["event_name"],
            object_kind=row["object_kind"],
            project_name=row["project_name"],
            project_namespace=row["project_namespace"],
            git_ssh_url=row["git_ssh_url"],
            branch_name=row["branch_name"],
            tag_name=row["tag_name"],
            commit_sha=row["commit_sha"],
            commit_title=row["commit_title"],
            commit_message=row["commit_message"],
            triggered_by_name=row["triggered_by_name"],
            triggered_by_username=row["triggered_by_username"],
            triggered_by_email=row["triggered_by_email"],
            mr_iid=row["mr_iid"],
            mr_title=row["mr_title"],
            mr_source_branch=row["mr_source_branch"],
            mr_target_branch=row["mr_target_branch"],
            changed_files=json.loads(row["changed_files_json"] or "[]"),
            commits=json.loads(row["commits_json"] or "[]"),
            variables=json.loads(row["variables_json"] or "{}"),
            steps=json.loads(row["steps_json"] or "[]"),
            pipeline_config_source=row["pipeline_config_source"],
            temp_workspace_path=row["temp_workspace_path"],
            cleanup_verified=bool(row["cleanup_verified"]),
            clone_duration_ms=int(row["clone_duration_ms"] or 0),
            total_duration_ms=int(row["total_duration_ms"] or 0),
            error_message=row["error_message"] or "",
            raw_payload=json.loads(row["raw_payload_json"] or "{}"),
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            config_snapshot=json.loads(snapshot_raw or "{}"),
            rerun_of_id=rerun_of_raw or "",
        )


POSTGRES_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS pipeline_executions (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        event_name TEXT NOT NULL,
        object_kind TEXT NOT NULL,
        project_name TEXT NOT NULL,
        project_namespace TEXT NOT NULL,
        git_ssh_url TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        tag_name TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        commit_title TEXT NOT NULL,
        commit_message TEXT NOT NULL,
        triggered_by_name TEXT NOT NULL,
        triggered_by_username TEXT NOT NULL,
        triggered_by_email TEXT NOT NULL,
        mr_iid INTEGER,
        mr_title TEXT NOT NULL DEFAULT '',
        mr_source_branch TEXT NOT NULL DEFAULT '',
        mr_target_branch TEXT NOT NULL DEFAULT '',
        changed_files_json TEXT NOT NULL DEFAULT '[]',
        commits_json TEXT NOT NULL DEFAULT '[]',
        variables_json TEXT NOT NULL DEFAULT '{}',
        steps_json TEXT NOT NULL DEFAULT '[]',
        pipeline_config_source TEXT NOT NULL DEFAULT '',
        temp_workspace_path TEXT NOT NULL DEFAULT '',
        cleanup_verified INTEGER NOT NULL DEFAULT 0,
        clone_duration_ms BIGINT NOT NULL DEFAULT 0,
        total_duration_ms BIGINT NOT NULL DEFAULT 0,
        error_message TEXT NOT NULL DEFAULT '',
        raw_payload_json TEXT NOT NULL DEFAULT '{}',
        config_snapshot_json TEXT NOT NULL DEFAULT '{}',
        rerun_of_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_executions_created_at ON pipeline_executions (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_executions_status ON pipeline_executions (status)",
    "CREATE INDEX IF NOT EXISTS idx_executions_object_kind ON pipeline_executions (object_kind)",
    "CREATE INDEX IF NOT EXISTS idx_executions_branch ON pipeline_executions (branch_name)",
    "ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS config_snapshot_json TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS rerun_of_id TEXT NOT NULL DEFAULT ''",
    """
    CREATE TABLE IF NOT EXISTS auth_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS local_users (
        username TEXT PRIMARY KEY,
        display_name TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'operator',
        password_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
]

MARIADB_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS pipeline_executions (
        id VARCHAR(64) PRIMARY KEY,
        status VARCHAR(32) NOT NULL,
        event_name VARCHAR(128) NOT NULL,
        object_kind VARCHAR(64) NOT NULL,
        project_name VARCHAR(255) NOT NULL,
        project_namespace VARCHAR(255) NOT NULL,
        git_ssh_url VARCHAR(512) NOT NULL,
        branch_name VARCHAR(255) NOT NULL,
        tag_name VARCHAR(255) NOT NULL,
        commit_sha VARCHAR(128) NOT NULL,
        commit_title TEXT NOT NULL,
        commit_message LONGTEXT NOT NULL,
        triggered_by_name VARCHAR(255) NOT NULL,
        triggered_by_username VARCHAR(255) NOT NULL,
        triggered_by_email VARCHAR(255) NOT NULL,
        mr_iid INT NULL,
        mr_title TEXT NOT NULL,
        mr_source_branch VARCHAR(255) NOT NULL,
        mr_target_branch VARCHAR(255) NOT NULL,
        changed_files_json LONGTEXT NOT NULL,
        commits_json LONGTEXT NOT NULL,
        variables_json LONGTEXT NOT NULL,
        steps_json LONGTEXT NOT NULL,
        pipeline_config_source VARCHAR(255) NOT NULL,
        temp_workspace_path VARCHAR(512) NOT NULL,
        cleanup_verified TINYINT(1) NOT NULL DEFAULT 0,
        clone_duration_ms BIGINT NOT NULL DEFAULT 0,
        total_duration_ms BIGINT NOT NULL DEFAULT 0,
        error_message LONGTEXT NOT NULL,
        raw_payload_json LONGTEXT NOT NULL,
        config_snapshot_json LONGTEXT NOT NULL,
        rerun_of_id VARCHAR(64) NOT NULL DEFAULT '',
        created_at VARCHAR(64) NOT NULL,
        started_at VARCHAR(64) NULL,
        finished_at VARCHAR(64) NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS auth_settings (
        `key` VARCHAR(128) PRIMARY KEY,
        `value` LONGTEXT NOT NULL,
        updated_at VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS local_users (
        username VARCHAR(64) PRIMARY KEY,
        display_name VARCHAR(128) NOT NULL DEFAULT '',
        email VARCHAR(255) NOT NULL DEFAULT '',
        role VARCHAR(32) NOT NULL DEFAULT 'operator',
        password_hash VARCHAR(255) NOT NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        created_at VARCHAR(64) NOT NULL,
        updated_at VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
]

MARIADB_INDEXES = [
    ("idx_executions_created_at", "CREATE INDEX idx_executions_created_at ON pipeline_executions (created_at)"),
    ("idx_executions_status", "CREATE INDEX idx_executions_status ON pipeline_executions (status)"),
    ("idx_executions_object_kind", "CREATE INDEX idx_executions_object_kind ON pipeline_executions (object_kind)"),
    ("idx_executions_branch", "CREATE INDEX idx_executions_branch ON pipeline_executions (branch_name)"),
]


def _import_postgres_driver() -> tuple[str, Any]:
    """Return ('psycopg', module) or ('psycopg2', module) if installed."""
    for mod_name in ("psycopg", "psycopg2"):
        try:
            return mod_name, __import__(mod_name)
        except ImportError:
            continue
    raise RuntimeError(
        "PostgreSQL driver is not installed in this Python runtime. "
        "Install 'psycopg[binary]' (or 'psycopg2-binary') from requirements.txt."
    )


def _import_mariadb_driver() -> tuple[str, Any]:
    """Return ('pymysql', module), ('mariadb', module), or ('MySQLdb', module) if installed."""
    for mod_name in ("pymysql", "mariadb", "MySQLdb"):
        try:
            return mod_name, __import__(mod_name)
        except ImportError:
            continue
    raise RuntimeError(
        "MariaDB driver is not installed in this Python runtime. "
        "Install 'PyMySQL' (or 'mariadb') from requirements.txt."
    )


def check_driver_available(engine: str) -> tuple[bool, str]:
    """Report whether the Python driver for the given vendor is available."""
    norm = engine.strip().lower()
    if norm == "sqlite":
        return True, "sqlite3 (built-in)"
    if norm == "postgresql":
        try:
            driver_name, _ = _import_postgres_driver()
            return True, f"{driver_name} installed"
        except RuntimeError as exc:
            return False, str(exc)
    if norm == "mariadb":
        try:
            driver_name, _ = _import_mariadb_driver()
            return True, f"{driver_name} installed"
        except RuntimeError as exc:
            return False, str(exc)
    return False, f"Unsupported database engine '{engine}'."


class _RemoteSQLAuditRepository(AbstractAuditRepository):
    """Shared DB-API %s-parameterized repository logic for PostgreSQL and MariaDB."""

    engine_name: str = ""

    def __init__(
        self,
        host: str,
        port: int,
        name: str,
        user: str,
        password_env: str,
        ssl_mode: str = "prefer",
        connect_timeout_seconds: int = 10,
    ) -> None:
        self._host = host
        self._port = port
        self._name = name
        self._user = user
        self._password_env = password_env or "RUNNER_DB_PASSWORD"
        self._ssl_mode = ssl_mode or "prefer"
        self._connect_timeout_seconds = max(2, int(connect_timeout_seconds))
        self._lock = threading.RLock()

    @abstractmethod
    def _open_connection(self) -> Any:
        """Open a DB-API 2.0 connection to the remote vendor."""

    @contextlib.contextmanager
    def _session(self) -> Iterator[Any]:
        conn = self._open_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            with contextlib.suppress(Exception):
                conn.rollback()
            raise
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    @staticmethod
    def _fetchall_dicts(cur: Any) -> list[dict[str, Any]]:
        cols = [desc[0] for desc in (cur.description or [])]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    @staticmethod
    def _fetchone_dict(cur: Any) -> dict[str, Any] | None:
        cols = [desc[0] for desc in (cur.description or [])]
        row = cur.fetchone()
        return dict(zip(cols, row)) if row is not None else None

    def _safe_dsn_label(self) -> str:
        return f"{self.engine_name}://{self._user}@{self._host}:{self._port}/{self._name}"

    def create_execution(self, record: ExecutionRecord) -> None:
        sql = """
        INSERT INTO pipeline_executions (
            id, status, event_name, object_kind, project_name, project_namespace,
            git_ssh_url, branch_name, tag_name, commit_sha, commit_title, commit_message,
            triggered_by_name, triggered_by_username, triggered_by_email,
            mr_iid, mr_title, mr_source_branch, mr_target_branch,
            changed_files_json, commits_json, variables_json, steps_json,
            pipeline_config_source, temp_workspace_path, cleanup_verified,
            clone_duration_ms, total_duration_ms, error_message, raw_payload_json,
            config_snapshot_json, rerun_of_id,
            created_at, started_at, finished_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s,
            %s, %s, %s
        )
        """
        params = (
            record.id,
            record.status.value,
            record.event_name,
            record.object_kind,
            record.project_name,
            record.project_namespace,
            record.git_ssh_url,
            record.branch_name,
            record.tag_name,
            record.commit_sha,
            record.commit_title,
            record.commit_message,
            record.triggered_by_name,
            record.triggered_by_username,
            record.triggered_by_email,
            record.mr_iid,
            record.mr_title,
            record.mr_source_branch,
            record.mr_target_branch,
            json.dumps(record.changed_files),
            json.dumps(record.commits),
            json.dumps(record.variables),
            json.dumps(record.steps),
            record.pipeline_config_source,
            record.temp_workspace_path,
            1 if record.cleanup_verified else 0,
            record.clone_duration_ms,
            record.total_duration_ms,
            record.error_message,
            json.dumps(record.raw_payload),
            json.dumps(record.config_snapshot),
            record.rerun_of_id,
            record.created_at,
            record.started_at,
            record.finished_at,
        )
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)

    def update_execution(self, record: ExecutionRecord) -> None:
        sql = """
        UPDATE pipeline_executions SET
            status = %s,
            changed_files_json = %s,
            commits_json = %s,
            variables_json = %s,
            steps_json = %s,
            pipeline_config_source = %s,
            temp_workspace_path = %s,
            cleanup_verified = %s,
            clone_duration_ms = %s,
            total_duration_ms = %s,
            error_message = %s,
            started_at = %s,
            finished_at = %s
        WHERE id = %s
        """
        params = (
            record.status.value,
            json.dumps(record.changed_files),
            json.dumps(record.commits),
            json.dumps(record.variables),
            json.dumps(record.steps),
            record.pipeline_config_source,
            record.temp_workspace_path,
            1 if record.cleanup_verified else 0,
            record.clone_duration_ms,
            record.total_duration_ms,
            record.error_message,
            record.started_at,
            record.finished_at,
            record.id,
        )
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        sql = "SELECT * FROM pipeline_executions WHERE id = %s"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (execution_id,))
            row = self._fetchone_dict(cur)
        return self._row_to_record(row) if row else None

    def list_executions(
        self,
        status: str = "all",
        event_kind: str = "all",
        search: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[ExecutionRecord]:
        clauses: list[str] = []
        params: list[Any] = []

        norm_status = status.strip().lower()
        if norm_status and norm_status != "all":
            clauses.append("status = %s")
            params.append(norm_status)

        norm_event = event_kind.strip().lower()
        if norm_event and norm_event != "all":
            clauses.append("object_kind = %s")
            params.append(norm_event)

        norm_search = search.strip()
        if norm_search:
            like = f"%{norm_search}%"
            clauses.append(
                "(LOWER(id) LIKE LOWER(%s) OR LOWER(project_name) LIKE LOWER(%s) "
                "OR LOWER(branch_name) LIKE LOWER(%s) OR LOWER(tag_name) LIKE LOWER(%s) "
                "OR LOWER(commit_title) LIKE LOWER(%s) OR LOWER(commit_sha) LIKE LOWER(%s) "
                "OR LOWER(triggered_by_name) LIKE LOWER(%s) OR LOWER(triggered_by_username) LIKE LOWER(%s) "
                "OR LOWER(changed_files_json) LIKE LOWER(%s) OR LOWER(mr_title) LIKE LOWER(%s))"
            )
            params.extend([like] * 10)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
        SELECT * FROM pipeline_executions
        {where_sql}
        ORDER BY created_at DESC, id DESC
        LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = self._fetchall_dicts(cur)

        return [self._row_to_record(row) for row in rows]

    def get_summary_stats(self) -> dict[str, Any]:
        sql = """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status IN ('queued', 'cloning', 'running') THEN 1 ELSE 0 END) AS active,
            AVG(CASE WHEN total_duration_ms > 0 THEN total_duration_ms END) AS avg_duration_ms
        FROM pipeline_executions
        """
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            row = self._fetchone_dict(cur)

        total = int(row["total"] or 0) if row else 0
        succeeded = int(row["succeeded"] or 0) if row else 0
        failed = int(row["failed"] or 0) if row else 0
        active = int(row["active"] or 0) if row else 0
        avg_ms = round(float(row["avg_duration_ms"])) if row and row["avg_duration_ms"] is not None else 0
        return {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "active": active,
            "avg_duration_ms": avg_ms,
        }

    def switch_database(self, new_db_path: Path) -> None:
        raise ValueError("SQLite file switching is only valid when engine is set to 'sqlite'.")

    def list_local_users(self) -> list[LocalUserRecord]:
        sql = "SELECT * FROM local_users ORDER BY LOWER(username) ASC"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            rows = self._fetchall_dicts(cur)
        return [self._row_to_local_user(row) for row in rows]

    def get_local_user(self, username: str) -> LocalUserRecord | None:
        sql = "SELECT * FROM local_users WHERE LOWER(username) = LOWER(%s)"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (username.strip(),))
            row = self._fetchone_dict(cur)
        return self._row_to_local_user(row) if row else None

    def create_local_user(
        self,
        username: str,
        display_name: str,
        email: str,
        role: str,
        password_hash: str,
    ) -> LocalUserRecord:
        now = ExecutionRecord.utc_now_iso()
        sql = """
        INSERT INTO local_users (
            username, display_name, email, role, password_hash, is_active, created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, 1, %s, %s)
        """
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (username, display_name, email, role, password_hash, now, now))
        return LocalUserRecord(
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            password_hash=password_hash,
            is_active=True,
            created_at=now,
            updated_at=now,
        )

    def update_local_user_password(self, username: str, password_hash: str) -> bool:
        now = ExecutionRecord.utc_now_iso()
        sql = "UPDATE local_users SET password_hash = %s, updated_at = %s WHERE LOWER(username) = LOWER(%s)"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (password_hash, now, username.strip()))
            return cur.rowcount > 0

    def set_local_user_active(self, username: str, is_active: bool) -> bool:
        now = ExecutionRecord.utc_now_iso()
        sql = "UPDATE local_users SET is_active = %s, updated_at = %s WHERE LOWER(username) = LOWER(%s)"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (1 if is_active else 0, now, username.strip()))
            return cur.rowcount > 0

    def delete_local_user(self, username: str) -> bool:
        sql = "DELETE FROM local_users WHERE LOWER(username) = LOWER(%s)"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (username.strip(),))
            return cur.rowcount > 0

    def has_any_local_user(self) -> bool:
        sql = "SELECT COUNT(*) AS cnt FROM local_users WHERE is_active = 1"
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            row = self._fetchone_dict(cur)
        return bool(row and int(row["cnt"]) > 0)

    @staticmethod
    def _row_to_local_user(row: dict[str, Any]) -> LocalUserRecord:
        return LocalUserRecord(
            username=str(row["username"]),
            display_name=str(row.get("display_name") or row["username"]),
            email=str(row.get("email") or ""),
            role=str(row.get("role") or "operator"),
            password_hash=str(row["password_hash"]),
            is_active=bool(row["is_active"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def _row_to_record(row: dict[str, Any]) -> ExecutionRecord:
        return ExecutionRecord(
            id=str(row["id"]),
            status=ExecutionStatus(str(row["status"])),
            event_name=str(row["event_name"]),
            object_kind=str(row["object_kind"]),
            project_name=str(row["project_name"]),
            project_namespace=str(row["project_namespace"]),
            git_ssh_url=str(row["git_ssh_url"]),
            branch_name=str(row["branch_name"]),
            tag_name=str(row["tag_name"]),
            commit_sha=str(row["commit_sha"]),
            commit_title=str(row["commit_title"]),
            commit_message=str(row["commit_message"]),
            triggered_by_name=str(row["triggered_by_name"]),
            triggered_by_username=str(row["triggered_by_username"]),
            triggered_by_email=str(row["triggered_by_email"]),
            mr_iid=row.get("mr_iid"),
            mr_title=str(row.get("mr_title") or ""),
            mr_source_branch=str(row.get("mr_source_branch") or ""),
            mr_target_branch=str(row.get("mr_target_branch") or ""),
            changed_files=json.loads(row.get("changed_files_json") or "[]"),
            commits=json.loads(row.get("commits_json") or "[]"),
            variables=json.loads(row.get("variables_json") or "{}"),
            steps=json.loads(row.get("steps_json") or "[]"),
            pipeline_config_source=str(row.get("pipeline_config_source") or ""),
            temp_workspace_path=str(row.get("temp_workspace_path") or ""),
            cleanup_verified=bool(row.get("cleanup_verified")),
            clone_duration_ms=int(row.get("clone_duration_ms") or 0),
            total_duration_ms=int(row.get("total_duration_ms") or 0),
            error_message=str(row.get("error_message") or ""),
            raw_payload=json.loads(row.get("raw_payload_json") or "{}"),
            created_at=str(row["created_at"]),
            started_at=row.get("started_at"),
            finished_at=row.get("finished_at"),
            config_snapshot=json.loads(row.get("config_snapshot_json") or "{}"),
            rerun_of_id=str(row.get("rerun_of_id") or ""),
        )


class PostgreSQLAuditRepository(_RemoteSQLAuditRepository):
    """Thread-safe PostgreSQL audit repository using psycopg / psycopg2."""

    engine_name = "postgresql"

    def _open_connection(self) -> Any:
        _, pg = _import_postgres_driver()
        password = os.environ.get(self._password_env, "")
        return pg.connect(
            host=self._host,
            port=self._port,
            dbname=self._name,
            user=self._user,
            password=password,
            sslmode=self._ssl_mode,
            connect_timeout=self._connect_timeout_seconds,
        )

    def initialize(self) -> None:
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            for stmt in POSTGRES_STATEMENTS:
                cur.execute(stmt)
            cur.execute("SELECT COUNT(*) AS cnt FROM local_users")
            cnt_row = self._fetchone_dict(cur)
            if cnt_row and int(cnt_row["cnt"]) == 0:
                cur.execute("SELECT value FROM auth_settings WHERE key = %s", ("local_admin_hash",))
                hash_row = self._fetchone_dict(cur)
                cur.execute("SELECT value FROM auth_settings WHERE key = %s", ("local_admin_username",))
                name_row = self._fetchone_dict(cur)
                if hash_row and hash_row.get("value"):
                    admin_name = str(name_row["value"]) if name_row and name_row.get("value") else "admin"
                    now = ExecutionRecord.utc_now_iso()
                    cur.execute(
                        """
                        INSERT INTO local_users (
                            username, display_name, email, role, password_hash, is_active, created_at, updated_at
                        ) VALUES (%s, %s, '', 'admin', %s, 1, %s, %s)
                        """,
                        (admin_name, admin_name, str(hash_row["value"]), now, now),
                    )

    def get_auth_setting(self, key: str) -> str | None:
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM auth_settings WHERE key = %s", (key,))
            row = self._fetchone_dict(cur)
        return str(row["value"]) if row else None

    def set_auth_setting(self, key: str, value: str) -> None:
        now = ExecutionRecord.utc_now_iso()
        sql = """
        INSERT INTO auth_settings (key, value, updated_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
        """
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (key, value, now))

    def get_database_info(self) -> dict[str, Any]:
        size_bytes = 0
        row_count = 0
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS cnt FROM pipeline_executions")
            cnt_row = self._fetchone_dict(cur)
            row_count = int(cnt_row["cnt"]) if cnt_row else 0
            cur.execute("SELECT pg_database_size(current_database()) AS db_size")
            size_row = self._fetchone_dict(cur)
            size_bytes = int(size_row["db_size"] or 0) if size_row else 0

        return {
            "engine": "postgresql",
            "path": self._safe_dsn_label(),
            "exists": True,
            "size_bytes": size_bytes,
            "size_human": _format_bytes(size_bytes),
            "row_count": row_count,
            "wal_mode": False,
        }


class MariaDBAuditRepository(_RemoteSQLAuditRepository):
    """Thread-safe MariaDB / MySQL audit repository using PyMySQL / mariadb."""

    engine_name = "mariadb"

    def _open_connection(self) -> Any:
        driver_name, mod = _import_mariadb_driver()
        password = os.environ.get(self._password_env, "")
        kwargs: dict[str, Any] = {
            "host": self._host,
            "port": self._port,
            "user": self._user,
            "password": password,
            "database": self._name,
            "connect_timeout": self._connect_timeout_seconds,
        }
        if driver_name == "pymysql":
            kwargs["charset"] = "utf8mb4"
            kwargs["autocommit"] = False
            if self._ssl_mode in {"require", "verify-ca", "verify-full"}:
                kwargs["ssl"] = {"check_hostname": self._ssl_mode == "verify-full"}
        elif driver_name == "mariadb":
            kwargs["autocommit"] = False
            if self._ssl_mode in {"require", "verify-ca", "verify-full"}:
                kwargs["ssl"] = True
        return mod.connect(**kwargs)

    def initialize(self) -> None:
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            for stmt in MARIADB_STATEMENTS:
                cur.execute(stmt)

            for idx_name, idx_sql in MARIADB_INDEXES:
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM information_schema.STATISTICS
                    WHERE table_schema = DATABASE() AND table_name = 'pipeline_executions' AND index_name = %s
                    """,
                    (idx_name,),
                )
                idx_row = self._fetchone_dict(cur)
                if not idx_row or int(idx_row["cnt"]) == 0:
                    cur.execute(idx_sql)

            for col_name, alter_sql in (
                (
                    "config_snapshot_json",
                    "ALTER TABLE pipeline_executions ADD COLUMN config_snapshot_json LONGTEXT NOT NULL",
                ),
                (
                    "rerun_of_id",
                    "ALTER TABLE pipeline_executions ADD COLUMN rerun_of_id VARCHAR(64) NOT NULL DEFAULT ''",
                ),
            ):
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM information_schema.COLUMNS
                    WHERE table_schema = DATABASE() AND table_name = 'pipeline_executions' AND column_name = %s
                    """,
                    (col_name,),
                )
                col_row = self._fetchone_dict(cur)
                if not col_row or int(col_row["cnt"]) == 0:
                    cur.execute(alter_sql)

            cur.execute("SELECT COUNT(*) AS cnt FROM local_users")
            cnt_row = self._fetchone_dict(cur)
            if cnt_row and int(cnt_row["cnt"]) == 0:
                cur.execute("SELECT `value` FROM auth_settings WHERE `key` = %s", ("local_admin_hash",))
                hash_row = self._fetchone_dict(cur)
                cur.execute("SELECT `value` FROM auth_settings WHERE `key` = %s", ("local_admin_username",))
                name_row = self._fetchone_dict(cur)
                if hash_row and hash_row.get("value"):
                    admin_name = str(name_row["value"]) if name_row and name_row.get("value") else "admin"
                    now = ExecutionRecord.utc_now_iso()
                    cur.execute(
                        """
                        INSERT INTO local_users (
                            username, display_name, email, role, password_hash, is_active, created_at, updated_at
                        ) VALUES (%s, %s, '', 'admin', %s, 1, %s, %s)
                        """,
                        (admin_name, admin_name, str(hash_row["value"]), now, now),
                    )

    def get_auth_setting(self, key: str) -> str | None:
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute("SELECT `value` FROM auth_settings WHERE `key` = %s", (key,))
            row = self._fetchone_dict(cur)
        return str(row["value"]) if row else None

    def set_auth_setting(self, key: str, value: str) -> None:
        now = ExecutionRecord.utc_now_iso()
        sql = """
        INSERT INTO auth_settings (`key`, `value`, updated_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = VALUES(updated_at)
        """
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute(sql, (key, value, now))

    def get_database_info(self) -> dict[str, Any]:
        size_bytes = 0
        row_count = 0
        with self._lock, self._session() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS cnt FROM pipeline_executions")
            cnt_row = self._fetchone_dict(cur)
            row_count = int(cnt_row["cnt"]) if cnt_row else 0
            cur.execute(
                """
                SELECT COALESCE(SUM(data_length + index_length), 0) AS db_size
                FROM information_schema.TABLES WHERE table_schema = DATABASE()
                """
            )
            size_row = self._fetchone_dict(cur)
            size_bytes = int(size_row["db_size"] or 0) if size_row else 0

        return {
            "engine": "mariadb",
            "path": self._safe_dsn_label(),
            "exists": True,
            "size_bytes": size_bytes,
            "size_human": _format_bytes(size_bytes),
            "row_count": row_count,
            "wal_mode": False,
        }


def create_repository(config: AppConfig) -> AbstractAuditRepository:
    """Factory that builds and initializes the configured audit database backend."""
    engine = config.database.engine.strip().lower()
    if engine == "sqlite":
        db_path = config.resolve_path(config.database.sqlite_path)
        repo: AbstractAuditRepository = SQLiteAuditRepository(db_path=db_path, wal_mode=config.database.wal_mode)
    elif engine == "postgresql":
        repo = PostgreSQLAuditRepository(
            host=config.database.host,
            port=config.database.port,
            name=config.database.name,
            user=config.database.user,
            password_env=config.database.password_env,
            ssl_mode=config.database.ssl_mode,
            connect_timeout_seconds=config.database.connect_timeout_seconds,
        )
    elif engine == "mariadb":
        repo = MariaDBAuditRepository(
            host=config.database.host,
            port=config.database.port,
            name=config.database.name,
            user=config.database.user,
            password_env=config.database.password_env,
            ssl_mode=config.database.ssl_mode,
            connect_timeout_seconds=config.database.connect_timeout_seconds,
        )
    else:
        raise ValueError(f"Unsupported database engine '{engine}'. Supported: sqlite, postgresql, mariadb.")

    repo.initialize()
    return repo


def test_database_connection(config: AppConfig) -> tuple[bool, str]:
    """Verify driver availability, connectivity, and schema readiness for the given DatabaseConfig."""
    engine = config.database.engine.strip().lower()
    try:
        if engine == "sqlite":
            resolved = config.validate_database_path(config.database.sqlite_path)
            repo = SQLiteAuditRepository(db_path=resolved, wal_mode=config.database.wal_mode)
            repo.initialize()
            info = repo.get_database_info()
            return True, f"SQLite connection verified at {config.database.sqlite_path} ({info['row_count']} runs)."

        if engine == "postgresql":
            repo_pg = PostgreSQLAuditRepository(
                host=config.database.host,
                port=config.database.port,
                name=config.database.name,
                user=config.database.user,
                password_env=config.database.password_env,
                ssl_mode=config.database.ssl_mode,
                connect_timeout_seconds=config.database.connect_timeout_seconds,
            )
            repo_pg.initialize()
            info = repo_pg.get_database_info()
            return True, f"PostgreSQL connection verified at {info['path']} ({info['row_count']} runs)."

        if engine == "mariadb":
            repo_maria = MariaDBAuditRepository(
                host=config.database.host,
                port=config.database.port,
                name=config.database.name,
                user=config.database.user,
                password_env=config.database.password_env,
                ssl_mode=config.database.ssl_mode,
                connect_timeout_seconds=config.database.connect_timeout_seconds,
            )
            repo_maria.initialize()
            info = repo_maria.get_database_info()
            return True, f"MariaDB connection verified at {info['path']} ({info['row_count']} runs)."

        return False, f"Unsupported database vendor '{engine}'."
    except Exception as exc:
        return False, f"Database connection failed: {exc}"


def _format_bytes(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.2f} MB"
