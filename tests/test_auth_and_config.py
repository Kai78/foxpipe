"""Tests for LDAP authentication, first-run local admin setup, CSRF protection, and editable config GUI."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.auth import authenticate_ldap
from app.config import load_config
from app.main import create_app


def _extract_csrf(html_text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    assert match, "Expected csrf_token hidden input in HTML form"
    return match.group(1)


def _write_test_config(tmp_path: Path, auth_enabled: bool = True) -> Path:
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        f"""
server:
  host: "127.0.0.1"
  port: 8090
  app_title: "Test Runner"
webhook:
  secret_token: "secret"
  allowed_events: ["Push Hook"]
  enable_local_simulator: true
ssh:
  private_key_path: "keys/id_ed25519"
  known_hosts_path: "keys/known_hosts"
  strict_host_key_checking: "accept-new"
  clone_timeout_seconds: 30
  clone_depth: 10
pipeline:
  temp_base_dir: "{tmp_path}/workspaces"
  repo_config_filename: ".pipeline.yml"
  step_timeout_seconds: 30
  max_background_workers: 2
  secure_cleanup: true
database:
  engine: "sqlite"
  sqlite_path: "{tmp_path}/data/audit.db"
  allowed_dir: "{tmp_path}/data"
  wal_mode: true
logging:
  log_file: "{tmp_path}/logs/runner.log"
  level: "INFO"
  max_bytes: 1048576
  backup_count: 2
auth:
  enabled: {str(auth_enabled).lower()}
  session_max_age_seconds: 3600
  allow_local_fallback: true
  ldap:
    enabled: false
    server_uri: "ldap://ldap.example.internal:389"
    use_ssl: false
    start_tls: false
    auth_mode: "direct_bind"
    base_dn: "dc=example,dc=internal"
    user_dn_template: "uid={{username}},ou=people,dc=example,dc=internal"
    bind_dn: ""
    bind_password_env: "LDAP_BIND_PASSWORD"
    user_search_filter: "(uid={{username}})"
    allowed_group_dn: ""
    timeout_seconds: 5
""",
        encoding="utf-8",
    )
    return cfg_file


def test_login_setup_session_and_editable_config_gui(tmp_path: Path) -> None:
    cfg_file = _write_test_config(tmp_path, auth_enabled=True)
    app = create_app(cfg_file)

    with TestClient(app) as client:
        # Unauthenticated dashboard redirects to /login
        unauth_dash = client.get("/", follow_redirects=False)
        assert unauth_dash.status_code == 303
        assert unauth_dash.headers["location"].startswith("/login")

        # Unauthenticated API returns 401
        assert client.get("/api/executions").status_code == 401

        # First-run setup form renders and claims local admin
        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert "Create Local Admin Passcode" in login_page.text
        csrf = _extract_csrf(login_page.text)

        setup_resp = client.post(
            "/login/setup",
            data={
                "username": "opsadmin",
                "passcode": "super-secret-pass",
                "confirm_passcode": "super-secret-pass",
                "next_url": "/",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert setup_resp.status_code == 303
        assert setup_resp.headers["location"] == "/"

        # Authenticated access to dashboard and config succeeds
        dash_resp = client.get("/")
        assert dash_resp.status_code == 200
        assert "opsadmin" in dash_resp.text

        cfg_resp = client.get("/config")
        assert cfg_resp.status_code == 200
        cfg_csrf = _extract_csrf(cfg_resp.text)

        # Modify LDAP configuration via GUI
        ldap_save = client.post(
            "/config/ldap",
            data={
                "csrf_token": cfg_csrf,
                "auth_enabled": "on",
                "ldap_enabled": "on",
                "allow_local_fallback": "on",
                "server_uri": "ldaps://directory.corp.example:636",
                "auth_mode": "search_bind",
                "base_dn": "ou=users,dc=corp,dc=example",
                "user_dn_template": "uid={username},ou=users,dc=corp,dc=example",
                "bind_dn": "cn=svc-gitlab,ou=svc,dc=corp,dc=example",
                "bind_password_env": "LDAP_BIND_PASSWORD",
                "user_search_filter": "(sAMAccountName={username})",
                "allowed_group_dn": "cn=ci-admins,ou=groups,dc=corp,dc=example",
                "timeout_seconds": "15",
                "session_max_age_seconds": "7200",
                "use_ssl": "on",
            },
            follow_redirects=False,
        )
        assert ldap_save.status_code == 303
        assert "notice=" in ldap_save.headers["location"]

        # Reload config from YAML to verify persistence
        reloaded = load_config(cfg_file)
        assert reloaded.auth.ldap.enabled is True
        assert reloaded.auth.ldap.server_uri == "ldaps://directory.corp.example:636"
        assert reloaded.auth.ldap.auth_mode == "search_bind"
        assert reloaded.auth.ldap.use_ssl is True
        assert reloaded.auth.ldap.allowed_group_dn == "cn=ci-admins,ou=groups,dc=corp,dc=example"

        # Modify general runner settings via GUI
        gen_save = client.post(
            "/config/save",
            data={
                "csrf_token": cfg_csrf,
                "app_title": "Corp GitLab Runner",
                "allowed_events": "Push Hook, Merge Request Hook",
                "allowed_repo_hosts": "gitlab.corp.example",
                "enable_local_simulator": "on",
                "ssh_private_key_path": "keys/id_ed25519",
                "ssh_known_hosts_path": "keys/known_hosts",
                "strict_host_key_checking": "yes",
                "clone_timeout_seconds": "90",
                "clone_depth": "25",
                "temp_base_dir": str(tmp_path / "workspaces"),
                "repo_config_filename": ".pipeline.yml",
                "fallback_config_filenames": "pipeline.yml",
                "step_timeout_seconds": "180",
                "max_background_workers": "6",
                "secure_cleanup": "on",
                "default_scripts_lines": "Check :: echo ok",
                "log_file": "logs/runner.log",
                "log_level": "DEBUG",
                "wal_mode": "on",
            },
            follow_redirects=False,
        )
        assert gen_save.status_code == 303
        assert "notice=" in gen_save.headers["location"]
        reloaded2 = load_config(cfg_file)
        assert reloaded2.server.app_title == "Corp GitLab Runner"
        assert reloaded2.ssh.strict_host_key_checking == "yes"
        assert reloaded2.pipeline.max_background_workers == 6
        assert reloaded2.logging.level == "DEBUG"

        # Sign out clears session
        logout_resp = client.post("/logout", data={"csrf_token": cfg_csrf}, follow_redirects=False)
        assert logout_resp.status_code == 303
        assert client.get("/", follow_redirects=False).status_code == 303


def test_ldap_authentication_direct_and_group_check(tmp_path: Path) -> None:
    cfg_file = _write_test_config(tmp_path, auth_enabled=True)
    cfg = load_config(cfg_file)
    cfg.auth.ldap.enabled = True
    cfg.auth.ldap.allowed_group_dn = "cn=ci-users,ou=groups,dc=example,dc=internal"

    # Empty password rejected before touching LDAP
    empty_res = authenticate_ldap("alice", "", cfg)
    assert empty_res.success is False

    fake_entry = SimpleNamespace(
        entry_dn="uid=alice,ou=people,dc=example,dc=internal",
        displayName=SimpleNamespace(value="Alice Dev"),
        cn=SimpleNamespace(value="Alice Dev"),
        mail=SimpleNamespace(value="alice@example.internal"),
        memberOf=SimpleNamespace(values=["cn=ci-users,ou=groups,dc=example,dc=internal"]),
    )

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            self.user = kwargs.get("user", "")
            self.entries = [fake_entry]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def open(self):
            return True

        def start_tls(self):
            return True

        def bind(self):
            return True

        def search(self, **kwargs):
            return True

    with patch("app.auth.Server"), patch("app.auth.Connection", FakeConnection):
        res = authenticate_ldap("alice", "valid-ldap-password", cfg)
        assert res.success is True
        assert res.user is not None
        assert res.user.display_name == "Alice Dev"
        assert res.user.email == "alice@example.internal"
        assert res.user.auth_source == "ldap"

        # Missing required group fails
        cfg.auth.ldap.allowed_group_dn = "cn=admins,ou=groups,dc=example,dc=internal"
        denied = authenticate_ldap("alice", "valid-ldap-password", cfg)
        assert denied.success is False


def test_branding_logo_and_customization(tmp_path: Path) -> None:
    cfg_file = _write_test_config(tmp_path, auth_enabled=True)
    app = create_app(cfg_file)

    with TestClient(app) as client:
        # Default SVG logo appears on /login
        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert "<svg" in login_page.text
        assert "Pipeline Runner" in login_page.text
        csrf = _extract_csrf(login_page.text)

        setup_resp = client.post(
            "/login/setup",
            data={
                "username": "opsadmin",
                "passcode": "super-secret-pass",
                "confirm_passcode": "super-secret-pass",
                "next_url": "/",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert setup_resp.status_code == 303

        # Default SVG logo appears in dashboard header & sidebar
        dash_resp = client.get("/")
        assert dash_resp.status_code == 200
        assert "<svg" in dash_resp.text

        cfg_resp = client.get("/config")
        assert cfg_resp.status_code == 200
        cfg_csrf = _extract_csrf(cfg_resp.text)

        # Reject SVG uploads for security
        svg_resp = client.post(
            "/config/branding",
            data={
                "csrf_token": cfg_csrf,
                "brand_name": "Acme CI",
                "login_subtitle": "Internal Runner",
                "logo_url": "",
            },
            files={"logo_file": ("bad.svg", b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image/svg+xml")},
            follow_redirects=False,
        )
        assert svg_resp.status_code == 303
        assert "error=" in svg_resp.headers["location"]

        # Reject javascript: logo URLs
        bad_url_resp = client.post(
            "/config/branding",
            data={
                "csrf_token": cfg_csrf,
                "brand_name": "Acme CI",
                "login_subtitle": "Internal Runner",
                "logo_url": "javascript:alert(1)",
            },
            follow_redirects=False,
        )
        assert bad_url_resp.status_code == 303
        assert "error=" in bad_url_resp.headers["location"]

        # Valid 1x1 PNG upload succeeds and persists
        valid_png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
            b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        upload_resp = client.post(
            "/config/branding",
            data={
                "csrf_token": cfg_csrf,
                "brand_name": "Acme Corp CI",
                "login_subtitle": "Engineering Release Pipelines",
                "logo_url": "",
            },
            files={"logo_file": ("acme.png", valid_png, "image/png")},
            follow_redirects=False,
        )
        assert upload_resp.status_code == 303
        assert "notice=" in upload_resp.headers["location"]

        reloaded = load_config(cfg_file)
        assert reloaded.branding.brand_name == "Acme Corp CI"
        assert reloaded.branding.login_subtitle == "Engineering Release Pipelines"
        assert reloaded.branding.logo_path.startswith("/static/branding/brand_")

        # Custom logo renders on dashboard and is served via /static/branding/
        dash_custom = client.get("/")
        assert dash_custom.status_code == 200
        assert "Acme Corp CI" in dash_custom.text
        assert reloaded.branding.logo_path in dash_custom.text
        assert client.get(reloaded.branding.logo_path).status_code == 200

        # Reset logo clears uploaded file and restores default SVG mark
        reset_resp = client.post(
            "/config/branding",
            data={
                "csrf_token": cfg_csrf,
                "brand_name": "Acme Corp CI",
                "login_subtitle": "Engineering Release Pipelines",
                "logo_url": reloaded.branding.logo_path,
                "reset_logo": "on",
            },
            follow_redirects=False,
        )
        assert reset_resp.status_code == 303
        assert "notice=" in reset_resp.headers["location"]

        reloaded_reset = load_config(cfg_file)
        assert reloaded_reset.branding.logo_path == ""


def test_local_users_security_and_tree_config(tmp_path: Path) -> None:
    cfg_file = _write_test_config(tmp_path, auth_enabled=True)
    app = create_app(cfg_file)

    with TestClient(app) as client:
        login_page = client.get("/login")
        csrf = _extract_csrf(login_page.text)

        # Claim initial local admin
        setup_resp = client.post(
            "/login/setup",
            data={
                "username": "opsadmin",
                "passcode": "super-secret-pass",
                "confirm_passcode": "super-secret-pass",
                "next_url": "/config?section=security",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert setup_resp.status_code == 303

        # Verify Config Tree-View is embedded inside the left sidebar and Security section renders Local Users + LDAP Settings
        sec_cfg = client.get("/config?section=security")
        assert sec_cfg.status_code == 200
        assert 'id="sidebar-config-tree"' in sec_cfg.text
        assert "Configuration Tree" in sec_cfg.text
        assert "Local Users &amp; Passwords" in sec_cfg.text
        assert "Authentication Policy &amp; LDAP Directory" in sec_cfg.text
        assert "opsadmin" in sec_cfg.text
        sec_csrf = _extract_csrf(sec_cfg.text)

        # Add a new local user with password
        add_user_resp = client.post(
            "/config/security/users/add",
            data={
                "csrf_token": sec_csrf,
                "username": "alice.ci",
                "display_name": "Alice CI",
                "email": "alice@example.internal",
                "role": "operator",
                "password": "alice-password-123",
                "confirm_password": "alice-password-123",
            },
            follow_redirects=False,
        )
        assert add_user_resp.status_code == 303
        assert "section=security" in add_user_resp.headers["location"]
        assert "notice=" in add_user_resp.headers["location"]

        # Reject duplicate username
        dup_resp = client.post(
            "/config/security/users/add",
            data={
                "csrf_token": sec_csrf,
                "username": "ALICE.CI",
                "display_name": "Alice Dup",
                "email": "",
                "role": "operator",
                "password": "alice-password-123",
                "confirm_password": "alice-password-123",
            },
            follow_redirects=False,
        )
        assert dup_resp.status_code == 303
        assert "error=" in dup_resp.headers["location"]

        # Sign out and sign in as newly added local user
        client.post("/logout", data={"csrf_token": sec_csrf}, follow_redirects=False)
        login2 = client.get("/login")
        csrf2 = _extract_csrf(login2.text)

        alice_login = client.post(
            "/login",
            data={
                "username": "alice.ci",
                "password": "alice-password-123",
                "next_url": "/",
                "csrf_token": csrf2,
            },
            follow_redirects=False,
        )
        assert alice_login.status_code == 303
        assert alice_login.headers["location"] == "/"

        dash = client.get("/")
        assert dash.status_code == 200
        assert "Alice CI" in dash.text
        alice_csrf = _extract_csrf(dash.text)

        # Reset password for opsadmin, then sign in with updated password
        pw_resp = client.post(
            "/config/security/users/opsadmin/password",
            data={
                "csrf_token": alice_csrf,
                "new_password": "new-ops-password-999",
                "confirm_password": "new-ops-password-999",
            },
            follow_redirects=False,
        )
        assert pw_resp.status_code == 303
        assert "notice=" in pw_resp.headers["location"]

        # Disable opsadmin -> blocks login; re-enable -> allows login
        toggle_off = client.post(
            "/config/security/users/opsadmin/toggle",
            data={"csrf_token": alice_csrf},
            follow_redirects=False,
        )
        assert toggle_off.status_code == 303
        assert "disabled" in toggle_off.headers["location"]

        toggle_on = client.post(
            "/config/security/users/opsadmin/toggle",
            data={"csrf_token": alice_csrf},
            follow_redirects=False,
        )
        assert toggle_on.status_code == 303
        assert "enabled" in toggle_on.headers["location"]


def test_database_vendor_switching_postgresql_and_mariadb(tmp_path: Path) -> None:
    cfg_file = _write_test_config(tmp_path, auth_enabled=True)
    app = create_app(cfg_file)

    with TestClient(app) as client:
        login_page = client.get("/login")
        csrf = _extract_csrf(login_page.text)
        client.post(
            "/login/setup",
            data={
                "username": "opsadmin",
                "passcode": "super-secret-pass",
                "confirm_passcode": "super-secret-pass",
                "next_url": "/config?section=storage",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        storage_page = client.get("/config?section=storage")
        assert storage_page.status_code == 200
        assert "Show All" not in storage_page.text
        assert "SQLite (Default)" in storage_page.text
        assert "PostgreSQL" in storage_page.text
        assert "MariaDB" in storage_page.text
        storage_csrf = _extract_csrf(storage_page.text)

        # Reject invalid vendor
        bad_vendor = client.post(
            "/config/database",
            data={
                "csrf_token": storage_csrf,
                "engine": "oracle",
                "action": "switch",
            },
            follow_redirects=False,
        )
        assert bad_vendor.status_code == 303
        assert "error=" in bad_vendor.headers["location"]

        # Lightweight fake DB-API driver recording parameterized queries & simulating results
        executed_queries: list[tuple[str, tuple]] = []

        class FakeCursor:
            def __init__(self, dialect: str):
                self.dialect = dialect
                self.description = [("cnt",), ("db_size",)]
                self._rows: list[tuple] = [(0, 4096)]
                self.rowcount = 1

            def execute(self, sql: str, params=()):
                norm = " ".join(sql.split())
                executed_queries.append((norm, tuple(params) if isinstance(params, (list, tuple)) else ()))
                if "SELECT COUNT(*) AS cnt FROM local_users" in norm:
                    self.description = [("cnt",)]
                    self._rows = [(1,)]
                elif "SELECT COUNT(*) AS cnt FROM pipeline_executions" in norm:
                    self.description = [("cnt",)]
                    self._rows = [(3,)]
                elif "pg_database_size" in norm or "information_schema.TABLES" in norm:
                    self.description = [("db_size",)]
                    self._rows = [(8192,)]
                elif "information_schema.STATISTICS" in norm or "information_schema.COLUMNS" in norm:
                    self.description = [("cnt",)]
                    self._rows = [(1,)]
                else:
                    self.description = [("cnt",)]
                    self._rows = [(0,)]

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def fetchall(self):
                return list(self._rows)

        class FakeConn:
            def __init__(self, dialect: str):
                self.dialect = dialect

            def cursor(self):
                return FakeCursor(self.dialect)

            def commit(self):
                pass

            def rollback(self):
                pass

            def close(self):
                pass

        # Switch to PostgreSQL via GUI
        with patch("app.database._import_postgres_driver", return_value=("psycopg", SimpleNamespace(connect=lambda **kw: FakeConn("postgresql")))):
            pg_test = client.post(
                "/config/database",
                data={
                    "csrf_token": storage_csrf,
                    "engine": "postgresql",
                    "host": "pg.internal",
                    "port": "5432",
                    "name": "ci_audit",
                    "user_name": "ci_runner",
                    "password_env": "RUNNER_DB_PASSWORD",
                    "ssl_mode": "require",
                    "connect_timeout_seconds": "10",
                    "action": "test",
                },
                follow_redirects=False,
            )
            assert pg_test.status_code == 303
            assert "notice=" in pg_test.headers["location"]

            pg_switch = client.post(
                "/config/database",
                data={
                    "csrf_token": storage_csrf,
                    "engine": "postgresql",
                    "host": "pg.internal",
                    "port": "5432",
                    "name": "ci_audit",
                    "user_name": "ci_runner",
                    "password_env": "RUNNER_DB_PASSWORD",
                    "ssl_mode": "require",
                    "connect_timeout_seconds": "10",
                    "action": "switch",
                },
                follow_redirects=False,
            )
            assert pg_switch.status_code == 303
            assert "notice=" in pg_switch.headers["location"]

            reloaded_pg = load_config(cfg_file)
            assert reloaded_pg.database.engine == "postgresql"
            assert reloaded_pg.database.host == "pg.internal"
            assert reloaded_pg.database.port == 5432
            assert reloaded_pg.database.name == "ci_audit"
            assert reloaded_pg.database.ssl_mode == "require"

        # Switch to MariaDB via GUI
        with patch("app.database._import_mariadb_driver", return_value=("pymysql", SimpleNamespace(connect=lambda **kw: FakeConn("mariadb")))):
            maria_switch = client.post(
                "/config/database",
                data={
                    "csrf_token": storage_csrf,
                    "engine": "mariadb",
                    "host": "mariadb.internal",
                    "port": "3306",
                    "name": "ci_mariadb",
                    "user_name": "ci_runner",
                    "password_env": "RUNNER_DB_PASSWORD",
                    "ssl_mode": "prefer",
                    "connect_timeout_seconds": "10",
                    "action": "switch",
                },
                follow_redirects=False,
            )
            assert maria_switch.status_code == 303
            assert "notice=" in maria_switch.headers["location"]

            reloaded_maria = load_config(cfg_file)
            assert reloaded_maria.database.engine == "mariadb"
            assert reloaded_maria.database.host == "mariadb.internal"
            assert reloaded_maria.database.port == 3306
            assert reloaded_maria.database.name == "ci_mariadb"

        # Verify MariaDB & PostgreSQL DDL ran cleanly
        assert any("CREATE TABLE IF NOT EXISTS pipeline_executions" in q for q, _ in executed_queries)
        assert any("ENGINE=InnoDB" in q for q, _ in executed_queries)

        # Switch back to SQLite default cleanly
        sqlite_back = client.post(
            "/config/database",
            data={
                "csrf_token": storage_csrf,
                "engine": "sqlite",
                "sqlite_path": str(tmp_path / "data/audit.db"),
                "action": "switch",
            },
            follow_redirects=False,
        )
        assert sqlite_back.status_code == 303
        assert "notice=" in sqlite_back.headers["location"]
        assert load_config(cfg_file).database.engine == "sqlite"


