"""Configuration loader and runtime settings manager for GitLab SSH Pipeline Runner."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(slots=True)
class ServerConfig:
    """HTTP server binding and application identity."""

    host: str = "0.0.0.0"
    port: int = 8090
    app_title: str = "GitLab SSH Pipeline Runner"
    workers: int = 1


@dataclass(slots=True)
class WebhookConfig:
    """GitLab webhook verification and event filtering."""

    secret_token: str = ""
    allowed_events: list[str] = field(
        default_factory=lambda: ["Push Hook", "Tag Push Hook", "Merge Request Hook", "System Hook"]
    )
    allowed_repo_hosts: list[str] = field(default_factory=list)
    enable_local_simulator: bool = True


@dataclass(slots=True)
class SSHConfig:
    """SSH authentication and Git clone settings."""

    private_key_path: str = "keys/id_ed25519"
    known_hosts_path: str = "keys/known_hosts"
    strict_host_key_checking: str = "accept-new"
    clone_timeout_seconds: int = 120
    clone_depth: int = 50


@dataclass(slots=True)
class DefaultScriptConfig:
    """Fallback script entry when a repository lacks a pipeline config file."""

    name: str
    command: str


@dataclass(slots=True)
class PipelineConfig:
    """Temporary workspace, repository pipeline config, and background worker settings."""

    temp_base_dir: str = "/tmp/gitlab_pipeline_workspaces"
    repo_config_filename: str = ".pipeline.yml"
    fallback_config_filenames: list[str] = field(
        default_factory=lambda: [".gitlab-pipeline.yml", "pipeline.yml"]
    )
    default_scripts: list[DefaultScriptConfig] = field(default_factory=list)
    step_timeout_seconds: int = 300
    max_background_workers: int = 4
    secure_cleanup: bool = True


@dataclass(slots=True)
class DatabaseConfig:
    """Changeable audit database configuration (SQLite default, PostgreSQL, or MariaDB)."""

    engine: str = "sqlite"  # "sqlite" | "postgresql" | "mariadb"
    sqlite_path: str = "data/pipeline_audit.db"
    allowed_dir: str = "data"
    wal_mode: bool = True
    host: str = "127.0.0.1"
    port: int = 5432
    name: str = "pipeline_audit"
    user: str = "pipeline_runner"
    password_env: str = "RUNNER_DB_PASSWORD"
    ssl_mode: str = "prefer"
    connect_timeout_seconds: int = 10


@dataclass(slots=True)
class LoggingConfig:
    """Rotating friendly logfile settings."""

    log_file: str = "logs/pipeline_runner.log"
    level: str = "INFO"
    max_bytes: int = 5_242_880
    backup_count: int = 5


@dataclass(slots=True)
class LDAPConfig:
    """Modifiable LDAP / Active Directory authentication settings."""

    enabled: bool = False
    server_uri: str = "ldap://ldap.example.com:389"
    use_ssl: bool = False
    start_tls: bool = False
    auth_mode: str = "direct_bind"
    base_dn: str = "dc=example,dc=com"
    user_dn_template: str = "uid={username},ou=people,dc=example,dc=com"
    bind_dn: str = ""
    bind_password_env: str = "LDAP_BIND_PASSWORD"
    user_search_filter: str = "(|(uid={username})(sAMAccountName={username})(mail={username}))"
    allowed_group_dn: str = ""
    timeout_seconds: int = 10


@dataclass(slots=True)
class AuthConfig:
    """Dashboard session authentication configuration."""

    enabled: bool = True
    session_max_age_seconds: int = 28_800
    allow_local_fallback: bool = True
    ldap: LDAPConfig = field(default_factory=LDAPConfig)


@dataclass(slots=True)
class BrandingConfig:
    """Customizable brand name, logo, and login subtitle."""

    brand_name: str = "Pipeline Runner"
    logo_path: str = ""
    login_subtitle: str = "GitLab SSH Pipeline Runner"


@dataclass(slots=True)
class AppConfig:
    """Root application configuration loaded from YAML + environment overrides."""

    config_path: Path
    server: ServerConfig = field(default_factory=ServerConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    ssh: SSHConfig = field(default_factory=SSHConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    branding: BrandingConfig = field(default_factory=BrandingConfig)

    def resolve_path(self, raw_path: str) -> Path:
        """Resolve a relative config path against the project root."""
        candidate = Path(raw_path)
        if candidate.is_absolute():
            return candidate
        return (PROJECT_ROOT / candidate).resolve()

    def validate_project_subpath(self, raw_path: str, label: str) -> str:
        """Confine editable relative paths safely inside the project root."""
        cleaned = raw_path.strip()
        if not cleaned:
            raise ValueError(f"{label} cannot be empty.")
        candidate = Path(cleaned)
        resolved = candidate.resolve() if candidate.is_absolute() else (PROJECT_ROOT / candidate).resolve()
        if not resolved.is_relative_to(PROJECT_ROOT):
            raise ValueError(f"{label} must remain inside the application directory.")
        return str(resolved.relative_to(PROJECT_ROOT))

    def validate_database_path(self, new_path: str) -> Path:
        """Ensure a requested SQLite database path stays strictly inside allowed_dir."""
        cleaned = new_path.strip()
        if not cleaned:
            raise ValueError("Database path cannot be empty.")
        if not cleaned.endswith(".db") and not cleaned.endswith(".sqlite") and not cleaned.endswith(".sqlite3"):
            raise ValueError("SQLite database filename must end with .db, .sqlite, or .sqlite3.")

        allowed_base = self.resolve_path(self.database.allowed_dir)
        allowed_base.mkdir(parents=True, exist_ok=True)

        target = Path(cleaned)
        resolved = target.resolve() if target.is_absolute() else (PROJECT_ROOT / target).resolve()

        if not resolved.is_relative_to(allowed_base):
            raise ValueError(
                f"Database path must reside inside the configured data directory ({self.database.allowed_dir}/)."
            )
        return resolved


def validate_ldap_server_uri(uri: str) -> str:
    """Validate LDAP server URI scheme and hostname."""
    cleaned = uri.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
        raise ValueError("LDAP Server URI must begin with ldap:// or ldaps:// and include a hostname.")
    return cleaned


def validate_logo_url(raw_url: str) -> str:
    """Allow empty string, local /static/ paths, or https:// / http:// image URLs."""
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if cleaned.startswith("/static/"):
        if ".." in cleaned:
            raise ValueError("Invalid static logo path.")
        return cleaned
    parsed = urlparse(cleaned)
    if parsed.scheme in {"https", "http"} and parsed.netloc:
        return cleaned
    raise ValueError("Logo URL must be a /static/... path or an https:// or http:// URL.")


SUPPORTED_DB_ENGINES = {"sqlite", "postgresql", "mariadb"}
SUPPORTED_DB_SSL_MODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}


def validate_database_vendor_config(
    engine: str,
    host: str,
    port: int,
    name: str,
    user: str,
    password_env: str,
    ssl_mode: str,
    connect_timeout_seconds: int,
) -> dict[str, Any]:
    """Validate database vendor settings for PostgreSQL and MariaDB safely."""
    clean_engine = engine.strip().lower()
    if clean_engine not in SUPPORTED_DB_ENGINES:
        raise ValueError("Database vendor must be sqlite, postgresql, or mariadb.")

    clean_host = host.strip()
    clean_name = name.strip()
    clean_user = user.strip()
    clean_pw_env = password_env.strip() or "RUNNER_DB_PASSWORD"
    clean_ssl = ssl_mode.strip().lower() or "prefer"

    if clean_engine in {"postgresql", "mariadb"}:
        if not clean_host or any(ch.isspace() for ch in clean_host):
            raise ValueError("Database host must be a valid hostname or IP address without spaces.")
        if not (1 <= int(port) <= 65535):
            raise ValueError("Database port must be between 1 and 65535.")
        if not clean_name or any(ch.isspace() for ch in clean_name):
            raise ValueError("Database name cannot be empty or contain spaces.")
        if not clean_user or any(ch.isspace() for ch in clean_user):
            raise ValueError("Database username cannot be empty or contain spaces.")
        if not clean_pw_env.replace("_", "").isalnum():
            raise ValueError("Password environment variable name must contain only letters, numbers, and underscores.")
        if clean_ssl not in SUPPORTED_DB_SSL_MODES:
            raise ValueError("SSL mode must be one of: disable, allow, prefer, require, verify-ca, verify-full.")

    return {
        "engine": clean_engine,
        "host": clean_host or "127.0.0.1",
        "port": max(1, min(65535, int(port))),
        "name": clean_name or "pipeline_audit",
        "user": clean_user or "pipeline_runner",
        "password_env": clean_pw_env,
        "ssl_mode": clean_ssl if clean_ssl in SUPPORTED_DB_SSL_MODES else "prefer",
        "connect_timeout_seconds": max(2, min(60, int(connect_timeout_seconds))),
    }


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load configuration from YAML file with environment variable overrides."""
    env_path = os.environ.get("RUNNER_CONFIG_PATH", "").strip()
    if env_path and not (env_path.endswith(".yaml") or env_path.endswith(".yml")):
        env_path = ""
    raw_target = Path(config_path) if config_path else Path(env_path or "config.yaml")
    resolved_config_path = raw_target if raw_target.is_absolute() else (PROJECT_ROOT / raw_target).resolve()

    data: dict[str, Any] = {}
    if resolved_config_path.exists():
        with resolved_config_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
            if isinstance(loaded, dict):
                data = loaded

    srv_raw = _as_dict(data.get("server"))
    wh_raw = _as_dict(data.get("webhook"))
    ssh_raw = _as_dict(data.get("ssh"))
    pipe_raw = _as_dict(data.get("pipeline"))
    db_raw = _as_dict(data.get("database"))
    log_raw = _as_dict(data.get("logging"))
    auth_raw = _as_dict(data.get("auth"))
    ldap_raw = _as_dict(auth_raw.get("ldap"))
    brand_raw = _as_dict(data.get("branding"))

    default_scripts = [
        DefaultScriptConfig(
            name=str(item.get("name", "Pipeline Step")),
            command=str(item.get("command", "")),
        )
        for item in pipe_raw.get("default_scripts", [])
        if isinstance(item, dict) and item.get("command")
    ]
    if not default_scripts:
        default_scripts = [
            DefaultScriptConfig(name="Inspect Workspace", command="git status --short && ls -la"),
            DefaultScriptConfig(
                name="Inspect GitLab Environment",
                command="env | grep -E '^(GITLAB_|CI_|PIPELINE_)' | sort",
            ),
        ]

    secret_override = os.environ.get("GITLAB_WEBHOOK_SECRET", "").strip()
    db_path_override = os.environ.get("RUNNER_DB_PATH", "").strip()
    if db_path_override and not (
        db_path_override.endswith(".db")
        or db_path_override.endswith(".sqlite")
        or db_path_override.endswith(".sqlite3")
    ):
        db_path_override = ""

    engine_override = os.environ.get("RUNNER_DB_ENGINE", "").strip().lower()
    raw_engine = engine_override or str(db_raw.get("engine", "sqlite")).strip().lower()
    if raw_engine not in SUPPORTED_DB_ENGINES:
        raw_engine = "sqlite"
    default_port = 3306 if raw_engine == "mariadb" else 5432

    return AppConfig(
        config_path=resolved_config_path,
        server=ServerConfig(
            host=str(srv_raw.get("host", "0.0.0.0")),
            port=int(srv_raw.get("port", 8090)),
            app_title=str(srv_raw.get("app_title", "GitLab SSH Pipeline Runner")),
            workers=int(srv_raw.get("workers", 1)),
        ),
        webhook=WebhookConfig(
            secret_token=secret_override or str(wh_raw.get("secret_token", "")),
            allowed_events=[
                str(e)
                for e in wh_raw.get("allowed_events", ["Push Hook", "Tag Push Hook", "Merge Request Hook", "System Hook"])
            ],
            allowed_repo_hosts=[str(h) for h in wh_raw.get("allowed_repo_hosts", [])],
            enable_local_simulator=bool(wh_raw.get("enable_local_simulator", True)),
        ),
        ssh=SSHConfig(
            private_key_path=str(ssh_raw.get("private_key_path", "keys/id_ed25519")),
            known_hosts_path=str(ssh_raw.get("known_hosts_path", "keys/known_hosts")),
            strict_host_key_checking=str(ssh_raw.get("strict_host_key_checking", "accept-new")),
            clone_timeout_seconds=int(ssh_raw.get("clone_timeout_seconds", 120)),
            clone_depth=int(ssh_raw.get("clone_depth", 50)),
        ),
        pipeline=PipelineConfig(
            temp_base_dir=str(pipe_raw.get("temp_base_dir", "/tmp/gitlab_pipeline_workspaces")),
            repo_config_filename=str(pipe_raw.get("repo_config_filename", ".pipeline.yml")),
            fallback_config_filenames=[
                str(f) for f in pipe_raw.get("fallback_config_filenames", [".gitlab-pipeline.yml", "pipeline.yml"])
            ],
            default_scripts=default_scripts,
            step_timeout_seconds=int(pipe_raw.get("step_timeout_seconds", 300)),
            max_background_workers=max(1, int(pipe_raw.get("max_background_workers", 4))),
            secure_cleanup=bool(pipe_raw.get("secure_cleanup", True)),
        ),
        database=DatabaseConfig(
            engine=raw_engine,
            sqlite_path=db_path_override or str(db_raw.get("sqlite_path", "data/pipeline_audit.db")),
            allowed_dir=str(db_raw.get("allowed_dir", "data")),
            wal_mode=bool(db_raw.get("wal_mode", True)),
            host=str(db_raw.get("host", "127.0.0.1")),
            port=int(db_raw.get("port", default_port)),
            name=str(db_raw.get("name", "pipeline_audit")),
            user=str(db_raw.get("user", "pipeline_runner")),
            password_env=str(db_raw.get("password_env", "RUNNER_DB_PASSWORD")),
            ssl_mode=str(db_raw.get("ssl_mode", "prefer")),
            connect_timeout_seconds=max(2, int(db_raw.get("connect_timeout_seconds", 10))),
        ),
        logging=LoggingConfig(
            log_file=str(log_raw.get("log_file", "logs/pipeline_runner.log")),
            level=str(log_raw.get("level", "INFO")).upper(),
            max_bytes=int(log_raw.get("max_bytes", 5_242_880)),
            backup_count=int(log_raw.get("backup_count", 5)),
        ),
        auth=AuthConfig(
            enabled=bool(auth_raw.get("enabled", True)),
            session_max_age_seconds=max(300, int(auth_raw.get("session_max_age_seconds", 28_800))),
            allow_local_fallback=bool(auth_raw.get("allow_local_fallback", True)),
            ldap=LDAPConfig(
                enabled=bool(ldap_raw.get("enabled", False)),
                server_uri=str(ldap_raw.get("server_uri", "ldap://ldap.example.com:389")),
                use_ssl=bool(ldap_raw.get("use_ssl", False)),
                start_tls=bool(ldap_raw.get("start_tls", False)),
                auth_mode=str(ldap_raw.get("auth_mode", "direct_bind")),
                base_dn=str(ldap_raw.get("base_dn", "dc=example,dc=com")),
                user_dn_template=str(ldap_raw.get("user_dn_template", "uid={username},ou=people,dc=example,dc=com")),
                bind_dn=str(ldap_raw.get("bind_dn", "")),
                bind_password_env=str(ldap_raw.get("bind_password_env", "LDAP_BIND_PASSWORD")),
                user_search_filter=str(
                    ldap_raw.get("user_search_filter", "(|(uid={username})(sAMAccountName={username})(mail={username}))")
                ),
                allowed_group_dn=str(ldap_raw.get("allowed_group_dn", "")),
                timeout_seconds=max(2, int(ldap_raw.get("timeout_seconds", 10))),
            ),
        ),
        branding=BrandingConfig(
            brand_name=str(brand_raw.get("brand_name", "Pipeline Runner")),
            logo_path=str(brand_raw.get("logo_path", "")),
            login_subtitle=str(brand_raw.get("login_subtitle", "GitLab SSH Pipeline Runner")),
        ),
    )


def save_config_to_yaml(config: AppConfig) -> None:
    """Serialize the complete AppConfig cleanly back to config.yaml."""
    payload: dict[str, Any] = {
        "server": {
            "host": config.server.host,
            "port": config.server.port,
            "app_title": config.server.app_title,
            "workers": config.server.workers,
        },
        "webhook": {
            "secret_token": config.webhook.secret_token,
            "allowed_events": config.webhook.allowed_events,
            "allowed_repo_hosts": config.webhook.allowed_repo_hosts,
            "enable_local_simulator": config.webhook.enable_local_simulator,
        },
        "ssh": {
            "private_key_path": config.ssh.private_key_path,
            "known_hosts_path": config.ssh.known_hosts_path,
            "strict_host_key_checking": config.ssh.strict_host_key_checking,
            "clone_timeout_seconds": config.ssh.clone_timeout_seconds,
            "clone_depth": config.ssh.clone_depth,
        },
        "pipeline": {
            "temp_base_dir": config.pipeline.temp_base_dir,
            "repo_config_filename": config.pipeline.repo_config_filename,
            "fallback_config_filenames": config.pipeline.fallback_config_filenames,
            "default_scripts": [
                {"name": s.name, "command": s.command} for s in config.pipeline.default_scripts
            ],
            "step_timeout_seconds": config.pipeline.step_timeout_seconds,
            "max_background_workers": config.pipeline.max_background_workers,
            "secure_cleanup": config.pipeline.secure_cleanup,
        },
        "database": {
            "engine": config.database.engine,
            "sqlite_path": config.database.sqlite_path,
            "allowed_dir": config.database.allowed_dir,
            "wal_mode": config.database.wal_mode,
            "host": config.database.host,
            "port": config.database.port,
            "name": config.database.name,
            "user": config.database.user,
            "password_env": config.database.password_env,
            "ssl_mode": config.database.ssl_mode,
            "connect_timeout_seconds": config.database.connect_timeout_seconds,
        },
        "logging": {
            "log_file": config.logging.log_file,
            "level": config.logging.level,
            "max_bytes": config.logging.max_bytes,
            "backup_count": config.logging.backup_count,
        },
        "auth": {
            "enabled": config.auth.enabled,
            "session_max_age_seconds": config.auth.session_max_age_seconds,
            "allow_local_fallback": config.auth.allow_local_fallback,
            "ldap": {
                "enabled": config.auth.ldap.enabled,
                "server_uri": config.auth.ldap.server_uri,
                "use_ssl": config.auth.ldap.use_ssl,
                "start_tls": config.auth.ldap.start_tls,
                "auth_mode": config.auth.ldap.auth_mode,
                "base_dn": config.auth.ldap.base_dn,
                "user_dn_template": config.auth.ldap.user_dn_template,
                "bind_dn": config.auth.ldap.bind_dn,
                "bind_password_env": config.auth.ldap.bind_password_env,
                "user_search_filter": config.auth.ldap.user_search_filter,
                "allowed_group_dn": config.auth.ldap.allowed_group_dn,
                "timeout_seconds": config.auth.ldap.timeout_seconds,
            },
        },
        "branding": {
            "brand_name": config.branding.brand_name,
            "logo_path": config.branding.logo_path,
            "login_subtitle": config.branding.login_subtitle,
        },
    }

    with config.config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False, default_flow_style=False)


def update_database_path_in_yaml(config: AppConfig, relative_db_path: str) -> None:
    """Persist an updated SQLite database path into config.yaml cleanly."""
    config.database.sqlite_path = relative_db_path
    save_config_to_yaml(config)


def get_redacted_yaml_preview(config: AppConfig) -> str:
    """Return a YAML preview with sensitive token values masked."""
    if config.config_path.exists():
        loaded = yaml.safe_load(config.config_path.read_text(encoding="utf-8"))
        data = loaded if isinstance(loaded, dict) else {}
    else:
        data = {}

    wh = data.get("webhook")
    if isinstance(wh, dict) and wh.get("secret_token"):
        wh["secret_token"] = "•••••••• (configured)"
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


def snapshot_execution_config(config: AppConfig, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Capture non-secret build configuration and safe webhook headers for exact re-runs."""
    safe_headers: dict[str, str] = {}
    if headers:
        for k, v in headers.items():
            lower_k = k.lower()
            if lower_k in {"x-gitlab-event", "x-gitlab-event-uuid", "content-type"}:
                safe_headers[k] = str(v)

    return {
        "server": {
            "app_title": config.server.app_title,
        },
        "webhook": {
            "allowed_events": list(config.webhook.allowed_events),
            "allowed_repo_hosts": list(config.webhook.allowed_repo_hosts),
            "enable_local_simulator": config.webhook.enable_local_simulator,
        },
        "ssh": {
            "private_key_path": config.ssh.private_key_path,
            "known_hosts_path": config.ssh.known_hosts_path,
            "strict_host_key_checking": config.ssh.strict_host_key_checking,
            "clone_timeout_seconds": config.ssh.clone_timeout_seconds,
            "clone_depth": config.ssh.clone_depth,
        },
        "pipeline": {
            "temp_base_dir": config.pipeline.temp_base_dir,
            "repo_config_filename": config.pipeline.repo_config_filename,
            "fallback_config_filenames": list(config.pipeline.fallback_config_filenames),
            "default_scripts": [
                {"name": s.name, "command": s.command} for s in config.pipeline.default_scripts
            ],
            "step_timeout_seconds": config.pipeline.step_timeout_seconds,
            "max_background_workers": config.pipeline.max_background_workers,
            "secure_cleanup": config.pipeline.secure_cleanup,
        },
        "headers": safe_headers,
    }


def restore_execution_config(base_config: AppConfig, snapshot: dict[str, Any] | None) -> AppConfig:
    """Reconstruct an AppConfig from an original build snapshot without mutating live config."""
    if not snapshot:
        return base_config

    srv_snap = _as_dict(snapshot.get("server"))
    wh_snap = _as_dict(snapshot.get("webhook"))
    ssh_snap = _as_dict(snapshot.get("ssh"))
    pipe_snap = _as_dict(snapshot.get("pipeline"))

    default_scripts = [
        DefaultScriptConfig(
            name=str(item.get("name", "Pipeline Step")),
            command=str(item.get("command", "")),
        )
        for item in pipe_snap.get("default_scripts", [])
        if isinstance(item, dict) and item.get("command")
    ]
    if not default_scripts:
        default_scripts = [
            DefaultScriptConfig(name=s.name, command=s.command)
            for s in base_config.pipeline.default_scripts
        ]

    return AppConfig(
        config_path=base_config.config_path,
        server=ServerConfig(
            host=base_config.server.host,
            port=base_config.server.port,
            app_title=str(srv_snap.get("app_title", base_config.server.app_title)),
            workers=base_config.server.workers,
        ),
        webhook=WebhookConfig(
            secret_token=base_config.webhook.secret_token,
            allowed_events=[
                str(e) for e in wh_snap.get("allowed_events", base_config.webhook.allowed_events)
            ],
            allowed_repo_hosts=[
                str(h) for h in wh_snap.get("allowed_repo_hosts", base_config.webhook.allowed_repo_hosts)
            ],
            enable_local_simulator=bool(
                wh_snap.get("enable_local_simulator", base_config.webhook.enable_local_simulator)
            ),
        ),
        ssh=SSHConfig(
            private_key_path=str(ssh_snap.get("private_key_path", base_config.ssh.private_key_path)),
            known_hosts_path=str(ssh_snap.get("known_hosts_path", base_config.ssh.known_hosts_path)),
            strict_host_key_checking=str(
                ssh_snap.get("strict_host_key_checking", base_config.ssh.strict_host_key_checking)
            ),
            clone_timeout_seconds=int(
                ssh_snap.get("clone_timeout_seconds", base_config.ssh.clone_timeout_seconds)
            ),
            clone_depth=int(ssh_snap.get("clone_depth", base_config.ssh.clone_depth)),
        ),
        pipeline=PipelineConfig(
            temp_base_dir=str(pipe_snap.get("temp_base_dir", base_config.pipeline.temp_base_dir)),
            repo_config_filename=str(
                pipe_snap.get("repo_config_filename", base_config.pipeline.repo_config_filename)
            ),
            fallback_config_filenames=[
                str(f)
                for f in pipe_snap.get("fallback_config_filenames", base_config.pipeline.fallback_config_filenames)
            ],
            default_scripts=default_scripts,
            step_timeout_seconds=int(
                pipe_snap.get("step_timeout_seconds", base_config.pipeline.step_timeout_seconds)
            ),
            max_background_workers=int(
                pipe_snap.get("max_background_workers", base_config.pipeline.max_background_workers)
            ),
            secure_cleanup=bool(pipe_snap.get("secure_cleanup", base_config.pipeline.secure_cleanup)),
        ),
        database=base_config.database,
        logging=base_config.logging,
        auth=base_config.auth,
        branding=base_config.branding,
    )

