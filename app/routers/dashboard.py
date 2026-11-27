"""Server-side rendered Jinja2 dashboard, login/LDAP auth, editable configuration, and logs."""

from __future__ import annotations

import uuid
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    AuthenticatedUser,
    authenticate_ldap,
    authenticate_local_admin,
    change_local_user_password,
    claim_local_admin,
    clear_session_cookie,
    create_csrf_token,
    create_local_user_account,
    get_session_user,
    is_local_admin_claimed,
    remove_local_user_account,
    set_session_cookie,
    test_ldap_connection,
    toggle_local_user_status,
    verify_csrf_token,
    verify_same_origin,
)
from app.config import (
    PROJECT_ROOT,
    AppConfig,
    DatabaseConfig,
    DefaultScriptConfig,
    get_redacted_yaml_preview,
    save_config_to_yaml,
    validate_database_vendor_config,
    validate_ldap_server_uri,
    validate_logo_url,
)
from app.database import (
    SQLiteAuditRepository,
    check_driver_available,
    create_repository,
    test_database_connection,
)
from app.git_service import generate_ssh_keypair, get_ssh_key_status
from app.logging_config import configure_logging, get_logger, read_recent_log_lines
from app.routers.webhook import rerun_execution_by_id

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
BRANDING_UPLOAD_DIR = Path(__file__).resolve().parent.parent / "static" / "branding"
MAX_LOGO_BYTES = 2 * 1024 * 1024
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["dashboard"])


def _detect_safe_raster_extension(payload: bytes, filename: str) -> str:
    """Validate uploaded logo bytes against safe raster image signatures only (no SVG/scripts)."""
    if not payload:
        raise ValueError("Uploaded logo file is empty.")
    if len(payload) > MAX_LOGO_BYTES:
        raise ValueError("Logo file must be 2 MB or smaller.")

    ext = Path(filename or "").suffix.lower()
    if ext == ".svg" or payload.lstrip()[:5].lower() in {b"<svg", b"<?xml"}:
        raise ValueError("SVG uploads are disabled for security. Please upload a PNG, JPG, WEBP, or ICO image.")

    if payload.startswith(b"\x89PNG\r\n\x1a\n") and ext in {".png", ""}:
        return ".png"
    if payload.startswith(b"\xff\xd8\xff") and ext in {".jpg", ".jpeg", ""}:
        return ".jpg"
    if len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WEBP" and ext in {".webp", ""}:
        return ".webp"
    if payload.startswith(b"\x00\x00\x01\x00") and ext in {".ico", ""}:
        return ".ico"

    raise ValueError("Unsupported or invalid image file. Only valid PNG, JPG, WEBP, or ICO files are allowed.")


def _cleanup_old_uploaded_logo(old_logo_path: str) -> None:
    """Remove a previously uploaded /static/branding/ asset when replaced or reset."""
    if not old_logo_path.startswith("/static/branding/"):
        return
    filename = old_logo_path.removeprefix("/static/branding/")
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        return
    base_dir = BRANDING_UPLOAD_DIR.resolve()
    candidate = (base_dir / filename).resolve()
    if candidate.is_relative_to(base_dir) and candidate.is_file():
        candidate.unlink(missing_ok=True)


def _format_duration(ms: int) -> str:
    if ms <= 0:
        return "0 ms"
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000.0
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes = int(seconds // 60)
    rem = seconds % 60
    return f"{minutes}m {rem:.1f}s"


def _format_timestamp(iso_value: str | None) -> str:
    if not iso_value:
        return "—"
    return iso_value.replace("T", " ").replace("Z", " UTC")


templates.env.filters["duration_fmt"] = _format_duration
templates.env.filters["ts_fmt"] = _format_timestamp


def _safe_next_url(raw_next: str) -> str:
    cleaned = (raw_next or "").strip()
    if not cleaned.startswith("/") or cleaned.startswith("//"):
        return "/"
    return cleaned


def _require_user(request: Request) -> AuthenticatedUser | RedirectResponse:
    config = request.app.state.config
    user = get_session_user(request, config)
    if user is not None:
        return user
    next_target = quote_plus(request.url.path + (f"?{request.url.query}" if request.url.query else ""))
    return RedirectResponse(url=f"/login?next={next_target}", status_code=status.HTTP_303_SEE_OTHER)


def _require_post_auth_and_csrf(request: Request, csrf_token: str) -> AuthenticatedUser:
    verify_same_origin(request)
    config = request.app.state.config
    user = get_session_user(request, config)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    if not verify_csrf_token(csrf_token, max_age=config.auth.session_max_age_seconds):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired form CSRF token.")
    return user


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    next: str = "/",
    error: str = "",
    notice: str = "",
) -> Response:
    """Render the LDAP / local admin login page (or first-run local admin setup)."""
    config = request.app.state.config
    repository = request.app.state.repository
    existing = get_session_user(request, config)
    if existing is not None and config.auth.enabled:
        return RedirectResponse(url=_safe_next_url(next), status_code=status.HTTP_303_SEE_OTHER)

    local_claimed = is_local_admin_claimed(repository)
    needs_first_run_setup = (
        config.auth.enabled
        and not config.auth.ldap.enabled
        and config.auth.allow_local_fallback
        and not local_claimed
    )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "app_title": config.server.app_title,
            "branding": config.branding,
            "ldap_enabled": config.auth.ldap.enabled,
            "ldap_server_uri": config.auth.ldap.server_uri,
            "ldap_auth_mode": config.auth.ldap.auth_mode,
            "allow_local_fallback": config.auth.allow_local_fallback,
            "needs_first_run_setup": needs_first_run_setup,
            "next_url": _safe_next_url(next),
            "csrf_token": create_csrf_token("login"),
            "error": error,
            "notice": notice,
        },
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form("/"),
    csrf_token: str = Form(...),
) -> Response:
    """Authenticate against configured LDAP directory (with optional local fallback)."""
    verify_same_origin(request)
    config = request.app.state.config
    repository = request.app.state.repository
    target_url = _safe_next_url(next_url)

    if not verify_csrf_token(csrf_token):
        return RedirectResponse(
            url=f"/login?next={quote_plus(target_url)}&error={quote_plus('Session expired. Please try again.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    result = None
    if config.auth.ldap.enabled:
        result = authenticate_ldap(username, password, config)
        if not result.success and config.auth.allow_local_fallback and is_local_admin_claimed(repository):
            fallback = authenticate_local_admin(username, password, repository)
            if fallback.success:
                result = fallback
    elif config.auth.allow_local_fallback:
        result = authenticate_local_admin(username, password, repository)

    if result and result.success and result.user:
        resp = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
        set_session_cookie(resp, request, result.user, config.auth.session_max_age_seconds)
        get_logger().info("User '%s' signed in (%s).", result.user.username, result.user.auth_source)
        return resp

    err_msg = result.error_message if result else "Authentication is not configured."
    return RedirectResponse(
        url=f"/login?next={quote_plus(target_url)}&error={quote_plus(err_msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/login/setup")
async def first_run_setup_submit(
    request: Request,
    username: str = Form("admin"),
    passcode: str = Form(...),
    confirm_passcode: str = Form(...),
    next_url: str = Form("/"),
    csrf_token: str = Form(...),
) -> Response:
    """One-time first-run local admin setup when LDAP is not enabled yet."""
    verify_same_origin(request)
    config = request.app.state.config
    repository = request.app.state.repository
    target_url = _safe_next_url(next_url)

    if not verify_csrf_token(csrf_token):
        return RedirectResponse(
            url=f"/login?error={quote_plus('Form token expired. Please submit again.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if passcode != confirm_passcode:
        return RedirectResponse(
            url=f"/login?error={quote_plus('Passcodes do not match.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        user = claim_local_admin(username, passcode, repository)
        resp = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
        set_session_cookie(resp, request, user, config.auth.session_max_age_seconds)
        return resp
    except ValueError as exc:
        return RedirectResponse(
            url=f"/login?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/logout")
async def logout_submit(request: Request, csrf_token: str = Form(...)) -> RedirectResponse:
    """Clear active dashboard session cookie."""
    verify_same_origin(request)
    if verify_csrf_token(csrf_token):
        user = get_session_user(request, request.app.state.config)
        if user:
            get_logger().info("User '%s' signed out.", user.username)
    resp = RedirectResponse(url="/login?notice=" + quote_plus("Signed out cleanly."), status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(resp, request)
    return resp


@router.get("/", response_class=HTMLResponse)
async def dashboard_home(
    request: Request,
    status_filter: str = "all",
    event: str = "all",
    q: str = "",
    page: int = 1,
    notice: str = "",
    error: str = "",
    rerun_id: str = "",
) -> Response:
    """Render the main pipeline audit dashboard reading directly from SQLite."""
    auth_check = _require_user(request)
    if isinstance(auth_check, RedirectResponse):
        return auth_check

    config = request.app.state.config
    repository = request.app.state.repository

    per_page = 25
    safe_page = max(1, page)
    offset = (safe_page - 1) * per_page

    executions = repository.list_executions(
        status=status_filter,
        event_kind=event,
        search=q,
        limit=per_page + 1,
        offset=offset,
    )
    has_next = len(executions) > per_page
    executions = executions[:per_page]
    stats = repository.get_summary_stats()
    db_info = repository.get_database_info()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": auth_check,
            "csrf_token": create_csrf_token(auth_check.username),
            "active_nav": "executions",
            "page_title": "Executions",
            "breadcrumbs": [config.branding.brand_name, "Executions"],
            "app_title": config.server.app_title,
            "branding": config.branding,
            "auth_enabled": config.auth.enabled,
            "executions": executions,
            "stats": stats,
            "db_info": db_info,
            "status_filter": status_filter.lower(),
            "event_filter": event.lower(),
            "search_query": q,
            "page": safe_page,
            "has_next": has_next,
            "local_simulator_enabled": config.webhook.enable_local_simulator,
            "notice": notice,
            "error": error,
            "rerun_id": rerun_id,
        },
    )


@router.get("/executions/{execution_id}", response_class=HTMLResponse)
async def execution_detail(request: Request, execution_id: str) -> Response:
    """Render full audit details, extracted GitLab variables, changed files, and step logs."""
    auth_check = _require_user(request)
    if isinstance(auth_check, RedirectResponse):
        return auth_check

    config = request.app.state.config
    repository = request.app.state.repository

    record = repository.get_execution(execution_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution record not found.")

    sorted_variables = sorted(record.variables.items(), key=lambda item: item[0])
    db_info = repository.get_database_info()

    return templates.TemplateResponse(
        "execution_detail.html",
        {
            "request": request,
            "current_user": auth_check,
            "csrf_token": create_csrf_token(auth_check.username),
            "active_nav": "executions",
            "page_title": f"Run {record.id}",
            "breadcrumbs": [config.branding.brand_name, "Executions", record.id],
            "app_title": config.server.app_title,
            "branding": config.branding,
            "auth_enabled": config.auth.enabled,
            "record": record,
            "sorted_variables": sorted_variables,
            "db_info": db_info,
        },
    )


@router.post("/executions/{execution_id}/rerun")
async def rerun_execution_form(
    request: Request,
    execution_id: str,
    csrf_token: str = Form(...),
    target: str = Form("dashboard"),
) -> RedirectResponse:
    """Trigger an exact-config re-run from the dashboard history table or detail page."""
    user = _require_post_auth_and_csrf(request, csrf_token)
    try:
        new_record = rerun_execution_by_id(request, execution_id, requested_by=user.username)
        if target == "detail":
            return RedirectResponse(
                url=f"/executions/{new_record.id}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        msg = f"Re-run {new_record.id} queued from {execution_id} with original build configuration."
        return RedirectResponse(
            url=f"/?notice={quote_plus(msg)}&rerun_id={quote_plus(new_record.id)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except HTTPException as exc:
        return RedirectResponse(
            url=f"/?error={quote_plus(str(exc.detail))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


VALID_CONFIG_SECTIONS = {
    "branding",
    "security",
    "webhook",
    "ssh",
    "pipeline",
    "storage",
    "yaml",
    "all",
}


def _safe_section(raw: str) -> str:
    cleaned = (raw or "").strip().lower()
    return cleaned if cleaned in VALID_CONFIG_SECTIONS else "branding"


@router.get("/config", response_class=HTMLResponse)
async def configuration_view(
    request: Request,
    section: str = "branding",
    notice: str = "",
    error: str = "",
) -> Response:
    """Render tree-view editable config.yaml GUI, security/users/LDAP settings, SQLite switcher, and SSH status."""
    auth_check = _require_user(request)
    if isinstance(auth_check, RedirectResponse):
        return auth_check

    config = request.app.state.config
    repository = request.app.state.repository
    db_info = repository.get_database_info()
    ssh_status = get_ssh_key_status(config)
    local_users = repository.list_local_users()

    data_dir = config.resolve_path(config.database.allowed_dir)
    available_dbs: list[str] = []
    if data_dir.exists():
        available_dbs = sorted(
            str(p.relative_to(PROJECT_ROOT)) if p.is_relative_to(PROJECT_ROOT) else str(p)
            for p in data_dir.iterdir()
            if p.is_file() and p.suffix in {".db", ".sqlite", ".sqlite3"}
        )

    default_scripts_text = "\n".join(
        f"{item.name} :: {item.command}" for item in config.pipeline.default_scripts
    )

    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "current_user": auth_check,
            "csrf_token": create_csrf_token(auth_check.username),
            "active_nav": "config",
            "page_title": "Configuration & Security",
            "breadcrumbs": [config.branding.brand_name, "Configuration"],
            "app_title": config.server.app_title,
            "branding": config.branding,
            "auth_enabled": config.auth.enabled,
            "config": config,
            "db_info": db_info,
            "db_driver_status": {
                "sqlite": check_driver_available("sqlite"),
                "postgresql": check_driver_available("postgresql"),
                "mariadb": check_driver_available("mariadb"),
            },
            "available_dbs": available_dbs,
            "ssh_status": ssh_status,
            "local_users": local_users,
            "active_section": _safe_section(section),
            "default_scripts_text": default_scripts_text,
            "config_yaml_text": get_redacted_yaml_preview(config),
            "notice": notice,
            "error": error,
        },
    )


@router.post("/config/branding")
async def save_branding_configuration(
    request: Request,
    csrf_token: str = Form(...),
    brand_name: str = Form(...),
    login_subtitle: str = Form(""),
    logo_url: str = Form(""),
    reset_logo: str = Form(""),
    logo_file: UploadFile | None = File(None),
) -> RedirectResponse:
    """Update customizable brand name, login subtitle, and custom logo (upload or URL)."""
    user = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config

    try:
        clean_brand = brand_name.strip()
        if not clean_brand:
            raise ValueError("Brand name cannot be empty.")
        if len(clean_brand) > 80:
            raise ValueError("Brand name must be 80 characters or fewer.")

        clean_subtitle = login_subtitle.strip()
        if len(clean_subtitle) > 120:
            raise ValueError("Login subtitle must be 120 characters or fewer.")

        old_logo_path = config.branding.logo_path
        new_logo_path = old_logo_path

        if reset_logo == "on":
            new_logo_path = ""
            _cleanup_old_uploaded_logo(old_logo_path)
        elif logo_file is not None and logo_file.filename:
            raw_bytes = await logo_file.read(MAX_LOGO_BYTES + 1)
            safe_ext = _detect_safe_raster_extension(raw_bytes, logo_file.filename)
            BRANDING_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            filename = f"brand_{uuid.uuid4().hex[:12]}{safe_ext}"
            target_file = (BRANDING_UPLOAD_DIR / filename).resolve()
            if not target_file.is_relative_to(BRANDING_UPLOAD_DIR.resolve()):
                raise ValueError("Invalid branding storage path.")
            target_file.write_bytes(raw_bytes)
            new_logo_path = f"/static/branding/{filename}"
            _cleanup_old_uploaded_logo(old_logo_path)
        else:
            validated_url = validate_logo_url(logo_url)
            if validated_url != old_logo_path:
                _cleanup_old_uploaded_logo(old_logo_path)
            new_logo_path = validated_url

        config.branding.brand_name = clean_brand
        config.branding.login_subtitle = clean_subtitle
        config.branding.logo_path = new_logo_path

        save_config_to_yaml(config)
        get_logger().info("Branding settings updated via GUI by '%s'.", user.username)
        return RedirectResponse(
            url="/config?section=branding&notice=" + quote_plus("Branding & logo settings saved."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=branding&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/security/users/add")
async def add_local_user_endpoint(
    request: Request,
    csrf_token: str = Form(...),
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    role: str = Form("operator"),
    password: str = Form(...),
    confirm_password: str = Form(...),
) -> RedirectResponse:
    """Create a new local user with salted scrypt password hash."""
    actor = _require_post_auth_and_csrf(request, csrf_token)
    repository = request.app.state.repository
    try:
        if password != confirm_password:
            raise ValueError("Passwords do not match.")
        create_local_user_account(
            username=username,
            password=password,
            repository=repository,
            display_name=display_name,
            email=email,
            role=role,
        )
        get_logger().info("Local user '%s' (role=%s) added by '%s'.", username.strip(), role.strip(), actor.username)
        return RedirectResponse(
            url="/config?section=security&notice=" + quote_plus(f"Local user '{username.strip()}' added."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=security&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/security/users/{target_username}/password")
async def reset_local_user_password_endpoint(
    request: Request,
    target_username: str,
    csrf_token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> RedirectResponse:
    """Update password for an existing local user."""
    actor = _require_post_auth_and_csrf(request, csrf_token)
    repository = request.app.state.repository
    try:
        if new_password != confirm_password:
            raise ValueError("Passwords do not match.")
        change_local_user_password(target_username, new_password, repository)
        get_logger().info("Password updated for local user '%s' by '%s'.", target_username, actor.username)
        return RedirectResponse(
            url="/config?section=security&notice=" + quote_plus(f"Password updated for '{target_username}'."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=security&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/security/users/{target_username}/toggle")
async def toggle_local_user_endpoint(
    request: Request,
    target_username: str,
    csrf_token: str = Form(...),
) -> RedirectResponse:
    """Enable or disable a local user account."""
    actor = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    repository = request.app.state.repository
    try:
        now_active = toggle_local_user_status(target_username, actor.username, config, repository)
        state_label = "enabled" if now_active else "disabled"
        get_logger().info("Local user '%s' %s by '%s'.", target_username, state_label, actor.username)
        return RedirectResponse(
            url="/config?section=security&notice=" + quote_plus(f"Local user '{target_username}' {state_label}."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=security&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/security/users/{target_username}/delete")
async def delete_local_user_endpoint(
    request: Request,
    target_username: str,
    csrf_token: str = Form(...),
) -> RedirectResponse:
    """Delete a local user account."""
    actor = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    repository = request.app.state.repository
    try:
        remove_local_user_account(target_username, actor.username, config, repository)
        get_logger().info("Local user '%s' removed by '%s'.", target_username, actor.username)
        return RedirectResponse(
            url="/config?section=security&notice=" + quote_plus(f"Local user '{target_username}' removed."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=security&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/save")
async def save_general_configuration(
    request: Request,
    csrf_token: str = Form(...),
    active_section: str = Form("webhook"),
    app_title: str = Form(...),
    webhook_secret_token: str = Form(""),
    clear_webhook_secret: str = Form(""),
    allowed_events: str = Form(""),
    allowed_repo_hosts: str = Form(""),
    enable_local_simulator: str = Form(""),
    ssh_private_key_path: str = Form(...),
    ssh_known_hosts_path: str = Form("keys/known_hosts"),
    strict_host_key_checking: str = Form("accept-new"),
    clone_timeout_seconds: int = Form(120),
    clone_depth: int = Form(50),
    temp_base_dir: str = Form(...),
    repo_config_filename: str = Form(".pipeline.yml"),
    fallback_config_filenames: str = Form(""),
    step_timeout_seconds: int = Form(300),
    max_background_workers: int = Form(4),
    secure_cleanup: str = Form(""),
    default_scripts_lines: str = Form(""),
    log_file: str = Form("logs/pipeline_runner.log"),
    log_level: str = Form("INFO"),
    wal_mode: str = Form(""),
) -> RedirectResponse:
    """Validate and persist editable server, webhook, SSH, pipeline, and logging settings."""
    user = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    safe_sec = _safe_section(active_section)

    try:
        clean_title = app_title.strip()
        if not clean_title:
            raise ValueError("Application title cannot be empty.")

        safe_key_path = config.validate_project_subpath(ssh_private_key_path, "SSH private key path")
        safe_hosts_path = config.validate_project_subpath(ssh_known_hosts_path, "SSH known_hosts path")
        safe_log_file = config.validate_project_subpath(log_file, "Logfile path")

        strict = strict_host_key_checking.strip().lower()
        if strict not in {"accept-new", "yes", "no"}:
            raise ValueError("StrictHostKeyChecking must be accept-new, yes, or no.")

        level = log_level.strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("Log level must be DEBUG, INFO, WARNING, or ERROR.")

        clean_temp = temp_base_dir.strip()
        if not clean_temp.startswith("/"):
            raise ValueError("Temporary workspace base directory must be an absolute path (e.g. /tmp/...).")

        parsed_scripts: list[DefaultScriptConfig] = []
        for raw_line in default_scripts_lines.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "::" in line:
                name_part, cmd_part = line.split("::", 1)
                if cmd_part.strip():
                    parsed_scripts.append(DefaultScriptConfig(name=name_part.strip() or "Step", command=cmd_part.strip()))
            else:
                parsed_scripts.append(DefaultScriptConfig(name="Step", command=line))

        config.server.app_title = clean_title
        if clear_webhook_secret == "on":
            config.webhook.secret_token = ""
        elif webhook_secret_token.strip():
            config.webhook.secret_token = webhook_secret_token.strip()

        config.webhook.allowed_events = [e.strip() for e in allowed_events.split(",") if e.strip()]
        config.webhook.allowed_repo_hosts = [h.strip() for h in allowed_repo_hosts.split(",") if h.strip()]
        config.webhook.enable_local_simulator = enable_local_simulator == "on"

        config.ssh.private_key_path = safe_key_path
        config.ssh.known_hosts_path = safe_hosts_path
        config.ssh.strict_host_key_checking = strict
        config.ssh.clone_timeout_seconds = max(10, min(3600, int(clone_timeout_seconds)))
        config.ssh.clone_depth = max(0, min(1000, int(clone_depth)))

        config.pipeline.temp_base_dir = clean_temp
        config.pipeline.repo_config_filename = repo_config_filename.strip() or ".pipeline.yml"
        config.pipeline.fallback_config_filenames = [
            f.strip() for f in fallback_config_filenames.split(",") if f.strip()
        ]
        config.pipeline.step_timeout_seconds = max(10, min(7200, int(step_timeout_seconds)))
        config.pipeline.max_background_workers = max(1, min(32, int(max_background_workers)))
        config.pipeline.secure_cleanup = secure_cleanup == "on"
        if parsed_scripts:
            config.pipeline.default_scripts = parsed_scripts

        config.logging.log_file = safe_log_file
        config.logging.level = level
        config.database.wal_mode = wal_mode == "on"

        save_config_to_yaml(config)
        configure_logging(config)
        get_logger().info("Configuration updated via GUI by '%s'.", user.username)

        return RedirectResponse(
            url=f"/config?section={safe_sec}&notice=" + quote_plus("Configuration saved to config.yaml."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/config?section={safe_sec}&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/ldap")
async def save_ldap_configuration(
    request: Request,
    csrf_token: str = Form(...),
    auth_enabled: str = Form(""),
    allow_local_fallback: str = Form(""),
    session_max_age_seconds: int = Form(28_800),
    ldap_enabled: str = Form(""),
    server_uri: str = Form(...),
    use_ssl: str = Form(""),
    start_tls: str = Form(""),
    auth_mode: str = Form("direct_bind"),
    base_dn: str = Form(...),
    user_dn_template: str = Form("uid={username},ou=people,dc=example,dc=com"),
    bind_dn: str = Form(""),
    bind_password_env: str = Form("LDAP_BIND_PASSWORD"),
    user_search_filter: str = Form("(|(uid={username})(sAMAccountName={username})(mail={username}))"),
    allowed_group_dn: str = Form(""),
    timeout_seconds: int = Form(10),
) -> RedirectResponse:
    """Update modifiable authentication and LDAP configuration from the GUI."""
    user = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config

    try:
        validated_uri = validate_ldap_server_uri(server_uri)
        clean_mode = auth_mode.strip().lower()
        if clean_mode not in {"direct_bind", "search_bind"}:
            raise ValueError("LDAP auth mode must be direct_bind or search_bind.")

        config.auth.enabled = auth_enabled == "on"
        config.auth.allow_local_fallback = allow_local_fallback == "on"
        config.auth.session_max_age_seconds = max(300, min(604_800, int(session_max_age_seconds)))

        config.auth.ldap.enabled = ldap_enabled == "on"
        config.auth.ldap.server_uri = validated_uri
        config.auth.ldap.use_ssl = use_ssl == "on"
        config.auth.ldap.start_tls = start_tls == "on"
        config.auth.ldap.auth_mode = clean_mode
        config.auth.ldap.base_dn = base_dn.strip()
        config.auth.ldap.user_dn_template = user_dn_template.strip()
        config.auth.ldap.bind_dn = bind_dn.strip()
        config.auth.ldap.bind_password_env = bind_password_env.strip() or "LDAP_BIND_PASSWORD"
        config.auth.ldap.user_search_filter = user_search_filter.strip()
        config.auth.ldap.allowed_group_dn = allowed_group_dn.strip()
        config.auth.ldap.timeout_seconds = max(2, min(60, int(timeout_seconds)))

        save_config_to_yaml(config)
        get_logger().info(
            "LDAP/Auth settings updated by '%s' (ldap_enabled=%s, server=%s).",
            user.username,
            config.auth.ldap.enabled,
            config.auth.ldap.server_uri,
        )
        return RedirectResponse(
            url="/config?section=security&notice=" + quote_plus("Security, Authentication & LDAP settings updated."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=security&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/ldap/test")
async def test_ldap_endpoint(request: Request, csrf_token: str = Form(...)) -> RedirectResponse:
    """Test reachability of the configured LDAP directory server."""
    _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    ok, message = test_ldap_connection(config)
    param = "notice" if ok else "error"
    return RedirectResponse(
        url=f"/config?section=security&{param}={quote_plus(message)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/config/database")
async def switch_database_endpoint(
    request: Request,
    csrf_token: str = Form(...),
    engine: str = Form("sqlite"),
    sqlite_path: str = Form("data/pipeline_audit.db"),
    host: str = Form("127.0.0.1"),
    port: int = Form(5432),
    name: str = Form("pipeline_audit"),
    user_name: str = Form("pipeline_runner"),
    password_env: str = Form("RUNNER_DB_PASSWORD"),
    ssl_mode: str = Form("prefer"),
    connect_timeout_seconds: int = Form(10),
    action: str = Form("switch"),
) -> RedirectResponse:
    """Test connection or switch the active audit database vendor (SQLite default, PostgreSQL, or MariaDB)."""
    user = _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    repository = request.app.state.repository

    try:
        validated = validate_database_vendor_config(
            engine=engine,
            host=host,
            port=port,
            name=name,
            user=user_name,
            password_env=password_env,
            ssl_mode=ssl_mode,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        chosen_engine = validated["engine"]
        clean_sqlite_rel = config.database.sqlite_path
        if chosen_engine == "sqlite":
            resolved_path = config.validate_database_path(sqlite_path)
            clean_sqlite_rel = (
                str(resolved_path.relative_to(PROJECT_ROOT))
                if resolved_path.is_relative_to(PROJECT_ROOT)
                else str(resolved_path)
            )

        candidate_db = DatabaseConfig(
            engine=chosen_engine,
            sqlite_path=clean_sqlite_rel,
            allowed_dir=config.database.allowed_dir,
            wal_mode=config.database.wal_mode,
            host=validated["host"],
            port=validated["port"],
            name=validated["name"],
            user=validated["user"],
            password_env=validated["password_env"],
            ssl_mode=validated["ssl_mode"],
            connect_timeout_seconds=validated["connect_timeout_seconds"],
        )
        candidate_cfg = AppConfig(
            config_path=config.config_path,
            server=config.server,
            webhook=config.webhook,
            ssh=config.ssh,
            pipeline=config.pipeline,
            database=candidate_db,
            logging=config.logging,
            auth=config.auth,
            branding=config.branding,
        )

        if action.strip().lower() == "test":
            ok, msg = test_database_connection(candidate_cfg)
            param = "notice" if ok else "error"
            return RedirectResponse(
                url=f"/config?section=storage&{param}={quote_plus(msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if chosen_engine == "sqlite" and isinstance(repository, SQLiteAuditRepository):
            resolved_path = config.validate_database_path(sqlite_path)
            repository.switch_database(resolved_path)
            new_repo = repository
        else:
            new_repo = create_repository(candidate_cfg)

        config.database = candidate_db
        request.app.state.repository = new_repo
        worker = getattr(request.app.state, "worker", None)
        if worker is not None:
            worker.set_repository(new_repo)

        save_config_to_yaml(config)
        target_desc = (
            clean_sqlite_rel
            if chosen_engine == "sqlite"
            else f"{chosen_engine}://{candidate_db.user}@{candidate_db.host}:{candidate_db.port}/{candidate_db.name}"
        )
        get_logger().info(
            "Active audit database switched to engine='%s' (%s) by '%s'.",
            chosen_engine,
            target_desc,
            user.username,
        )
        return RedirectResponse(
            url=f"/config?section=storage&notice={quote_plus(f'Active audit database switched to {chosen_engine} ({target_desc}).')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/config?section=storage&error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.post("/config/ssh-key")
async def generate_ssh_key_endpoint(request: Request, csrf_token: str = Form(...)) -> RedirectResponse:
    """Generate an Ed25519 SSH deploy key at the configured ssh.private_key_path."""
    _require_post_auth_and_csrf(request, csrf_token)
    config = request.app.state.config
    try:
        generate_ssh_keypair(config)
        return RedirectResponse(
            url="/config?section=ssh&notice=" + quote_plus("Ed25519 SSH deploy key generated successfully."),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url="/config?section=ssh&error=" + quote_plus(str(exc)),
            status_code=status.HTTP_303_SEE_OTHER,
        )


@router.get("/logs", response_class=HTMLResponse)
async def logs_view(
    request: Request,
    level: str = "ALL",
    limit: int = 200,
) -> Response:
    """Render friendly pipeline runner logfile entries."""
    auth_check = _require_user(request)
    if isinstance(auth_check, RedirectResponse):
        return auth_check

    config = request.app.state.config
    repository = request.app.state.repository
    log_path = config.resolve_path(config.logging.log_file)
    safe_limit = max(25, min(limit, 500))
    entries = read_recent_log_lines(log_path, limit=safe_limit, level_filter=level)
    db_info = repository.get_database_info()

    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "current_user": auth_check,
            "csrf_token": create_csrf_token(auth_check.username),
            "active_nav": "logs",
            "page_title": "Audit Logs",
            "breadcrumbs": [config.branding.brand_name, "Audit Logs"],
            "app_title": config.server.app_title,
            "branding": config.branding,
            "auth_enabled": config.auth.enabled,
            "log_entries": entries,
            "log_file_path": str(log_path),
            "level_filter": level.upper(),
            "limit": safe_limit,
            "db_info": db_info,
        },
    )
