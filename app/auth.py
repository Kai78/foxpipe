"""LDAP authentication, local admin fallback, and signed session/CSRF management."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from app.config import AppConfig
from app.database import AbstractAuditRepository
from app.logging_config import get_logger

SESSION_COOKIE_NAME = "pipeline_runner_session"
CSRF_SALT = "pipeline-runner-csrf-v1"
SESSION_SALT = "pipeline-runner-session-v1"

# Ephemeral in-memory fallback key generated once per process if SESSION_SECRET_KEY is unset.
_IN_MEMORY_SIGNING_KEY = secrets.token_hex(32)


@dataclass(slots=True)
class AuthenticatedUser:
    """Authenticated principal stored in signed session cookie."""

    username: str
    display_name: str
    email: str
    auth_source: str  # "ldap" | "local" | "anonymous"


@dataclass(slots=True)
class AuthResult:
    """Outcome of an authentication attempt."""

    success: bool
    user: AuthenticatedUser | None = None
    error_message: str = ""


def _get_signing_secret() -> str:
    env_key = os.environ.get("SESSION_SECRET_KEY", "").strip()
    return env_key or _IN_MEMORY_SIGNING_KEY


def _get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_get_signing_secret(), salt=SESSION_SALT)


def _get_csrf_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_get_signing_secret(), salt=CSRF_SALT)


def create_csrf_token(session_id_hint: str = "anon") -> str:
    """Generate a timed signed CSRF token for HTML forms."""
    return _get_csrf_serializer().dumps({"ctx": session_id_hint})


def verify_csrf_token(token: str, max_age: int = 28_800) -> bool:
    """Verify a submitted CSRF form token."""
    if not token:
        return False
    try:
        _get_csrf_serializer().loads(token, max_age=max_age)
        return True
    except (BadSignature, SignatureExpired):
        return False


def verify_same_origin(request: Request) -> None:
    """Enforce Origin/Referer match on state-changing requests."""
    expected_host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    origin = request.headers.get("origin", "").strip()
    if origin and expected_host:
        origin_host = urlparse(origin).netloc
        if origin_host and origin_host != expected_host:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-origin request rejected.")


def is_https_request(request: Request) -> bool:
    """Detect HTTPS either directly, via X-Forwarded-Proto, or via Origin/Referer behind TLS-terminating LB."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    if forwarded_proto == "https":
        return True
    if request.url.scheme == "https":
        return True
    origin = request.headers.get("origin", "").strip().lower()
    referer = request.headers.get("referer", "").strip().lower()
    if origin.startswith("https://") or referer.startswith("https://"):
        return True
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip().lower()
    return forwarded_host.endswith(".run.app")


def set_session_cookie(response: Response, request: Request, user: AuthenticatedUser, max_age: int) -> None:
    """Write an HttpOnly signed session cookie compatible with HTTPS iframes and local HTTP."""
    token = _get_serializer().dumps(
        {
            "u": user.username,
            "d": user.display_name,
            "e": user.email,
            "s": user.auth_source,
        }
    )
    https = is_https_request(request)
    if https:
        # Include Partitioned for cross-site iframe preview contexts
        cookie_val = (
            f"{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; "
            "HttpOnly; Secure; SameSite=None; Partitioned"
        )
        response.headers.append("Set-Cookie", cookie_val)
    else:
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=max_age,
            path="/",
            httponly=True,
            secure=False,
            samesite="lax",
        )


def clear_session_cookie(response: Response, request: Request) -> None:
    """Expire the session cookie cleanly."""
    https = is_https_request(request)
    if https:
        cookie_val = (
            f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; "
            "HttpOnly; Secure; SameSite=None; Partitioned"
        )
        response.headers.append("Set-Cookie", cookie_val)
    else:
        response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def get_session_user(request: Request, config: AppConfig) -> AuthenticatedUser | None:
    """Extract and validate the signed session user from request cookies."""
    if not config.auth.enabled:
        return AuthenticatedUser(
            username="operator",
            display_name="Local Operator",
            email="",
            auth_source="disabled",
        )

    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
    if not raw_cookie:
        return None
    try:
        data = _get_serializer().loads(raw_cookie, max_age=config.auth.session_max_age_seconds)
        if not isinstance(data, dict) or not data.get("u"):
            return None
        return AuthenticatedUser(
            username=str(data["u"]),
            display_name=str(data.get("d") or data["u"]),
            email=str(data.get("e") or ""),
            auth_source=str(data.get("s") or "local"),
        )
    except (BadSignature, SignatureExpired):
        return None


def _hash_passcode(passcode: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    derived = hashlib.scrypt(passcode.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${derived.hex()}"


def _verify_scrypt_hash(passcode: str, stored_hash: str) -> bool:
    parts = stored_hash.split("$")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    _, salt_hex, expected_hex = parts
    candidate = _hash_passcode(passcode, salt_hex=salt_hex)
    return hmac.compare_digest(candidate, stored_hash)


def _get_env_admin_passcode() -> str:
    val = os.environ.get("ADMIN_PASSCODE", "").strip()
    return val if len(val) >= 8 else ""


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


def is_local_admin_claimed(repository: AbstractAuditRepository) -> bool:
    """Return True if a valid ADMIN_PASSCODE env var is configured or a local user exists in SQLite."""
    if _get_env_admin_passcode():
        return True
    if repository.has_any_local_user():
        return True
    return bool(repository.get_auth_setting("local_admin_hash"))


def claim_local_admin(username: str, passcode: str, repository: AbstractAuditRepository) -> AuthenticatedUser:
    """One-time bootstrap for local dashboard admin passcode stored salted+hashed in SQLite."""
    if is_local_admin_claimed(repository):
        raise ValueError("Admin account has already been configured.")

    cleaned_user = username.strip() or "admin"
    if not USERNAME_PATTERN.match(cleaned_user):
        raise ValueError("Username must be 2-64 characters using letters, numbers, '.', '_', or '-'.")
    if len(passcode) < 8:
        raise ValueError("Admin passcode must be at least 8 characters long.")

    hashed = _hash_passcode(passcode)
    repository.create_local_user(
        username=cleaned_user,
        display_name=cleaned_user,
        email="",
        role="admin",
        password_hash=hashed,
    )
    repository.set_auth_setting("local_admin_username", cleaned_user)
    repository.set_auth_setting("local_admin_hash", hashed)
    get_logger().info("Local dashboard administrator '%s' claimed on first-run setup.", cleaned_user)
    return AuthenticatedUser(
        username=cleaned_user,
        display_name=cleaned_user,
        email="",
        auth_source="local",
    )


def create_local_user_account(
    username: str,
    password: str,
    repository: AbstractAuditRepository,
    display_name: str = "",
    email: str = "",
    role: str = "operator",
) -> None:
    """Validate and persist a new local user with salted scrypt password hash."""
    cleaned_user = username.strip()
    if not USERNAME_PATTERN.match(cleaned_user):
        raise ValueError("Username must be 2-64 characters using letters, numbers, '.', '_', or '-'.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 256:
        raise ValueError("Password must be 256 characters or fewer.")

    clean_role = role.strip().lower()
    if clean_role not in {"admin", "operator"}:
        raise ValueError("Role must be admin or operator.")

    clean_display = display_name.strip()[:80] or cleaned_user
    clean_email = email.strip()[:120]

    if repository.get_local_user(cleaned_user) is not None:
        raise ValueError(f"Local user '{cleaned_user}' already exists.")

    hashed = _hash_passcode(password)
    repository.create_local_user(
        username=cleaned_user,
        display_name=clean_display,
        email=clean_email,
        role=clean_role,
        password_hash=hashed,
    )


def change_local_user_password(
    username: str,
    new_password: str,
    repository: AbstractAuditRepository,
) -> None:
    """Reset a local user's password with salted scrypt hashing."""
    if len(new_password) < 8:
        raise ValueError("New password must be at least 8 characters long.")
    if len(new_password) > 256:
        raise ValueError("New password must be 256 characters or fewer.")
    user = repository.get_local_user(username)
    if user is None:
        raise ValueError(f"Local user '{username}' was not found.")
    hashed = _hash_passcode(new_password)
    repository.update_local_user_password(user.username, hashed)


def toggle_local_user_status(
    username: str,
    actor_username: str,
    config: AppConfig,
    repository: AbstractAuditRepository,
) -> bool:
    """Toggle active status for a local user while preventing self/last-admin lockout."""
    user = repository.get_local_user(username)
    if user is None:
        raise ValueError(f"Local user '{username}' was not found.")
    new_active = not user.is_active
    if not new_active:
        if user.username.lower() == actor_username.strip().lower():
            raise ValueError("You cannot disable your own active account.")
        active_users = [u for u in repository.list_local_users() if u.is_active]
        if len(active_users) <= 1 and not config.auth.ldap.enabled:
            raise ValueError("Cannot disable the last active local user while LDAP is disabled.")
    repository.set_local_user_active(user.username, new_active)
    return new_active


def remove_local_user_account(
    username: str,
    actor_username: str,
    config: AppConfig,
    repository: AbstractAuditRepository,
) -> None:
    """Delete a local user while preventing accidental lockout."""
    user = repository.get_local_user(username)
    if user is None:
        raise ValueError(f"Local user '{username}' was not found.")
    if user.username.lower() == actor_username.strip().lower():
        raise ValueError("You cannot delete your own active account.")
    active_users = [u for u in repository.list_local_users() if u.is_active]
    if user.is_active and len(active_users) <= 1 and not config.auth.ldap.enabled:
        raise ValueError("Cannot delete the last active local user while LDAP is disabled.")
    repository.delete_local_user(user.username)


def authenticate_local_admin(
    username: str,
    password: str,
    repository: AbstractAuditRepository,
) -> AuthResult:
    """Authenticate against local_users table, ADMIN_PASSCODE env var, or legacy local_admin_hash."""
    if not password:
        return AuthResult(success=False, error_message="Password is required.")

    cleaned_user = username.strip()
    env_passcode = _get_env_admin_passcode()
    if env_passcode and hmac.compare_digest(password, env_passcode):
        if cleaned_user.lower() in {"", "admin"} or (
            repository.get_auth_setting("local_admin_username") or ""
        ).lower() == cleaned_user.lower():
            resolved_name = cleaned_user or "admin"
            return AuthResult(
                success=True,
                user=AuthenticatedUser(
                    username=resolved_name,
                    display_name=resolved_name,
                    email="",
                    auth_source="local",
                ),
            )

    if cleaned_user:
        user_record = repository.get_local_user(cleaned_user)
        if user_record is not None:
            if not user_record.is_active:
                return AuthResult(success=False, error_message="This local account is disabled.")
            if _verify_scrypt_hash(password, user_record.password_hash):
                return AuthResult(
                    success=True,
                    user=AuthenticatedUser(
                        username=user_record.username,
                        display_name=user_record.display_name or user_record.username,
                        email=user_record.email,
                        auth_source="local",
                    ),
                )
            return AuthResult(success=False, error_message="Invalid username or password.")

    stored_hash = repository.get_auth_setting("local_admin_hash")
    stored_user = repository.get_auth_setting("local_admin_username") or "admin"
    if not stored_hash and not repository.has_any_local_user():
        if env_passcode:
            return AuthResult(success=False, error_message="Invalid credentials.")
        return AuthResult(success=False, error_message="No local user account configured yet.")

    if stored_hash and (not cleaned_user or cleaned_user.lower() == stored_user.lower()):
        if _verify_scrypt_hash(password, stored_hash):
            return AuthResult(
                success=True,
                user=AuthenticatedUser(
                    username=stored_user,
                    display_name=stored_user,
                    email="",
                    auth_source="local",
                ),
            )
    return AuthResult(success=False, error_message="Invalid username or password.")


def authenticate_ldap(username: str, password: str, config: AppConfig) -> AuthResult:
    """Authenticate a user against the configured LDAP / Active Directory server safely."""
    ldap_cfg = config.auth.ldap
    cleaned_user = username.strip()
    if not cleaned_user or not password:
        return AuthResult(success=False, error_message="Username and password are required.")

    logger = get_logger()
    try:
        server = Server(
            ldap_cfg.server_uri,
            use_ssl=ldap_cfg.use_ssl,
            connect_timeout=ldap_cfg.timeout_seconds,
            get_info=ALL,
        )

        if ldap_cfg.auth_mode == "search_bind":
            bind_password = os.environ.get(ldap_cfg.bind_password_env, "")
            if not ldap_cfg.bind_dn or not bind_password:
                return AuthResult(
                    success=False,
                    error_message=f"LDAP search_bind requires bind_dn and env var {ldap_cfg.bind_password_env}.",
                )

            with Connection(
                server,
                user=ldap_cfg.bind_dn,
                password=bind_password,
                auto_bind=False,
                receive_timeout=ldap_cfg.timeout_seconds,
            ) as svc_conn:
                if ldap_cfg.start_tls and not ldap_cfg.use_ssl:
                    svc_conn.open()
                    svc_conn.start_tls()
                if not svc_conn.bind():
                    return AuthResult(success=False, error_message="LDAP service bind failed.")

                safe_filter_user = escape_filter_chars(cleaned_user)
                search_filter = ldap_cfg.user_search_filter.replace("{username}", safe_filter_user)
                found = svc_conn.search(
                    search_base=ldap_cfg.base_dn,
                    search_filter=search_filter,
                    attributes=["cn", "displayName", "mail", "uid", "memberOf"],
                )
                if not found or not svc_conn.entries:
                    logger.warning("LDAP login failed: user '%s' not found in directory.", cleaned_user)
                    return AuthResult(success=False, error_message="Invalid LDAP credentials.")

                entry = svc_conn.entries[0]
                user_dn = str(entry.entry_dn)
                display_name = _entry_attr(entry, "displayName") or _entry_attr(entry, "cn") or cleaned_user
                email = _entry_attr(entry, "mail")
                member_of = _entry_list(entry, "memberOf")
        else:
            safe_rdn_user = escape_rdn(cleaned_user)
            user_dn = ldap_cfg.user_dn_template.replace("{username}", safe_rdn_user)
            display_name = cleaned_user
            email = ""
            member_of = []

        # Perform actual user credential bind
        with Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=False,
            receive_timeout=ldap_cfg.timeout_seconds,
        ) as user_conn:
            if ldap_cfg.start_tls and not ldap_cfg.use_ssl:
                user_conn.open()
                user_conn.start_tls()
            if not user_conn.bind():
                logger.warning("LDAP bind rejected for user '%s'.", cleaned_user)
                return AuthResult(success=False, error_message="Invalid LDAP credentials.")

            # Fetch attributes if direct_bind succeeded and base_dn is available
            if ldap_cfg.auth_mode == "direct_bind" and ldap_cfg.base_dn:
                try:
                    safe_filter_user = escape_filter_chars(cleaned_user)
                    search_filter = ldap_cfg.user_search_filter.replace("{username}", safe_filter_user)
                    if user_conn.search(
                        search_base=ldap_cfg.base_dn,
                        search_filter=search_filter,
                        attributes=["cn", "displayName", "mail", "memberOf"],
                    ) and user_conn.entries:
                        entry = user_conn.entries[0]
                        display_name = _entry_attr(entry, "displayName") or _entry_attr(entry, "cn") or cleaned_user
                        email = _entry_attr(entry, "mail")
                        member_of = _entry_list(entry, "memberOf")
                except LDAPException:
                    pass

            if ldap_cfg.allowed_group_dn.strip():
                required_group = ldap_cfg.allowed_group_dn.strip().lower()
                if not any(grp.lower() == required_group for grp in member_of):
                    logger.warning(
                        "LDAP user '%s' authenticated but is not in required group '%s'.",
                        cleaned_user,
                        ldap_cfg.allowed_group_dn,
                    )
                    return AuthResult(
                        success=False,
                        error_message="Account is not a member of the authorized LDAP group.",
                    )

        logger.info("Authenticated user '%s' via LDAP (%s).", cleaned_user, ldap_cfg.server_uri)
        return AuthResult(
            success=True,
            user=AuthenticatedUser(
                username=cleaned_user,
                display_name=display_name,
                email=email,
                auth_source="ldap",
            ),
        )

    except LDAPException as exc:
        logger.error("LDAP authentication error for '%s': %s", cleaned_user, exc)
        return AuthResult(success=False, error_message=f"LDAP connection failed: {exc}")


def test_ldap_connection(config: AppConfig) -> tuple[bool, str]:
    """Verify reachability and optional service bind for the configured LDAP server."""
    ldap_cfg = config.auth.ldap
    try:
        server = Server(
            ldap_cfg.server_uri,
            use_ssl=ldap_cfg.use_ssl,
            connect_timeout=ldap_cfg.timeout_seconds,
        )
        if ldap_cfg.auth_mode == "search_bind" and ldap_cfg.bind_dn:
            bind_password = os.environ.get(ldap_cfg.bind_password_env, "")
            with Connection(
                server,
                user=ldap_cfg.bind_dn,
                password=bind_password,
                auto_bind=False,
                receive_timeout=ldap_cfg.timeout_seconds,
            ) as conn:
                if ldap_cfg.start_tls and not ldap_cfg.use_ssl:
                    conn.open()
                    conn.start_tls()
                if conn.bind():
                    return True, f"Connected and bound to {ldap_cfg.server_uri} as {ldap_cfg.bind_dn}."
                return False, "Connected to LDAP server, but service bind failed."

        with Connection(
            server,
            auto_bind=False,
            receive_timeout=ldap_cfg.timeout_seconds,
        ) as conn:
            conn.open()
            if ldap_cfg.start_tls and not ldap_cfg.use_ssl:
                conn.start_tls()
            return True, f"TCP/TLS connection succeeded to {ldap_cfg.server_uri}."
    except Exception as exc:
        return False, f"LDAP connection failed: {exc}"


def _entry_attr(entry: object, attr_name: str) -> str:
    try:
        val = getattr(entry, attr_name, None)
        return str(val.value) if val and val.value else ""
    except Exception:
        return ""


def _entry_list(entry: object, attr_name: str) -> list[str]:
    try:
        val = getattr(entry, attr_name, None)
        if not val or not val.values:
            return []
        return [str(v) for v in val.values]
    except Exception:
        return []
