"""SSH-authenticated GitLab repository cloner, diff inspector, and secure workspace cleaner."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from app.config import AppConfig
from app.logging_config import get_logger
from app.models import ChangeType, GitLabContext

SAFE_REF_PATTERN = re.compile(r"^[A-Za-z0-9._/\-]+$")
SCP_SSH_PATTERN = re.compile(r"^([A-Za-z0-9._-]+)@([A-Za-z0-9._-]+):([A-Za-z0-9._/\-~]+)(?:\.git)?$")


@dataclass(slots=True)
class CloneResult:
    """Outcome of cloning and inspecting a Git repository in an ephemeral temp directory."""

    workspace_dir: Path
    clone_duration_ms: int
    discovered_changed_files: list[dict[str, str]]
    checked_out_sha: str


def _validate_git_ref(ref_value: str) -> str:
    """Reject empty or potentially dangerous git ref values (prevents flag injection)."""
    cleaned = ref_value.strip()
    if not cleaned:
        return ""
    if cleaned.startswith("-") or ".." in cleaned or not SAFE_REF_PATTERN.match(cleaned):
        raise ValueError(f"Unsafe or malformed git reference '{cleaned}'.")
    return cleaned


def validate_repository_url(repo_url: str, config: AppConfig) -> str:
    """Validate repository clone URL against allowed schemes and configured GitLab hosts."""
    cleaned = repo_url.strip()
    if not cleaned or cleaned.startswith("-"):
        raise ValueError("Repository URL is missing or invalid.")

    # Local repository path allowed only when local simulator is enabled and URL is file:// or existing path
    if cleaned.startswith("file://") or cleaned.startswith("/"):
        if not config.webhook.enable_local_simulator:
            raise ValueError("Local repository paths are disabled by configuration.")
        return cleaned

    scp_match = SCP_SSH_PATTERN.match(cleaned)
    if scp_match:
        host = scp_match.group(2)
        _check_host_allowlist(host, config.webhook.allowed_repo_hosts)
        return cleaned

    parsed = urlparse(cleaned)
    if parsed.scheme not in {"ssh", "https", "http"}:
        raise ValueError(f"Unsupported Git repository URL scheme '{parsed.scheme}'. Use SSH (git@...) or HTTPS.")
    if not parsed.hostname:
        raise ValueError("Repository URL does not contain a valid hostname.")

    _check_host_allowlist(parsed.hostname, config.webhook.allowed_repo_hosts)
    return cleaned


def _check_host_allowlist(host: str, allowed_hosts: list[str]) -> None:
    if not allowed_hosts:
        return
    normalized = host.lower()
    if normalized not in {h.lower() for h in allowed_hosts}:
        raise ValueError(f"Repository host '{host}' is not in webhook.allowed_repo_hosts.")


def build_git_ssh_command(config: AppConfig) -> str:
    """Construct an explicit, safe GIT_SSH_COMMAND using the configured private key."""
    key_path = config.resolve_path(config.ssh.private_key_path)
    known_hosts_path = config.resolve_path(config.ssh.known_hosts_path)

    ssh_args = ["ssh", "-o", "BatchMode=yes"]
    if key_path.exists():
        # Ensure restrictive permissions required by OpenSSH
        try:
            current_mode = stat.S_IMODE(key_path.stat().st_mode)
            if current_mode & 0o077:
                os.chmod(key_path, 0o600)
        except OSError:
            pass
        ssh_args.extend(["-i", str(key_path), "-o", "IdentitiesOnly=yes"])

    strict = config.ssh.strict_host_key_checking.strip().lower()
    if strict not in {"yes", "no", "accept-new"}:
        strict = "accept-new"
    ssh_args.extend(["-o", f"StrictHostKeyChecking={strict}"])

    if known_hosts_path.exists():
        ssh_args.extend(["-o", f"UserKnownHostsFile={known_hosts_path}"])
    elif strict == "no":
        ssh_args.extend(["-o", "UserKnownHostsFile=/dev/null"])

    return " ".join(shlex.quote(arg) for arg in ssh_args)


def get_ssh_key_status(config: AppConfig) -> dict[str, str | bool]:
    """Inspect configured SSH keypair for the Configuration dashboard."""
    key_path = config.resolve_path(config.ssh.private_key_path)
    pub_path = Path(f"{key_path}.pub")
    exists = key_path.exists()
    pub_exists = pub_path.exists()

    public_key = ""
    fingerprint = ""
    permissions = ""

    if exists:
        try:
            permissions = oct(stat.S_IMODE(key_path.stat().st_mode))
        except OSError:
            permissions = "unknown"

    if pub_exists:
        try:
            public_key = pub_path.read_text(encoding="utf-8").strip()
            proc = subprocess.run(
                ["ssh-keygen", "-lf", str(pub_path)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                fingerprint = proc.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass

    return {
        "private_key_path": str(key_path),
        "public_key_path": str(pub_path),
        "private_key_exists": exists,
        "public_key_exists": pub_exists,
        "permissions": permissions,
        "public_key": public_key,
        "fingerprint": fingerprint,
    }


def generate_ssh_keypair(config: AppConfig, comment: str = "gitlab-ssh-pipeline-runner") -> dict[str, str | bool]:
    """Generate a new Ed25519 SSH keypair at the configured ssh.private_key_path."""
    key_path = config.resolve_path(config.ssh.private_key_path)
    if key_path.exists():
        raise FileExistsError(f"SSH key already exists at {key_path}.")

    key_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(key_path.parent, 0o700)

    proc = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key_path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {proc.stderr.strip() or proc.stdout.strip()}")

    os.chmod(key_path, 0o600)
    get_logger().info("Generated new Ed25519 SSH deploy key at %s.", key_path)
    return get_ssh_key_status(config)


def create_temp_workspace(config: AppConfig, execution_id: str) -> Path:
    """Create a private temporary workspace directory for cloning a repository."""
    base_dir = Path(config.pipeline.temp_base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=f"run_{execution_id}_", dir=str(base_dir)))
    os.chmod(workspace, 0o700)
    return workspace


def clone_and_inspect_repository(
    config: AppConfig,
    context: GitLabContext,
    workspace_dir: Path,
    execution_id: str,
) -> CloneResult:
    """Clone the GitLab repository using SSH keys, checkout target ref/SHA, and inspect changed files."""
    logger = get_logger()
    repo_url = context.git_ssh_url or context.git_http_url
    validated_url = validate_repository_url(repo_url, config)

    target_branch = _validate_git_ref(context.mr_source_branch or context.branch_name)
    target_tag = _validate_git_ref(context.tag_name)
    target_sha = _validate_git_ref(context.checkout_sha or context.after_sha)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_SSH_COMMAND"] = build_git_ssh_command(config)

    started = time.monotonic()
    clone_cmd = ["git", "clone", "--no-tags"]
    if config.ssh.clone_depth > 0:
        clone_cmd.extend(["--depth", str(config.ssh.clone_depth)])

    ref_to_clone = target_tag or target_branch
    if ref_to_clone:
        clone_cmd.extend(["--branch", ref_to_clone])

    clone_cmd.extend([validated_url, str(workspace_dir)])

    logger.info("[%s] Cloning repository '%s' into ephemeral workspace...", execution_id, validated_url)
    clone_proc = subprocess.run(
        clone_cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=config.ssh.clone_timeout_seconds,
        check=False,
    )

    # Retry without --branch if specific ref wasn't directly cloneable (e.g., detached SHA or MR fork)
    if clone_proc.returncode != 0 and ref_to_clone:
        logger.warning(
            "[%s] Branch/tag clone failed for '%s', retrying default clone...",
            execution_id,
            ref_to_clone,
        )
        _wipe_directory_contents(workspace_dir)
        fallback_cmd = ["git", "clone"]
        if config.ssh.clone_depth > 0:
            fallback_cmd.extend(["--depth", str(config.ssh.clone_depth)])
        fallback_cmd.extend([validated_url, str(workspace_dir)])
        clone_proc = subprocess.run(
            fallback_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=config.ssh.clone_timeout_seconds,
            check=False,
        )

    if clone_proc.returncode != 0:
        err_msg = clone_proc.stderr.strip() or clone_proc.stdout.strip() or "git clone failed"
        raise RuntimeError(f"Git clone failed: {err_msg}")

    if target_sha:
        checkout_proc = subprocess.run(
            ["git", "-C", str(workspace_dir), "checkout", "--force", target_sha],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if checkout_proc.returncode != 0:
            logger.info(
                "[%s] Direct SHA checkout '%s' unavailable in shallow clone; fetching ref...",
                execution_id,
                target_sha[:8],
            )
            subprocess.run(
                ["git", "-C", str(workspace_dir), "fetch", "--all", "--tags"],
                env=env,
                capture_output=True,
                text=True,
                timeout=config.ssh.clone_timeout_seconds,
                check=False,
            )
            subprocess.run(
                ["git", "-C", str(workspace_dir), "checkout", "--force", target_sha],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

    head_proc = subprocess.run(
        ["git", "-C", str(workspace_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    checked_out_sha = head_proc.stdout.strip() if head_proc.returncode == 0 else target_sha

    discovered_files = _inspect_changed_files_from_git(
        workspace_dir=workspace_dir,
        before_sha=context.before_sha,
        after_sha=checked_out_sha,
    )

    clone_duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "[%s] Repository cloned cleanly in %d ms (HEAD=%s).",
        execution_id,
        clone_duration_ms,
        checked_out_sha[:8] if checked_out_sha else "unknown",
    )

    return CloneResult(
        workspace_dir=workspace_dir,
        clone_duration_ms=clone_duration_ms,
        discovered_changed_files=discovered_files,
        checked_out_sha=checked_out_sha,
    )


def _inspect_changed_files_from_git(
    workspace_dir: Path,
    before_sha: str,
    after_sha: str,
) -> list[dict[str, str]]:
    """Inspect changed files directly via git diff-tree as an authoritative supplement."""
    zero_sha = "0" * 40
    if before_sha and after_sha and before_sha != zero_sha:
        cmd = ["git", "-C", str(workspace_dir), "diff", "--name-status", before_sha, after_sha]
    elif after_sha:
        cmd = ["git", "-C", str(workspace_dir), "diff-tree", "--no-commit-id", "--name-status", "-r", "--root", after_sha]
    else:
        return []

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    if proc.returncode != 0:
        return []

    status_map = {
        "A": ChangeType.ADDED.value,
        "M": ChangeType.MODIFIED.value,
        "D": ChangeType.REMOVED.value,
        "R": ChangeType.RENAMED.value,
    }
    files: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        code = parts[0][0].upper()
        change_type = status_map.get(code, ChangeType.MODIFIED.value)
        if code == "R" and len(parts) >= 3:
            files.append(
                {
                    "path": parts[2],
                    "previous_path": parts[1],
                    "change_type": change_type,
                    "commit_id": after_sha,
                }
            )
        else:
            files.append(
                {
                    "path": parts[1],
                    "previous_path": "",
                    "change_type": change_type,
                    "commit_id": after_sha,
                }
            )
    return files


def secure_cleanup_workspace(workspace_dir: Path, execution_id: str) -> bool:
    """Securely remove temporary cloned repository files including read-only .git objects."""
    logger = get_logger()
    if not workspace_dir.exists():
        return True

    try:
        # Overwrite temporary script/secret files if any exist inside workspace root before deletion
        for item in workspace_dir.rglob("*"):
            if item.is_file() and item.suffix in {".key", ".pem", ".env"}:
                try:
                    size = item.stat().st_size
                    if size > 0 and size <= 1_048_576:
                        item.chmod(0o600)
                        item.write_bytes(b"\x00" * size)
                except OSError:
                    pass

        shutil.rmtree(workspace_dir, onerror=_handle_remove_readonly)
        removed = not workspace_dir.exists()
        if removed:
            logger.info("[%s] Securely cleaned up temporary workspace '%s'.", execution_id, workspace_dir)
        else:
            logger.warning("[%s] Temporary workspace '%s' still present after cleanup.", execution_id, workspace_dir)
        return removed
    except OSError as exc:
        logger.error("[%s] Failed to clean up workspace '%s': %s", execution_id, workspace_dir, exc)
        return False


def _wipe_directory_contents(directory: Path) -> None:
    if not directory.exists():
        return
    for child in directory.iterdir():
        if child.is_dir():
            shutil.rmtree(child, onerror=_handle_remove_readonly)
        else:
            child.chmod(0o600)
            child.unlink(missing_ok=True)


def _handle_remove_readonly(func: Callable[[str], None], path: str, _exc_info: object) -> None:
    """Ensure read-only Git pack/index files can be cleanly unlinked during cleanup."""
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        pass
