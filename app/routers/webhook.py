"""GitLab Webhook receiver and JSON audit API endpoints."""

from __future__ import annotations

import hmac
import uuid
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.auth import AuthenticatedUser, get_session_user, verify_same_origin
from app.config import AppConfig, restore_execution_config, snapshot_execution_config
from app.local_simulator import build_simulated_webhook_payload, ensure_sample_bare_repository
from app.logging_config import get_logger
from app.models import ExecutionRecord, ExecutionStatus
from app.webhook_parser import parse_gitlab_webhook

router = APIRouter(tags=["webhooks"])


def _require_api_session(request: Request) -> AuthenticatedUser:
    user = get_session_user(request, request.app.state.config)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user


def _verify_gitlab_token(request: Request, expected_token: str) -> None:
    """Verify X-Gitlab-Token using constant-time comparison when configured."""
    if not expected_token:
        return
    provided = request.headers.get("X-Gitlab-Token", "")
    if not provided or not hmac.compare_digest(provided, expected_token):
        get_logger().warning("Rejected webhook request due to invalid or missing X-Gitlab-Token.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Gitlab-Token header.",
        )


def _build_and_enqueue_execution(
    request: Request,
    payload: dict[str, Any],
    headers: dict[str, str],
    effective_config: AppConfig,
    config_snapshot: dict[str, Any],
    rerun_of_id: str = "",
) -> tuple[ExecutionRecord, dict[str, str]]:
    """Create ExecutionRecord from parsed webhook context and submit to background worker."""
    repository = request.app.state.repository
    worker = request.app.state.worker

    context = parse_gitlab_webhook(payload, headers)
    execution_id = f"exec-{uuid.uuid4().hex[:10]}"
    env_vars = context.to_env_vars(execution_id)
    if rerun_of_id:
        env_vars["PIPELINE_RERUN_OF"] = rerun_of_id

    record = ExecutionRecord(
        id=execution_id,
        status=ExecutionStatus.QUEUED,
        event_name=context.x_gitlab_event or context.event_name,
        object_kind=context.object_kind,
        project_name=context.project_name,
        project_namespace=context.project_path_with_namespace,
        git_ssh_url=context.git_ssh_url or context.git_http_url,
        branch_name=context.branch_name,
        tag_name=context.tag_name,
        commit_sha=context.checkout_sha or context.after_sha,
        commit_title=context.commit_title,
        commit_message=context.commit_message,
        triggered_by_name=context.triggered_by_name,
        triggered_by_username=context.triggered_by_username,
        triggered_by_email=context.triggered_by_email,
        mr_iid=context.mr_iid,
        mr_title=context.mr_title,
        mr_source_branch=context.mr_source_branch,
        mr_target_branch=context.mr_target_branch,
        changed_files=[
            {
                "path": f.path,
                "change_type": f.change_type.value,
                "commit_id": f.commit_id,
                "previous_path": f.previous_path,
            }
            for f in context.changed_files
        ],
        commits=[asdict(c) for c in context.commits],
        variables=env_vars,
        steps=[],
        pipeline_config_source="",
        temp_workspace_path="",
        cleanup_verified=False,
        clone_duration_ms=0,
        total_duration_ms=0,
        error_message="",
        raw_payload=payload,
        created_at=ExecutionRecord.utc_now_iso(),
        config_snapshot=config_snapshot,
        rerun_of_id=rerun_of_id,
    )

    repository.create_execution(record)
    worker.submit(record, context, config_override=effective_config)
    return record, env_vars


def _enqueue_webhook(
    request: Request,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> tuple[ExecutionRecord, dict[str, str]]:
    """Parse webhook payload, verify allowed events, snapshot config, and enqueue background job."""
    config = request.app.state.config
    context = parse_gitlab_webhook(payload, headers)
    if config.webhook.allowed_events:
        allowed_lower = {e.lower() for e in config.webhook.allowed_events}
        event_candidates = {
            context.x_gitlab_event.lower(),
            context.event_name.lower(),
            context.object_kind.lower(),
        }
        # Allow standard GitLab object_kind mappings if X-Gitlab-Event matches
        if not (event_candidates & allowed_lower) and context.x_gitlab_event.lower() not in allowed_lower:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Event '{context.x_gitlab_event}' is not permitted by webhook.allowed_events.",
            )

    config_snapshot = snapshot_execution_config(config, headers)
    return _build_and_enqueue_execution(
        request=request,
        payload=payload,
        headers=headers,
        effective_config=config,
        config_snapshot=config_snapshot,
    )


def _synthesize_payload_from_record(original: ExecutionRecord) -> dict[str, Any]:
    """Fallback payload builder if an older record lacked raw_payload."""
    ref = (
        f"refs/tags/{original.tag_name}"
        if original.tag_name
        else f"refs/heads/{original.branch_name or 'main'}"
    )
    return {
        "object_kind": original.object_kind,
        "event_name": original.object_kind,
        "ref": ref,
        "after": original.commit_sha,
        "checkout_sha": original.commit_sha,
        "user_name": original.triggered_by_name,
        "user_username": original.triggered_by_username,
        "user_email": original.triggered_by_email,
        "project": {
            "name": original.project_name,
            "path_with_namespace": original.project_namespace,
            "git_ssh_url": original.git_ssh_url,
            "git_http_url": original.git_ssh_url,
        },
        "commits": original.commits,
        "total_commits_count": len(original.commits),
    }


def rerun_execution_by_id(
    request: Request,
    execution_id: str,
    requested_by: str = "operator",
) -> ExecutionRecord:
    """Trigger a new background execution using the original build's exact config & payload."""
    config = request.app.state.config
    repository = request.app.state.repository

    original = repository.get_execution(execution_id)
    if not original:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Original execution record not found.")

    snapshot = dict(original.config_snapshot) if original.config_snapshot else {}
    effective_config = restore_execution_config(config, snapshot)
    raw_headers = snapshot.get("headers") if isinstance(snapshot.get("headers"), dict) else {}
    headers = dict(raw_headers) if raw_headers else {"X-Gitlab-Event": original.event_name}
    payload = original.raw_payload if original.raw_payload else _synthesize_payload_from_record(original)
    if not snapshot:
        snapshot = snapshot_execution_config(effective_config, headers)

    new_record, _ = _build_and_enqueue_execution(
        request=request,
        payload=payload,
        headers=headers,
        effective_config=effective_config,
        config_snapshot=snapshot,
        rerun_of_id=original.id,
    )
    get_logger().info(
        "[%s] Re-run queued from original build '%s' by '%s' using captured build configuration.",
        new_record.id,
        original.id,
        requested_by,
    )
    return new_record


@router.post("/webhook/gitlab", status_code=status.HTTP_202_ACCEPTED)
@router.post("/api/webhook/gitlab", status_code=status.HTTP_202_ACCEPTED)
async def receive_gitlab_webhook(request: Request) -> JSONResponse:
    """Receive GitLab push, tag, commit, or merge-request webhook and return 202 immediately."""
    config = request.app.state.config
    _verify_gitlab_token(request, config.webhook.secret_token)

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON webhook payload.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook payload must be a JSON object.")

    headers = {k: v for k, v in request.headers.items()}
    record, _ = _enqueue_webhook(request, payload, headers)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "accepted": True,
            "execution_id": record.id,
            "status": record.status.value,
            "event": record.event_name,
            "project": record.project_namespace,
            "branch": record.branch_name,
            "tag": record.tag_name,
            "message": "Webhook accepted; repository clone and pipeline execution queued in background.",
        },
    )


@router.post("/api/webhook/simulate", status_code=status.HTTP_202_ACCEPTED)
async def simulate_local_webhook(request: Request) -> JSONResponse:
    """Trigger a real end-to-end pipeline run using a local bare Git repository (when enabled)."""
    _require_api_session(request)
    verify_same_origin(request)
    config = request.app.state.config
    if not config.webhook.enable_local_simulator:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local webhook simulator is disabled in config.yaml.",
        )

    body: dict[str, Any] = {}
    try:
        parsed = await request.json()
        if isinstance(parsed, dict):
            body = parsed
    except Exception:
        pass

    event_type = str(body.get("event_type", "push")).strip().lower()
    if event_type not in {"push", "tag_push", "merge_request"}:
        event_type = "push"

    repo_info = ensure_sample_bare_repository()
    headers, payload = build_simulated_webhook_payload(event_type, repo_info)
    record, _ = _enqueue_webhook(request, payload, headers)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "accepted": True,
            "execution_id": record.id,
            "status": record.status.value,
            "event": record.event_name,
            "redirect_url": f"/executions/{record.id}",
        },
    )


@router.get("/api/executions")
async def api_list_executions(
    request: Request,
    status_filter: str = "all",
    event: str = "all",
    q: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """JSON endpoint for execution history and summary metrics."""
    _require_api_session(request)
    repository = request.app.state.repository
    safe_limit = max(1, min(limit, 200))
    records = repository.list_executions(
        status=status_filter,
        event_kind=event,
        search=q,
        limit=safe_limit,
    )
    stats = repository.get_summary_stats()
    return {
        "stats": stats,
        "executions": [
            {
                "id": r.id,
                "status": r.status.value,
                "event_name": r.event_name,
                "object_kind": r.object_kind,
                "project_name": r.project_name,
                "project_namespace": r.project_namespace,
                "branch_name": r.branch_name,
                "tag_name": r.tag_name,
                "commit_sha": r.commit_sha,
                "commit_title": r.commit_title,
                "triggered_by_name": r.triggered_by_name,
                "triggered_by_username": r.triggered_by_username,
                "changed_files_count": len(r.changed_files),
                "total_duration_ms": r.total_duration_ms,
                "cleanup_verified": r.cleanup_verified,
                "created_at": r.created_at,
            }
            for r in records
        ],
    }


@router.get("/api/executions/{execution_id}")
async def api_get_execution(request: Request, execution_id: str) -> dict[str, Any]:
    """JSON endpoint returning full audit details for one pipeline execution."""
    _require_api_session(request)
    record = request.app.state.repository.get_execution(execution_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found.")
    return {
        "id": record.id,
        "status": record.status.value,
        "event_name": record.event_name,
        "object_kind": record.object_kind,
        "project_name": record.project_name,
        "project_namespace": record.project_namespace,
        "branch_name": record.branch_name,
        "tag_name": record.tag_name,
        "commit_sha": record.commit_sha,
        "commit_title": record.commit_title,
        "commit_message": record.commit_message,
        "triggered_by_name": record.triggered_by_name,
        "triggered_by_username": record.triggered_by_username,
        "triggered_by_email": record.triggered_by_email,
        "mr_iid": record.mr_iid,
        "mr_title": record.mr_title,
        "mr_source_branch": record.mr_source_branch,
        "mr_target_branch": record.mr_target_branch,
        "changed_files": record.changed_files,
        "commits": record.commits,
        "variables": record.variables,
        "steps": record.steps,
        "pipeline_config_source": record.pipeline_config_source,
        "cleanup_verified": record.cleanup_verified,
        "clone_duration_ms": record.clone_duration_ms,
        "total_duration_ms": record.total_duration_ms,
        "error_message": record.error_message,
        "created_at": record.created_at,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
    }


@router.post("/api/executions/{execution_id}/rerun", status_code=status.HTTP_202_ACCEPTED)
async def api_rerun_execution(request: Request, execution_id: str) -> JSONResponse:
    """Re-run a historical pipeline execution with its exact original configuration."""
    user = _require_api_session(request)
    verify_same_origin(request)
    new_record = rerun_execution_by_id(request, execution_id, requested_by=user.username)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "accepted": True,
            "execution_id": new_record.id,
            "rerun_of_id": new_record.rerun_of_id,
            "status": new_record.status.value,
            "redirect_url": f"/executions/{new_record.id}",
        },
    )


@router.get("/api/health")
async def health_check(request: Request) -> dict[str, Any]:
    """Health check reporting database readiness."""
    db_info = request.app.state.repository.get_database_info()
    return {"status": "ok", "database": db_info["path"], "executions_logged": db_info["row_count"]}
