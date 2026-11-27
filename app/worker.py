"""Non-blocking background pipeline worker pool."""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

from app.config import AppConfig
from app.database import AbstractAuditRepository
from app.git_service import (
    clone_and_inspect_repository,
    create_temp_workspace,
    secure_cleanup_workspace,
)
from app.logging_config import get_logger
from app.models import ExecutionRecord, ExecutionStatus, GitLabContext
from app.pipeline_runner import execute_pipeline_steps, load_repository_pipeline_steps


class PipelineWorkerManager:
    """Executes webhook-triggered pipelines asynchronously in a bounded worker pool."""

    def __init__(self, config: AppConfig, repository: AbstractAuditRepository) -> None:
        self._config = config
        self._repository = repository
        self._executor = ThreadPoolExecutor(
            max_workers=config.pipeline.max_background_workers,
            thread_name_prefix="pipeline-worker",
        )

    def set_repository(self, repository: AbstractAuditRepository) -> None:
        """Swap the active audit repository at runtime (e.g. SQLite <-> PostgreSQL/MariaDB)."""
        self._repository = repository

    def submit(
        self,
        record: ExecutionRecord,
        context: GitLabContext,
        config_override: AppConfig | None = None,
    ) -> Future[None]:
        """Enqueue a pipeline execution and return immediately without blocking the webhook."""
        logger = get_logger()
        logger.info(
            "[%s] Webhook accepted (%s on %s / %s). Queued for background processing.",
            record.id,
            record.event_name,
            record.project_name,
            record.branch_name or record.tag_name or "default",
        )
        return self._executor.submit(self._run_pipeline, record, context, config_override)

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shut down the background worker pool."""
        self._executor.shutdown(wait=wait)

    def _run_pipeline(
        self,
        record: ExecutionRecord,
        context: GitLabContext,
        config_override: AppConfig | None = None,
    ) -> None:
        logger = get_logger()
        effective_config = config_override or self._config
        overall_start = time.monotonic()
        workspace_dir: Path | None = None

        record.started_at = ExecutionRecord.utc_now_iso()
        record.status = ExecutionStatus.CLONING
        self._repository.update_execution(record)

        try:
            workspace_dir = create_temp_workspace(effective_config, record.id)
            record.temp_workspace_path = str(workspace_dir)

            clone_result = clone_and_inspect_repository(
                config=effective_config,
                context=context,
                workspace_dir=workspace_dir,
                execution_id=record.id,
            )
            record.clone_duration_ms = clone_result.clone_duration_ms

            # Merge files discovered via git diff if webhook payload omitted per-file lists (common for MRs)
            existing_keys = {(f["path"], f["change_type"]) for f in record.changed_files}
            for item in clone_result.discovered_changed_files:
                key = (item["path"], item["change_type"])
                if key not in existing_keys:
                    record.changed_files.append(item)
                    existing_keys.add(key)

            # Refresh exported variables with any newly discovered files or checked-out SHA
            if clone_result.checked_out_sha and not context.checkout_sha:
                context.checkout_sha = clone_result.checked_out_sha
            updated_env = context.to_env_vars(record.id)
            if record.rerun_of_id:
                updated_env["PIPELINE_RERUN_OF"] = record.rerun_of_id
            if record.changed_files:
                updated_env["GITLAB_CHANGED_FILES"] = ",".join(f["path"] for f in record.changed_files)
                updated_env["GITLAB_CHANGED_FILES_COUNT"] = str(len(record.changed_files))
            record.variables = updated_env

            record.status = ExecutionStatus.RUNNING
            self._repository.update_execution(record)

            steps, config_source = load_repository_pipeline_steps(workspace_dir, effective_config)
            record.pipeline_config_source = config_source
            logger.info(
                "[%s] Loaded %d pipeline step(s) from '%s'.",
                record.id,
                len(steps),
                config_source,
            )

            step_results, all_passed, error_msg = execute_pipeline_steps(
                workspace_dir=workspace_dir,
                steps=steps,
                gitlab_env=updated_env,
                config=effective_config,
                execution_id=record.id,
            )
            record.steps = [asdict(step) for step in step_results]
            record.error_message = error_msg
            record.status = ExecutionStatus.SUCCEEDED if all_passed else ExecutionStatus.FAILED

        except Exception as exc:
            logger.exception("[%s] Pipeline execution failed: %s", record.id, exc)
            record.status = ExecutionStatus.FAILED
            record.error_message = str(exc)

        finally:
            if workspace_dir is not None and effective_config.pipeline.secure_cleanup:
                record.cleanup_verified = secure_cleanup_workspace(workspace_dir, record.id)
            elif workspace_dir is None:
                record.cleanup_verified = True

            record.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            record.finished_at = ExecutionRecord.utc_now_iso()
            self._repository.update_execution(record)
            logger.info(
                "[%s] Pipeline finished with status '%s' in %d ms (cleanup_verified=%s).",
                record.id,
                record.status.value,
                record.total_duration_ms,
                record.cleanup_verified,
            )
