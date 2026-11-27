"""Repository pipeline configuration parser and step executor."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.config import AppConfig
from app.logging_config import get_logger
from app.models import PipelineStepResult


@dataclass(slots=True)
class PipelineStepSpec:
    """Single executable step resolved from repository config or defaults."""

    name: str
    command: str


def load_repository_pipeline_steps(
    workspace_dir: Path,
    config: AppConfig,
) -> tuple[list[PipelineStepSpec], str]:
    """Discover pipeline scripts from the cloned repository configuration file."""
    candidates = [config.pipeline.repo_config_filename, *config.pipeline.fallback_config_filenames]

    for filename in candidates:
        candidate_path = (workspace_dir / filename).resolve()
        # Confine config lookup strictly within cloned workspace
        if not candidate_path.is_relative_to(workspace_dir.resolve()):
            continue
        if not candidate_path.is_file():
            continue

        raw_data = yaml.safe_load(candidate_path.read_text(encoding="utf-8"))
        steps = _parse_repo_yaml(raw_data)
        if steps:
            return steps, filename

    fallback_steps = [
        PipelineStepSpec(name=item.name, command=item.command)
        for item in config.pipeline.default_scripts
    ]
    return fallback_steps, "config.yaml (default_scripts)"


def _parse_repo_yaml(raw_data: Any) -> list[PipelineStepSpec]:
    """Parse flexible YAML pipeline definitions (steps list, scripts list, or stage map)."""
    if not isinstance(raw_data, dict):
        return []

    steps: list[PipelineStepSpec] = []

    raw_steps = raw_data.get("steps") or raw_data.get("scripts") or raw_data.get("pipeline")
    if isinstance(raw_steps, list):
        for index, item in enumerate(raw_steps, start=1):
            if isinstance(item, str) and item.strip():
                steps.append(PipelineStepSpec(name=f"Step {index}", command=item.strip()))
            elif isinstance(item, dict):
                cmd = item.get("command") or item.get("run") or item.get("script")
                if isinstance(cmd, list):
                    cmd_str = " && ".join(str(line).strip() for line in cmd if str(line).strip())
                else:
                    cmd_str = str(cmd or "").strip()
                if cmd_str:
                    step_name = str(item.get("name") or f"Step {index}")
                    steps.append(PipelineStepSpec(name=step_name, command=cmd_str))
        return steps

    # Support GitLab-style jobs: {build: {script: [...]}}
    for key, val in raw_data.items():
        if key in {"stages", "variables", "image", "before_script", "after_script"}:
            continue
        if isinstance(val, dict) and "script" in val:
            script_val = val["script"]
            if isinstance(script_val, list):
                cmd_str = " && ".join(str(line).strip() for line in script_val if str(line).strip())
            else:
                cmd_str = str(script_val or "").strip()
            if cmd_str:
                steps.append(PipelineStepSpec(name=str(key), command=cmd_str))

    return steps


def execute_pipeline_steps(
    workspace_dir: Path,
    steps: list[PipelineStepSpec],
    gitlab_env: dict[str, str],
    config: AppConfig,
    execution_id: str,
) -> tuple[list[PipelineStepResult], bool, str]:
    """Execute resolved pipeline steps sequentially inside the cloned workspace."""
    logger = get_logger()
    results: list[PipelineStepResult] = []
    exec_env = os.environ.copy()
    exec_env.update(gitlab_env)
    exec_env["PIPELINE_WORKSPACE_DIR"] = str(workspace_dir)

    for idx, step in enumerate(steps, start=1):
        logger.info("[%s] Running step %d/%d: '%s'", execution_id, idx, len(steps), step.name)
        started = time.monotonic()

        try:
            proc = subprocess.run(
                ["/bin/bash", "-eo", "pipefail", "-c", step.command],
                cwd=str(workspace_dir),
                env=exec_env,
                capture_output=True,
                text=True,
                timeout=config.pipeline.step_timeout_seconds,
                check=False,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            succeeded = proc.returncode == 0
            result = PipelineStepResult(
                step_index=idx,
                name=step.name,
                command=step.command,
                exit_code=proc.returncode,
                stdout=_truncate_output(proc.stdout),
                stderr=_truncate_output(proc.stderr),
                duration_ms=duration_ms,
                status="succeeded" if succeeded else "failed",
            )
            results.append(result)

            if not succeeded:
                err_msg = f"Step '{step.name}' failed with exit code {proc.returncode}."
                logger.error("[%s] %s", execution_id, err_msg)
                return results, False, err_msg

            logger.info("[%s] Step '%s' succeeded in %d ms.", execution_id, step.name, duration_ms)

        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            results.append(
                PipelineStepResult(
                    step_index=idx,
                    name=step.name,
                    command=step.command,
                    exit_code=124,
                    stdout=_truncate_output(stdout),
                    stderr=_truncate_output(stderr + f"\nStep timed out after {config.pipeline.step_timeout_seconds}s."),
                    duration_ms=duration_ms,
                    status="failed",
                )
            )
            err_msg = f"Step '{step.name}' timed out after {config.pipeline.step_timeout_seconds}s."
            logger.error("[%s] %s", execution_id, err_msg)
            return results, False, err_msg

    return results, True, ""


def _truncate_output(text: str, max_chars: int = 32_768) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [output truncated to 32 KB]"
