"""End-to-end integration tests: webhook 202 immediate return, background clone, SQLite audit, DB swap, and secure cleanup."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.local_simulator import build_simulated_webhook_payload, ensure_sample_bare_repository
from app.main import create_app


def test_webhook_returns_immediately_executes_cleans_up_and_logs(tmp_path: Path) -> None:
    db_file = tmp_path / "data" / "audit_one.db"
    alt_db_file = tmp_path / "data" / "audit_two.db"
    log_file = tmp_path / "logs" / "runner.log"
    work_base = tmp_path / "workspaces"
    cfg_file = tmp_path / "config.yaml"

    cfg_file.write_text(
        f"""
server:
  host: "127.0.0.1"
  port: 8000
  app_title: "Test Runner"
webhook:
  secret_token: "test-secret-token"
  allowed_events: ["Push Hook", "Tag Push Hook", "Merge Request Hook"]
  enable_local_simulator: true
ssh:
  private_key_path: "{tmp_path}/keys/id_ed25519"
  strict_host_key_checking: "no"
  clone_timeout_seconds: 30
  clone_depth: 20
pipeline:
  temp_base_dir: "{work_base}"
  repo_config_filename: ".pipeline.yml"
  step_timeout_seconds: 30
  max_background_workers: 2
  secure_cleanup: true
database:
  engine: "sqlite"
  sqlite_path: "{db_file}"
  allowed_dir: "{tmp_path}/data"
  wal_mode: true
logging:
  log_file: "{log_file}"
  level: "INFO"
  max_bytes: 1048576
  backup_count: 2
auth:
  enabled: false
""",
        encoding="utf-8",
    )

    repo_info = ensure_sample_bare_repository(tmp_path / "bare_repos")
    headers, payload = build_simulated_webhook_payload("push", repo_info)
    headers["X-Gitlab-Token"] = "test-secret-token"

    app = create_app(cfg_file)
    with TestClient(app) as client:
        # Reject invalid secret
        bad_resp = client.post("/webhook/gitlab", json=payload, headers={"X-Gitlab-Event": "Push Hook"})
        assert bad_resp.status_code == 401

        # Immediate 202 return
        start = time.monotonic()
        resp = client.post("/webhook/gitlab", json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start) * 1000
        assert resp.status_code == 202
        assert elapsed_ms < 2000
        exec_id = resp.json()["execution_id"]

        # Wait for background pipeline worker to finish
        deadline = time.monotonic() + 15.0
        final_data = {}
        while time.monotonic() < deadline:
            detail_resp = client.get(f"/api/executions/{exec_id}")
            assert detail_resp.status_code == 200
            final_data = detail_resp.json()
            if final_data["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.15)

        assert final_data["status"] == "succeeded"
        assert final_data["cleanup_verified"] is True
        assert len(final_data["steps"]) == 2
        assert final_data["pipeline_config_source"] == ".pipeline.yml"
        assert any(f["path"] == "src/calculator.py" for f in final_data["changed_files"])
        # Verify temp workspace directory was removed completely
        assert not any(work_base.iterdir())

        # Verify Jinja2 dashboard HTML renders cleanly
        dash_html = client.get("/")
        assert dash_html.status_code == 200
        assert exec_id in dash_html.text

        detail_html = client.get(f"/executions/{exec_id}")
        assert detail_html.status_code == 200
        assert "GITLAB_BRANCH" in detail_html.text

        # Verify friendly logfile created
        assert log_file.exists()
        log_text = log_file.read_text(encoding="utf-8")
        assert exec_id in log_text
        assert "Securely cleaned up temporary workspace" in log_text

        # Verify database can be switched cleanly at runtime
        app.state.repository.switch_database(alt_db_file)
        assert alt_db_file.exists()
        assert app.state.repository.get_summary_stats()["total"] == 0


def test_rerun_preserves_exact_original_configuration(tmp_path: Path) -> None:
    """Triggering Re-run from dashboard uses the original build's captured configuration even if live config changed."""
    db_file = tmp_path / "data" / "rerun_audit.db"
    log_file = tmp_path / "logs" / "rerun.log"
    work_base = tmp_path / "workspaces"
    cfg_file = tmp_path / "config.yaml"

    # Configure a distinctive repo_config_filename that does not exist in demo-service so default_scripts runs
    cfg_file.write_text(
        f"""
server:
  host: "127.0.0.1"
  port: 8000
  app_title: "Rerun Test Runner"
webhook:
  secret_token: "test-secret-token"
  allowed_events: ["Push Hook"]
  enable_local_simulator: true
ssh:
  private_key_path: "{tmp_path}/keys/id_ed25519"
  strict_host_key_checking: "no"
  clone_timeout_seconds: 30
  clone_depth: 20
pipeline:
  temp_base_dir: "{work_base}"
  repo_config_filename: ".nonexistent-original.yml"
  fallback_config_filenames: []
  default_scripts:
    - name: "Original Config Step"
      command: "echo ORIGINAL_BUILD_CONFIG_MARKER"
  step_timeout_seconds: 30
  max_background_workers: 2
  secure_cleanup: true
database:
  engine: "sqlite"
  sqlite_path: "{db_file}"
  allowed_dir: "{tmp_path}/data"
  wal_mode: true
logging:
  log_file: "{log_file}"
  level: "INFO"
  max_bytes: 1048576
  backup_count: 2
auth:
  enabled: false
""",
        encoding="utf-8",
    )

    repo_info = ensure_sample_bare_repository(tmp_path / "bare_repos")
    headers, payload = build_simulated_webhook_payload("push", repo_info)
    headers["X-Gitlab-Token"] = "test-secret-token"

    app = create_app(cfg_file)
    with TestClient(app) as client:
        resp = client.post("/webhook/gitlab", json=payload, headers=headers)
        assert resp.status_code == 202
        orig_id = resp.json()["execution_id"]

        deadline = time.monotonic() + 15.0
        orig_data = {}
        while time.monotonic() < deadline:
            orig_data = client.get(f"/api/executions/{orig_id}").json()
            if orig_data["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.1)

        assert orig_data["status"] == "succeeded"
        assert "ORIGINAL_BUILD_CONFIG_MARKER" in orig_data["steps"][0]["stdout"]

        # Now mutate live application config completely
        from app.config import DefaultScriptConfig

        app.state.config.pipeline.repo_config_filename = ".pipeline.yml"
        app.state.config.pipeline.default_scripts = [
            DefaultScriptConfig(name="Changed Config Step", command="echo MUTATED_CONFIG_MARKER")
        ]

        # Re-run button appears in dashboard history table; trigger Re-run via form POST
        dash_html = client.get("/")
        assert dash_html.status_code == 200
        assert f'/executions/{orig_id}/rerun' in dash_html.text

        import re

        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', dash_html.text)
        assert csrf_match
        rerun_resp = client.post(
            f"/executions/{orig_id}/rerun",
            data={"csrf_token": csrf_match.group(1), "target": "dashboard"},
            follow_redirects=False,
        )
        assert rerun_resp.status_code == 303
        assert "rerun_id=" in rerun_resp.headers["location"]
        rerun_id_match = re.search(r"rerun_id=([^&]+)", rerun_resp.headers["location"])
        assert rerun_id_match
        rerun_id = rerun_id_match.group(1)

        deadline = time.monotonic() + 15.0
        rerun_data = {}
        while time.monotonic() < deadline:
            rerun_data = client.get(f"/api/executions/{rerun_id}").json()
            if rerun_data["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.1)

        assert rerun_data["status"] == "succeeded"
        assert rerun_data["steps"][0]["name"] == "Original Config Step"
        assert "ORIGINAL_BUILD_CONFIG_MARKER" in rerun_data["steps"][0]["stdout"]
        assert rerun_data["variables"]["PIPELINE_RERUN_OF"] == orig_id

