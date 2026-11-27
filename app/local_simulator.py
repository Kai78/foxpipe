"""Local bare Git repository builder for authentic end-to-end webhook testing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.config import PROJECT_ROOT


def ensure_sample_bare_repository(base_dir: Path | None = None) -> dict[str, Any]:
    """Create or refresh a real local bare Git repository with branches, tags, and .pipeline.yml."""
    root = base_dir or (PROJECT_ROOT / "data" / "sample_repo")
    bare_repo = root / "demo-service.git"
    if bare_repo.exists() and (bare_repo / "HEAD").exists():
        # Read existing commits/refs so webhook payload matches real Git SHAs
        return _inspect_sample_repo(bare_repo)

    root.mkdir(parents=True, exist_ok=True)
    if bare_repo.exists():
        shutil.rmtree(bare_repo)

    subprocess.run(["git", "init", "--bare", str(bare_repo)], check=True, capture_output=True, text=True)

    with tempfile.TemporaryDirectory(prefix="seed_sample_repo_") as tmp:
        work = Path(tmp) / "work"
        subprocess.run(["git", "clone", str(bare_repo), str(work)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(work), "config", "user.name", "Elena Vance"], check=True)
        subprocess.run(["git", "-C", str(work), "config", "user.email", "elena.vance@example.com"], check=True)
        subprocess.run(["git", "-C", str(work), "checkout", "-b", "main"], check=True, capture_output=True)

        (work / ".pipeline.yml").write_text(
            """name: demo-service-pipeline
steps:
  - name: Verify Git Checkout & Changed Files
    command: |
      echo "Repository: $GITLAB_PROJECT_NAMESPACE"
      echo "Event: $GITLAB_EVENT ($GITLAB_OBJECT_KIND)"
      echo "Branch: $GITLAB_BRANCH | Tag: $GITLAB_TAG | SHA: $GITLAB_COMMIT_SHORT_SHA"
      echo "Triggered by: $GITLAB_USER_NAME <$GITLAB_USER_EMAIL>"
      echo "Changed files ($GITLAB_CHANGED_FILES_COUNT): $GITLAB_CHANGED_FILES"
      git log -1 --stat
  - name: Run Python Unit Check
    command: |
      python3 -m unittest discover -s tests -p "test_*.py"
""",
            encoding="utf-8",
        )
        (work / "src").mkdir(exist_ok=True)
        (work / "tests").mkdir(exist_ok=True)
        (work / "src" / "calculator.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n",
            encoding="utf-8",
        )
        (work / "tests" / "test_calculator.py").write_text(
            "import unittest\nfrom src.calculator import add\n\n"
            "class TestCalculator(unittest.TestCase):\n"
            "    def test_add(self) -> None:\n"
            "        self.assertEqual(add(2, 3), 5)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(work), "commit", "-m", "chore: initialize service and pipeline config"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "-C", str(work), "push", "-u", "origin", "main"], check=True, capture_output=True)

        # Second commit on main
        (work / "src" / "calculator.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n\n"
            "def multiply(a: int, b: int) -> int:\n    return a * b\n",
            encoding="utf-8",
        )
        (work / "README.md").write_text("# Demo Service\nSample repository for GitLab webhook pipelines.\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(work), "commit", "-m", "feat(math): add multiply helper and README"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "-C", str(work), "push", "origin", "main"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(work), "tag", "-a", "v1.2.0", "-m", "Release v1.2.0"], check=True)
        subprocess.run(["git", "-C", str(work), "push", "origin", "v1.2.0"], check=True, capture_output=True)

        # Feature branch for Merge Request testing
        subprocess.run(["git", "-C", str(work), "checkout", "-b", "feat/audit-headers"], check=True, capture_output=True)
        (work / "src" / "headers.py").write_text(
            "def build_audit_header(exec_id: str) -> dict[str, str]:\n"
            "    return {'X-Pipeline-Run': exec_id}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(work), "commit", "-m", "feat(audit): attach X-Pipeline-Run header"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "-C", str(work), "push", "-u", "origin", "feat/audit-headers"], check=True, capture_output=True)

    return _inspect_sample_repo(bare_repo)


def _inspect_sample_repo(bare_repo: Path) -> dict[str, Any]:
    def git_out(*args: str) -> str:
        proc = subprocess.run(
            ["git", "--git-dir", str(bare_repo), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.stdout.strip()

    main_head = git_out("rev-parse", "refs/heads/main")
    main_parent = git_out("rev-parse", "refs/heads/main~1")
    feat_head = git_out("rev-parse", "refs/heads/feat/audit-headers")
    tag_sha = git_out("rev-parse", "refs/tags/v1.2.0^{commit}")

    return {
        "repo_path": str(bare_repo),
        "main_head": main_head,
        "main_parent": main_parent,
        "feat_head": feat_head,
        "tag_sha": tag_sha or main_head,
    }


def build_simulated_webhook_payload(event_type: str, repo_info: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    """Build an authentic GitLab webhook header + JSON body pointing to the real local bare repo."""
    repo_url = f"file://{repo_info['repo_path']}"
    project_block = {
        "id": 4021,
        "name": "demo-service",
        "description": "Local Git repository for webhook pipeline verification",
        "web_url": "https://gitlab.example.internal/platform/demo-service",
        "git_ssh_url": repo_url,
        "git_http_url": repo_url,
        "namespace": "platform",
        "path_with_namespace": "platform/demo-service",
        "default_branch": "main",
    }

    if event_type == "tag_push":
        headers = {"X-Gitlab-Event": "Tag Push Hook"}
        payload = {
            "object_kind": "tag_push",
            "event_name": "tag_push",
            "before": "0" * 40,
            "after": repo_info["tag_sha"],
            "ref": "refs/tags/v1.2.0",
            "checkout_sha": repo_info["tag_sha"],
            "message": "Release v1.2.0",
            "user_id": 104,
            "user_name": "Elena Vance",
            "user_username": "evance",
            "user_email": "elena.vance@example.com",
            "project_id": 4021,
            "project": project_block,
            "commits": [
                {
                    "id": repo_info["tag_sha"],
                    "message": "feat(math): add multiply helper and README",
                    "title": "feat(math): add multiply helper and README",
                    "timestamp": "2026-11-27T12:00:00Z",
                    "url": "https://gitlab.example.internal/platform/demo-service/-/commit/" + repo_info["tag_sha"],
                    "author": {"name": "Elena Vance", "email": "elena.vance@example.com"},
                    "added": ["README.md"],
                    "modified": ["src/calculator.py"],
                    "removed": [],
                }
            ],
            "total_commits_count": 1,
        }
        return headers, payload

    if event_type == "merge_request":
        headers = {"X-Gitlab-Event": "Merge Request Hook"}
        payload = {
            "object_kind": "merge_request",
            "event_type": "merge_request",
            "user": {
                "id": 108,
                "name": "Marcus Chen",
                "username": "mchen",
                "email": "marcus.chen@example.com",
            },
            "project": project_block,
            "object_attributes": {
                "id": 9912,
                "iid": 42,
                "title": "feat(audit): attach X-Pipeline-Run header",
                "description": "Adds X-Pipeline-Run header helper for downstream trace correlation.",
                "state": "opened",
                "action": "open",
                "merge_status": "can_be_merged",
                "source_branch": "feat/audit-headers",
                "target_branch": "main",
                "url": "https://gitlab.example.internal/platform/demo-service/-/merge_requests/42",
                "draft": False,
                "last_commit": {
                    "id": repo_info["feat_head"],
                    "message": "feat(audit): attach X-Pipeline-Run header",
                    "title": "feat(audit): attach X-Pipeline-Run header",
                    "timestamp": "2026-11-27T12:10:00Z",
                    "author": {"name": "Marcus Chen", "email": "marcus.chen@example.com"},
                },
            },
            "labels": [{"title": "backend"}, {"title": "audit"}],
            "assignees": [{"username": "mchen"}],
            "reviewers": [{"username": "evance"}],
        }
        return headers, payload

    # Default: Push Hook
    headers = {"X-Gitlab-Event": "Push Hook"}
    payload = {
        "object_kind": "push",
        "event_name": "push",
        "before": repo_info["main_parent"],
        "after": repo_info["main_head"],
        "ref": "refs/heads/main",
        "checkout_sha": repo_info["main_head"],
        "user_id": 104,
        "user_name": "Elena Vance",
        "user_username": "evance",
        "user_email": "elena.vance@example.com",
        "project_id": 4021,
        "project": project_block,
        "commits": [
            {
                "id": repo_info["main_head"],
                "message": "feat(math): add multiply helper and README",
                "title": "feat(math): add multiply helper and README",
                "timestamp": "2026-11-27T12:00:00Z",
                "url": "https://gitlab.example.internal/platform/demo-service/-/commit/" + repo_info["main_head"],
                "author": {"name": "Elena Vance", "email": "elena.vance@example.com"},
                "added": ["README.md"],
                "modified": ["src/calculator.py"],
                "removed": [],
            }
        ],
        "total_commits_count": 1,
    }
    return headers, payload
