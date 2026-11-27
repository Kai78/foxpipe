"""Unit tests for comprehensive GitLab webhook variable extraction."""

from __future__ import annotations

from app.webhook_parser import parse_gitlab_webhook


def test_parse_push_webhook_extracts_all_variables() -> None:
    payload = {
        "object_kind": "push",
        "event_name": "push",
        "before": "1111111111111111111111111111111111111111",
        "after": "2222222222222222222222222222222222222222",
        "ref": "refs/heads/release/2026-q4",
        "checkout_sha": "2222222222222222222222222222222222222222",
        "user_id": 77,
        "user_name": "Ada Lovelace",
        "user_username": "alovelace",
        "user_email": "ada@example.org",
        "project": {
            "id": 901,
            "name": "core-engine",
            "path_with_namespace": "analytics/core-engine",
            "git_ssh_url": "git@gitlab.example.com:analytics/core-engine.git",
            "git_http_url": "https://gitlab.example.com/analytics/core-engine.git",
            "web_url": "https://gitlab.example.com/analytics/core-engine",
            "default_branch": "main",
        },
        "commits": [
            {
                "id": "2222222222222222222222222222222222222222",
                "title": "feat: optimize query planner",
                "message": "feat: optimize query planner\n\nIncludes index hints.",
                "timestamp": "2026-11-27T10:00:00Z",
                "url": "https://gitlab.example.com/analytics/core-engine/-/commit/22222222",
                "author": {"name": "Ada Lovelace", "email": "ada@example.org"},
                "added": ["src/planner.py"],
                "modified": ["src/engine.py", "README.md"],
                "removed": ["src/legacy.py"],
            }
        ],
        "total_commits_count": 1,
    }

    ctx = parse_gitlab_webhook(payload, {"X-Gitlab-Event": "Push Hook"})
    env = ctx.to_env_vars("exec-test123")

    assert ctx.branch_name == "release/2026-q4"
    assert ctx.tag_name == ""
    assert ctx.triggered_by_username == "alovelace"
    assert ctx.commit_title == "feat: optimize query planner"
    assert len(ctx.changed_files) == 4
    assert env["GITLAB_BRANCH"] == "release/2026-q4"
    assert env["GITLAB_ADDED_FILES"] == "src/planner.py"
    assert env["GITLAB_MODIFIED_FILES"] == "src/engine.py,README.md"
    assert env["GITLAB_REMOVED_FILES"] == "src/legacy.py"
    assert env["GITLAB_USER_EMAIL"] == "ada@example.org"
    assert env["CI_COMMIT_SHORT_SHA"] == "22222222"


def test_parse_tag_and_merge_request_webhooks() -> None:
    tag_ctx = parse_gitlab_webhook(
        {
            "object_kind": "tag_push",
            "ref": "refs/tags/v2.4.1",
            "after": "abcdef1234567890abcdef1234567890abcdef12",
            "user_name": "Grace Hopper",
            "user_username": "ghopper",
            "project": {"name": "compiler", "path_with_namespace": "systems/compiler"},
        },
        {"X-Gitlab-Event": "Tag Push Hook"},
    )
    assert tag_ctx.is_tag is True
    assert tag_ctx.tag_name == "v2.4.1"
    assert tag_ctx.branch_name == ""

    mr_ctx = parse_gitlab_webhook(
        {
            "object_kind": "merge_request",
            "user": {"name": "Linus", "username": "ltorvalds", "email": "linus@example.org"},
            "project": {"name": "kernel", "path_with_namespace": "os/kernel"},
            "object_attributes": {
                "id": 100,
                "iid": 19,
                "title": "Fix scheduler race",
                "state": "opened",
                "action": "update",
                "source_branch": "fix/scheduler",
                "target_branch": "main",
                "draft": False,
                "last_commit": {"id": "deadbeef12345678", "message": "Fix lock ordering"},
            },
            "labels": [{"title": "priority::high"}],
        },
        {"X-Gitlab-Event": "Merge Request Hook"},
    )
    mr_env = mr_ctx.to_env_vars("exec-mr19")
    assert mr_ctx.mr_iid == 19
    assert mr_ctx.mr_source_branch == "fix/scheduler"
    assert mr_ctx.mr_target_branch == "main"
    assert mr_env["GITLAB_MR_LABELS"] == "priority::high"
    assert mr_env["CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"] == "fix/scheduler"
