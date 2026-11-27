"""Domain models and enumerations for the GitLab SSH Pipeline Runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    """Lifecycle states of a pipeline execution."""

    QUEUED = "queued"
    CLONING = "cloning"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ChangeType(str, Enum):
    """File modification type detected in a commit or git diff."""

    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    RENAMED = "renamed"


@dataclass(frozen=True, slots=True)
class ChangedFile:
    """Represents a file touched by a commit, push, or merge request."""

    path: str
    change_type: ChangeType
    commit_id: str = ""
    previous_path: str = ""


@dataclass(frozen=True, slots=True)
class CommitDetail:
    """Normalized metadata for a single Git commit from a webhook payload."""

    sha: str
    short_sha: str
    title: str
    message: str
    timestamp: str
    url: str
    author_name: str
    author_email: str
    added: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


@dataclass(slots=True)
class GitLabContext:
    """All extracted variables from a GitLab Push, Tag, Commit, or Merge Request webhook."""

    event_name: str
    object_kind: str
    x_gitlab_event: str
    x_gitlab_event_uuid: str
    project_id: int | None
    project_name: str
    project_path_with_namespace: str
    project_web_url: str
    git_ssh_url: str
    git_http_url: str
    default_branch: str
    ref: str
    branch_name: str
    tag_name: str
    is_tag: bool
    before_sha: str
    after_sha: str
    checkout_sha: str
    commit_message: str
    commit_title: str
    total_commits_count: int
    triggered_by_name: str
    triggered_by_username: str
    triggered_by_email: str
    triggered_by_id: int | None
    triggered_by_avatar: str
    # Merge Request specific fields
    mr_id: int | None = None
    mr_iid: int | None = None
    mr_title: str = ""
    mr_description: str = ""
    mr_state: str = ""
    mr_action: str = ""
    mr_merge_status: str = ""
    mr_source_branch: str = ""
    mr_target_branch: str = ""
    mr_url: str = ""
    mr_draft: bool = False
    mr_labels: list[str] = field(default_factory=list)
    mr_assignees: list[str] = field(default_factory=list)
    mr_reviewers: list[str] = field(default_factory=list)
    # Collections
    commits: list[CommitDetail] = field(default_factory=list)
    changed_files: list[ChangedFile] = field(default_factory=list)
    extra_variables: dict[str, str] = field(default_factory=dict)

    def to_env_vars(self, execution_id: str) -> dict[str, str]:
        """Build a clean flat dictionary of environment variables for pipeline scripts."""
        added_files = [f.path for f in self.changed_files if f.change_type == ChangeType.ADDED]
        modified_files = [f.path for f in self.changed_files if f.change_type == ChangeType.MODIFIED]
        removed_files = [f.path for f in self.changed_files if f.change_type == ChangeType.REMOVED]
        all_changed = [f.path for f in self.changed_files]

        env: dict[str, str] = {
            "PIPELINE_EXECUTION_ID": execution_id,
            "GITLAB_EVENT": self.x_gitlab_event,
            "GITLAB_EVENT_NAME": self.event_name,
            "GITLAB_OBJECT_KIND": self.object_kind,
            "GITLAB_EVENT_UUID": self.x_gitlab_event_uuid,
            "GITLAB_PROJECT_ID": str(self.project_id or ""),
            "GITLAB_PROJECT_NAME": self.project_name,
            "GITLAB_PROJECT_NAMESPACE": self.project_path_with_namespace,
            "GITLAB_PROJECT_WEB_URL": self.project_web_url,
            "GITLAB_SSH_URL": self.git_ssh_url,
            "GITLAB_HTTP_URL": self.git_http_url,
            "GITLAB_DEFAULT_BRANCH": self.default_branch,
            "GITLAB_REF": self.ref,
            "GITLAB_BRANCH": self.branch_name,
            "GITLAB_TAG": self.tag_name,
            "GITLAB_IS_TAG": "true" if self.is_tag else "false",
            "GITLAB_BEFORE_SHA": self.before_sha,
            "GITLAB_AFTER_SHA": self.after_sha,
            "GITLAB_CHECKOUT_SHA": self.checkout_sha,
            "GITLAB_COMMIT_SHA": self.checkout_sha or self.after_sha,
            "GITLAB_COMMIT_SHORT_SHA": (self.checkout_sha or self.after_sha)[:8],
            "GITLAB_COMMIT_MESSAGE": self.commit_message,
            "GITLAB_COMMIT_TITLE": self.commit_title,
            "GITLAB_TOTAL_COMMITS": str(self.total_commits_count),
            "GITLAB_USER_NAME": self.triggered_by_name,
            "GITLAB_USER_USERNAME": self.triggered_by_username,
            "GITLAB_USER_EMAIL": self.triggered_by_email,
            "GITLAB_USER_ID": str(self.triggered_by_id or ""),
            "GITLAB_CHANGED_FILES": ",".join(all_changed),
            "GITLAB_CHANGED_FILES_COUNT": str(len(all_changed)),
            "GITLAB_ADDED_FILES": ",".join(added_files),
            "GITLAB_MODIFIED_FILES": ",".join(modified_files),
            "GITLAB_REMOVED_FILES": ",".join(removed_files),
            # Standard CI_* aliases for compatibility with existing scripts
            "CI_COMMIT_REF_NAME": self.branch_name or self.tag_name,
            "CI_COMMIT_BRANCH": self.branch_name,
            "CI_COMMIT_TAG": self.tag_name,
            "CI_COMMIT_SHA": self.checkout_sha or self.after_sha,
            "CI_COMMIT_SHORT_SHA": (self.checkout_sha or self.after_sha)[:8],
            "CI_COMMIT_MESSAGE": self.commit_message,
            "CI_COMMIT_TITLE": self.commit_title,
            "CI_PROJECT_ID": str(self.project_id or ""),
            "CI_PROJECT_NAME": self.project_name,
            "CI_PROJECT_PATH": self.project_path_with_namespace,
            "CI_PROJECT_URL": self.project_web_url,
            "CI_DEFAULT_BRANCH": self.default_branch,
            "CI_PIPELINE_SOURCE": self.object_kind or "webhook",
            "GITLAB_USER_LOGIN": self.triggered_by_username,
        }

        if self.object_kind == "merge_request" or self.mr_iid is not None:
            env.update(
                {
                    "GITLAB_MR_ID": str(self.mr_id or ""),
                    "GITLAB_MR_IID": str(self.mr_iid or ""),
                    "GITLAB_MR_TITLE": self.mr_title,
                    "GITLAB_MR_DESCRIPTION": self.mr_description,
                    "GITLAB_MR_STATE": self.mr_state,
                    "GITLAB_MR_ACTION": self.mr_action,
                    "GITLAB_MR_MERGE_STATUS": self.mr_merge_status,
                    "GITLAB_MR_SOURCE_BRANCH": self.mr_source_branch,
                    "GITLAB_MR_TARGET_BRANCH": self.mr_target_branch,
                    "GITLAB_MR_URL": self.mr_url,
                    "GITLAB_MR_DRAFT": "true" if self.mr_draft else "false",
                    "GITLAB_MR_LABELS": ",".join(self.mr_labels),
                    "GITLAB_MR_ASSIGNEES": ",".join(self.mr_assignees),
                    "GITLAB_MR_REVIEWERS": ",".join(self.mr_reviewers),
                    "CI_MERGE_REQUEST_IID": str(self.mr_iid or ""),
                    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": self.mr_source_branch,
                    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": self.mr_target_branch,
                    "CI_MERGE_REQUEST_TITLE": self.mr_title,
                }
            )

        for key, value in self.extra_variables.items():
            if key not in env and value != "":
                env[key] = value

        return env


@dataclass(slots=True)
class PipelineStepResult:
    """Result of executing a single command step inside the cloned repository."""

    step_index: int
    name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    status: str


@dataclass(slots=True)
class LocalUserRecord:
    """Local dashboard user account persisted with salted scrypt password hash in SQLite."""

    username: str
    display_name: str
    email: str
    role: str
    password_hash: str
    is_active: bool
    created_at: str
    updated_at: str


@dataclass(slots=True)
class ExecutionRecord:
    """Full audit record persisted to the database for every webhook-triggered run."""

    id: str
    status: ExecutionStatus
    event_name: str
    object_kind: str
    project_name: str
    project_namespace: str
    git_ssh_url: str
    branch_name: str
    tag_name: str
    commit_sha: str
    commit_title: str
    commit_message: str
    triggered_by_name: str
    triggered_by_username: str
    triggered_by_email: str
    mr_iid: int | None
    mr_title: str
    mr_source_branch: str
    mr_target_branch: str
    changed_files: list[dict[str, str]]
    commits: list[dict[str, Any]]
    variables: dict[str, str]
    steps: list[dict[str, Any]]
    pipeline_config_source: str
    temp_workspace_path: str
    cleanup_verified: bool
    clone_duration_ms: int
    total_duration_ms: int
    error_message: str
    raw_payload: dict[str, Any]
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    rerun_of_id: str = ""

    @staticmethod
    def utc_now_iso() -> str:
        """Return an ISO-8601 UTC timestamp string."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
