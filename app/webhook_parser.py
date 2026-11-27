"""Comprehensive GitLab Webhook parser for push, tag, commit, and merge request events."""

from __future__ import annotations

from typing import Any

from app.models import ChangeType, ChangedFile, CommitDetail, GitLabContext

ZERO_SHA = "0" * 40


def _clean_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _clean_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_branch_and_tag(ref: str, object_kind: str) -> tuple[str, str, bool]:
    """Derive branch name, tag name, and tag flag from a Git ref string."""
    if ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
        return "", tag, True
    if ref.startswith("refs/heads/"):
        branch = ref.removeprefix("refs/heads/")
        return branch, "", False
    if object_kind == "tag_push":
        return "", ref, True
    return ref, "", False


def _flatten_scalar_variables(payload: dict[str, Any], prefix: str = "GITLAB_RAW") -> dict[str, str]:
    """Flatten top-level and nested scalar fields into uppercase environment-safe variable names."""
    flattened: dict[str, str] = {}
    ignored_top_keys = {"commits", "raw_payload"}

    def walk(node: Any, path_parts: list[str], depth: int) -> None:
        if depth > 2:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                if depth == 0 and key in ignored_top_keys:
                    continue
                safe_key = "".join(ch if ch.isalnum() else "_" for ch in str(key).upper()).strip("_")
                if not safe_key:
                    continue
                walk(val, [*path_parts, safe_key], depth + 1)
        elif isinstance(node, (str, int, float, bool)):
            var_name = f"{prefix}_{'_'.join(path_parts)}"
            if len(var_name) <= 80:
                flattened[var_name] = str(node)

    walk(payload, [], 0)
    return flattened


def parse_gitlab_webhook(
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> GitLabContext:
    """Extract all available metadata, commits, files, and variables from a GitLab webhook."""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    object_kind = _clean_str(payload.get("object_kind")).lower()
    event_name = _clean_str(payload.get("event_name")) or object_kind or "push"
    x_gitlab_event = norm_headers.get("x-gitlab-event", "") or _derive_event_header(object_kind, event_name)
    x_gitlab_event_uuid = norm_headers.get("x-gitlab-event-uuid", "")

    project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    repository = payload.get("repository") if isinstance(payload.get("repository"), dict) else {}
    user_obj = payload.get("user") if isinstance(payload.get("user"), dict) else {}

    project_id = _clean_int(payload.get("project_id") or project.get("id"))
    project_name = _clean_str(project.get("name") or repository.get("name") or "unknown-repository")
    project_namespace = _clean_str(
        project.get("path_with_namespace") or project.get("namespace") or project_name
    )
    project_web_url = _clean_str(project.get("web_url") or repository.get("homepage"))
    git_ssh_url = _clean_str(
        project.get("git_ssh_url") or repository.get("git_ssh_url") or project.get("ssh_url") or repository.get("url")
    )
    git_http_url = _clean_str(
        project.get("git_http_url") or repository.get("git_http_url") or project.get("http_url")
    )
    default_branch = _clean_str(project.get("default_branch") or "main")

    # Triggered by user (Push events have top-level user_*; MR events nest under payload["user"])
    triggered_by_name = _clean_str(payload.get("user_name") or user_obj.get("name"))
    triggered_by_username = _clean_str(payload.get("user_username") or user_obj.get("username"))
    triggered_by_email = _clean_str(payload.get("user_email") or user_obj.get("email"))
    triggered_by_id = _clean_int(payload.get("user_id") or user_obj.get("id"))
    triggered_by_avatar = _clean_str(payload.get("user_avatar") or user_obj.get("avatar_url"))

    ref = _clean_str(payload.get("ref"))
    branch_name, tag_name, is_tag = _extract_branch_and_tag(ref, object_kind)
    before_sha = _clean_str(payload.get("before"))
    after_sha = _clean_str(payload.get("after"))
    checkout_sha = _clean_str(payload.get("checkout_sha") or ("" if after_sha == ZERO_SHA else after_sha))
    total_commits_count = _clean_int(payload.get("total_commits_count")) or 0

    commits: list[CommitDetail] = []
    changed_files: list[ChangedFile] = []
    seen_file_keys: set[tuple[str, str]] = set()

    raw_commits = payload.get("commits")
    if isinstance(raw_commits, list):
        for raw_c in raw_commits:
            if not isinstance(raw_c, dict):
                continue
            sha = _clean_str(raw_c.get("id"))
            author = raw_c.get("author") if isinstance(raw_c.get("author"), dict) else {}
            message = _clean_str(raw_c.get("message"))
            title = _clean_str(raw_c.get("title")) or (message.splitlines()[0] if message else "")

            added = tuple(_clean_str(p) for p in raw_c.get("added", []) if p)
            modified = tuple(_clean_str(p) for p in raw_c.get("modified", []) if p)
            removed = tuple(_clean_str(p) for p in raw_c.get("removed", []) if p)

            commits.append(
                CommitDetail(
                    sha=sha,
                    short_sha=sha[:8],
                    title=title,
                    message=message,
                    timestamp=_clean_str(raw_c.get("timestamp")),
                    url=_clean_str(raw_c.get("url")),
                    author_name=_clean_str(author.get("name")),
                    author_email=_clean_str(author.get("email")),
                    added=added,
                    modified=modified,
                    removed=removed,
                )
            )

            for path in added:
                key = (path, ChangeType.ADDED.value)
                if key not in seen_file_keys:
                    seen_file_keys.add(key)
                    changed_files.append(ChangedFile(path=path, change_type=ChangeType.ADDED, commit_id=sha))
            for path in modified:
                key = (path, ChangeType.MODIFIED.value)
                if key not in seen_file_keys:
                    seen_file_keys.add(key)
                    changed_files.append(ChangedFile(path=path, change_type=ChangeType.MODIFIED, commit_id=sha))
            for path in removed:
                key = (path, ChangeType.REMOVED.value)
                if key not in seen_file_keys:
                    seen_file_keys.add(key)
                    changed_files.append(ChangedFile(path=path, change_type=ChangeType.REMOVED, commit_id=sha))

    # Fallback commit summary from top-level or latest commit
    commit_message = _clean_str(payload.get("message"))
    commit_title = ""
    if commits:
        latest_commit = commits[-1]
        if not commit_message:
            commit_message = latest_commit.message
        commit_title = latest_commit.title
        if not triggered_by_name and latest_commit.author_name:
            triggered_by_name = latest_commit.author_name
        if not triggered_by_email and latest_commit.author_email:
            triggered_by_email = latest_commit.author_email
        if not checkout_sha:
            checkout_sha = latest_commit.sha
    elif commit_message:
        commit_title = commit_message.splitlines()[0]

    # Merge Request Hook fields
    mr_attrs = payload.get("object_attributes") if isinstance(payload.get("object_attributes"), dict) else {}
    mr_id: int | None = None
    mr_iid: int | None = None
    mr_title = ""
    mr_description = ""
    mr_state = ""
    mr_action = ""
    mr_merge_status = ""
    mr_source_branch = ""
    mr_target_branch = ""
    mr_url = ""
    mr_draft = False
    mr_labels: list[str] = []
    mr_assignees: list[str] = []
    mr_reviewers: list[str] = []

    if object_kind == "merge_request" or "merge_request" in x_gitlab_event.lower():
        mr_id = _clean_int(mr_attrs.get("id"))
        mr_iid = _clean_int(mr_attrs.get("iid"))
        mr_title = _clean_str(mr_attrs.get("title"))
        mr_description = _clean_str(mr_attrs.get("description"))
        mr_state = _clean_str(mr_attrs.get("state"))
        mr_action = _clean_str(mr_attrs.get("action"))
        mr_merge_status = _clean_str(mr_attrs.get("merge_status"))
        mr_source_branch = _clean_str(mr_attrs.get("source_branch"))
        mr_target_branch = _clean_str(mr_attrs.get("target_branch"))
        mr_url = _clean_str(mr_attrs.get("url"))
        mr_draft = bool(mr_attrs.get("draft") or mr_attrs.get("work_in_progress"))

        if not branch_name:
            branch_name = mr_source_branch
        if not ref and branch_name:
            ref = f"refs/heads/{branch_name}"

        last_commit = mr_attrs.get("last_commit") if isinstance(mr_attrs.get("last_commit"), dict) else {}
        if last_commit:
            lc_sha = _clean_str(last_commit.get("id"))
            lc_msg = _clean_str(last_commit.get("message"))
            lc_title = _clean_str(last_commit.get("title")) or (lc_msg.splitlines()[0] if lc_msg else mr_title)
            lc_author = last_commit.get("author") if isinstance(last_commit.get("author"), dict) else {}
            if not checkout_sha:
                checkout_sha = lc_sha
            if not after_sha:
                after_sha = lc_sha
            if not commit_message:
                commit_message = lc_msg or mr_title
            if not commit_title:
                commit_title = lc_title
            if not commits and lc_sha:
                commits.append(
                    CommitDetail(
                        sha=lc_sha,
                        short_sha=lc_sha[:8],
                        title=lc_title,
                        message=lc_msg,
                        timestamp=_clean_str(last_commit.get("timestamp")),
                        url=_clean_str(last_commit.get("url")),
                        author_name=_clean_str(lc_author.get("name")),
                        author_email=_clean_str(lc_author.get("email")),
                    )
                )

        if not commit_title and mr_title:
            commit_title = mr_title

        raw_labels = payload.get("labels") or mr_attrs.get("labels") or []
        if isinstance(raw_labels, list):
            mr_labels = [_clean_str(lbl.get("title") if isinstance(lbl, dict) else lbl) for lbl in raw_labels if lbl]

        for field_name, target_list in (("assignees", mr_assignees), ("reviewers", mr_reviewers)):
            people = payload.get(field_name) or []
            if isinstance(people, list):
                for person in people:
                    if isinstance(person, dict):
                        target_list.append(_clean_str(person.get("username") or person.get("name")))

    # Direct single-commit / note / custom commit event fallback
    if not commit_title and mr_title:
        commit_title = mr_title
    if not commit_title and tag_name:
        commit_title = f"Tag {tag_name}"
    if not commit_title and branch_name:
        commit_title = f"Event on {branch_name}"

    extra_variables = _flatten_scalar_variables(payload)

    return GitLabContext(
        event_name=event_name,
        object_kind=object_kind or "push",
        x_gitlab_event=x_gitlab_event,
        x_gitlab_event_uuid=x_gitlab_event_uuid,
        project_id=project_id,
        project_name=project_name,
        project_path_with_namespace=project_namespace,
        project_web_url=project_web_url,
        git_ssh_url=git_ssh_url,
        git_http_url=git_http_url,
        default_branch=default_branch,
        ref=ref,
        branch_name=branch_name,
        tag_name=tag_name,
        is_tag=is_tag,
        before_sha=before_sha,
        after_sha=after_sha,
        checkout_sha=checkout_sha,
        commit_message=commit_message,
        commit_title=commit_title,
        total_commits_count=total_commits_count or len(commits),
        triggered_by_name=triggered_by_name or "Unknown",
        triggered_by_username=triggered_by_username,
        triggered_by_email=triggered_by_email,
        triggered_by_id=triggered_by_id,
        triggered_by_avatar=triggered_by_avatar,
        mr_id=mr_id,
        mr_iid=mr_iid,
        mr_title=mr_title,
        mr_description=mr_description,
        mr_state=mr_state,
        mr_action=mr_action,
        mr_merge_status=mr_merge_status,
        mr_source_branch=mr_source_branch,
        mr_target_branch=mr_target_branch,
        mr_url=mr_url,
        mr_draft=mr_draft,
        mr_labels=mr_labels,
        mr_assignees=mr_assignees,
        mr_reviewers=mr_reviewers,
        commits=commits,
        changed_files=changed_files,
        extra_variables=extra_variables,
    )


def _derive_event_header(object_kind: str, event_name: str) -> str:
    mapping = {
        "push": "Push Hook",
        "tag_push": "Tag Push Hook",
        "merge_request": "Merge Request Hook",
        "system_hook": "System Hook",
    }
    return mapping.get(object_kind, event_name or "Push Hook")
