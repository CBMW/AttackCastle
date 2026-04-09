from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any


ISSUE_STATUS_ORDER = {
    "failed": 0,
    "blocked": 1,
    "cancelled": 2,
    "skipped": 3,
    "warning": 4,
    "coverage-gap": 5,
}
TASK_ISSUE_STATUSES = {"failed", "blocked", "skipped", "cancelled"}
TOOL_ISSUE_STATUSES = {"failed", "blocked", "skipped", "cancelled"}
COVERAGE_GAP_FACT_KEYS = ("web_probe.coverage_gaps", "web_discovery.coverage_gaps", "active_validation.coverage_gaps")
WARNING_KEYWORDS = (
    "not found",
    "could not",
    "unable to",
    "coverage",
    "blind spot",
    "gap",
    "stage budget",
    "timeout",
    "rate limit",
    "downgrade",
    "canary failure",
    "generic response",
)


def _sha1_token(*parts: object) -> str:
    digest = hashlib.sha1("|".join(str(part or "") for part in parts).encode("utf-8")).hexdigest()  # noqa: S324
    return digest[:12]


def _coerce_mapping(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if item is None:
        return {}
    payload: dict[str, Any] = {}
    for key in dir(item):
        if key.startswith("_"):
            continue
        try:
            value = getattr(item, key)
        except Exception:
            continue
        if callable(value):
            continue
        payload[key] = value
    return payload


def _get_attr(source: Any, key: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _metadata_state(source: Any) -> str:
    metadata = _get_attr(source, "metadata")
    if metadata is not None:
        state = _get_attr(metadata, "state")
        if hasattr(state, "value"):
            return str(state.value or "")
        if state is not None:
            return str(state or "")
    state = _get_attr(source, "state")
    return str(state or "")


def _facts(source: Any) -> dict[str, Any]:
    value = _get_attr(source, "facts", {})
    return dict(value) if isinstance(value, dict) else {}


def _sequence(source: Any, key: str) -> list[Any]:
    value = _get_attr(source, key, [])
    return list(value) if isinstance(value, list) else []


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _looks_notable_warning(message: str) -> bool:
    text = message.lower()
    return any(keyword in text for keyword in WARNING_KEYWORDS)


def _task_issue_fields(task: dict[str, Any]) -> dict[str, Any] | None:
    status = str(task.get("status") or "").lower()
    if status not in TASK_ISSUE_STATUSES:
        return None
    detail = task.get("detail", {}) if isinstance(task.get("detail"), dict) else {}
    task_key = str(task.get("key") or "")
    label = str(task.get("label") or task_key or "Workflow task")
    capability = str(detail.get("capability") or "")
    stage = str(detail.get("stage") or "")
    message = (
        str(detail.get("reason") or "")
        or str(task.get("error") or "")
        or str(detail.get("decision_reason") or "")
        or f"Task ended in {status} state."
    )
    if status == "skipped":
        impact = "This stage was skipped, so related assessment coverage is incomplete."
        suggested_action = "Review policy decisions and prerequisite data, then rerun if this stage should execute."
    elif status == "cancelled":
        impact = "This stage was cancelled before completion, so related coverage may be missing."
        suggested_action = "Resume or rerun the assessment if this stage is required for completeness."
    else:
        impact = "This stage did not complete successfully, so related assessment coverage may be missing."
        suggested_action = "Review the related task and tool logs, fix the failure condition, and rerun the affected stage."
    return {
        "kind": "task",
        "label": label,
        "status": status,
        "message": _normalize_text(message),
        "impact": impact,
        "suggested_action": suggested_action,
        "stage": stage or None,
        "task_key": task_key or None,
        "tool_name": capability or None,
        "exit_code": None,
        "url": None,
        "source": f"task:{task_key or label}",
    }


def _tool_issue_fields(execution: dict[str, Any]) -> dict[str, Any] | None:
    status = str(execution.get("status") or "").lower()
    if status not in TOOL_ISSUE_STATUSES:
        return None
    tool_name = str(execution.get("tool_name") or "tool")
    exit_code = execution.get("exit_code")
    error_message = str(execution.get("error_message") or "")
    if exit_code is not None and error_message:
        message = f"{error_message} (exit code {exit_code})"
    elif exit_code is not None:
        message = f"Exited with code {exit_code}."
    else:
        message = error_message or f"Execution ended in {status} state."
    if status == "skipped":
        impact = "This tool did not run, so the corresponding capability may not be represented in the report."
    elif status == "cancelled":
        impact = "This tool execution was cancelled before completion."
    else:
        impact = "This tool execution failed, so the corresponding capability may be incomplete."
    return {
        "kind": "tool",
        "label": f"{tool_name} execution",
        "status": status,
        "message": _normalize_text(message),
        "impact": impact,
        "suggested_action": "Review stderr, raw artifacts, and tool configuration, then retry the affected execution.",
        "stage": None,
        "task_key": None,
        "tool_name": tool_name,
        "exit_code": exit_code,
        "url": None,
        "source": f"tool:{tool_name}:{execution.get('execution_id') or tool_name}",
    }


def _run_error_fields(message: str) -> dict[str, Any]:
    task_key = None
    normalized = _normalize_text(message)
    trimmed = normalized
    if ": " in normalized:
        prefix, suffix = normalized.split(": ", 1)
        if prefix and suffix:
            task_key = prefix
            trimmed = suffix
    return {
        "kind": "run_error",
        "label": "Run error" if not task_key else f"{task_key} error",
        "status": "failed",
        "message": trimmed,
        "impact": "Assessment execution encountered an error that may have reduced completeness or reliability.",
        "suggested_action": "Review the related task and tool logs, then rerun the affected stage or full scan as needed.",
        "stage": None,
        "task_key": task_key,
        "tool_name": None,
        "exit_code": None,
        "url": None,
        "source": f"run-error:{normalized}",
    }


def _warning_fields(message: str) -> dict[str, Any] | None:
    normalized = _normalize_text(message)
    if not normalized or not _looks_notable_warning(normalized):
        return None
    return {
        "kind": "warning",
        "label": "Coverage warning",
        "status": "warning",
        "message": normalized,
        "impact": "A warning indicates the assessment may have reduced confidence or incomplete coverage in one area.",
        "suggested_action": "Review the warning context and rerun the affected capability if coverage is required.",
        "stage": None,
        "task_key": None,
        "tool_name": None,
        "exit_code": None,
        "url": None,
        "source": f"warning:{normalized}",
    }


def _coverage_gap_fields(source_name: str, item: dict[str, Any]) -> dict[str, Any]:
    url = str(item.get("url") or "").strip() or None
    label = str(item.get("label") or item.get("title") or item.get("reason") or source_name)
    status = str(item.get("mode") or "coverage-gap").strip().lower() or "coverage-gap"
    return {
        "kind": "coverage_gap",
        "label": label,
        "status": status,
        "message": _normalize_text(item.get("reason") or item.get("message") or "Coverage gap recorded."),
        "impact": str(item.get("impact") or "Assessment coverage is incomplete for this area."),
        "suggested_action": str(
            item.get("suggested_action") or "Review the gap and rerun the affected discovery path if needed."
        ),
        "stage": None,
        "task_key": None,
        "tool_name": None,
        "exit_code": None,
        "url": url,
        "source": f"coverage:{source_name}:{url or label}",
    }


def _run_state_issue(state: str) -> dict[str, Any] | None:
    normalized = state.lower()
    if normalized == "failed":
        return {
            "kind": "run_state",
            "label": "Run failed",
            "status": "failed",
            "message": "The scan run ended in a failed state before all intended work completed.",
            "impact": "Assessment completeness is reduced because the run did not finish cleanly.",
            "suggested_action": "Review the issue list below, fix the blocking condition, and rerun the assessment.",
            "stage": None,
            "task_key": None,
            "tool_name": None,
            "exit_code": None,
            "url": None,
            "source": "run-state:failed",
        }
    if normalized == "cancelled":
        return {
            "kind": "run_state",
            "label": "Run cancelled",
            "status": "cancelled",
            "message": "The scan run was cancelled before all intended work completed.",
            "impact": "Assessment completeness is reduced because the run stopped early.",
            "suggested_action": "Resume or rerun the assessment if full coverage is still required.",
            "stage": None,
            "task_key": None,
            "tool_name": None,
            "exit_code": None,
            "url": None,
            "source": "run-state:cancelled",
        }
    return None


def _issue_signature(issue: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(issue.get("kind") or ""),
        str(issue.get("status") or ""),
        str(issue.get("task_key") or ""),
        str(issue.get("tool_name") or ""),
        str(issue.get("url") or ""),
        _normalize_text(issue.get("message") or ""),
    )


def build_execution_issues(source: Any) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()

    def add_issue(issue: dict[str, Any] | None) -> None:
        if issue is None:
            return
        signature = _issue_signature(issue)
        if signature in seen:
            return
        seen.add(signature)
        issue_id = _sha1_token(*signature)
        normalized = dict(issue)
        normalized["issue_id"] = f"issue_{issue_id}"
        issues.append(normalized)

    add_issue(_run_state_issue(_metadata_state(source)))

    for task in _sequence(source, "task_states"):
        add_issue(_task_issue_fields(_coerce_mapping(task)))

    for execution in _sequence(source, "tool_executions"):
        add_issue(_tool_issue_fields(_coerce_mapping(execution)))

    for message in _sequence(source, "errors"):
        add_issue(_run_error_fields(str(message)))

    for message in _sequence(source, "warnings"):
        add_issue(_warning_fields(str(message)))

    facts = _facts(source)
    for fact_key in COVERAGE_GAP_FACT_KEYS:
        items = facts.get(fact_key, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                add_issue(_coverage_gap_fields(fact_key, item))

    issues.sort(
        key=lambda issue: (
            ISSUE_STATUS_ORDER.get(str(issue.get("status") or "").lower(), 99),
            str(issue.get("kind") or ""),
            str(issue.get("label") or ""),
        )
    )
    return issues


def summarize_execution_issues(source: Any, issues: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    normalized_issues = issues if issues is not None else build_execution_issues(source)
    state = _metadata_state(source).lower()
    counts_by_kind = Counter(str(issue.get("kind") or "unknown") for issue in normalized_issues)
    counts_by_status = Counter(str(issue.get("status") or "unknown") for issue in normalized_issues)
    total_count = len(normalized_issues)
    if state in {"failed", "cancelled"}:
        completeness_status = "failed"
    elif total_count > 0:
        completeness_status = "partial"
    else:
        completeness_status = "healthy"
    return {
        "total_count": total_count,
        "counts_by_kind": dict(counts_by_kind),
        "counts_by_status": dict(counts_by_status),
        "blocking_count": sum(
            counts_by_status.get(name, 0) for name in ("failed", "blocked", "cancelled")
        ),
        "coverage_count": counts_by_kind.get("coverage_gap", 0),
        "warning_count": counts_by_status.get("warning", 0),
        "completeness_status": completeness_status,
        "headline": (
            "No execution issues affecting completeness."
            if total_count == 0
            else f"{total_count} issue(s) affecting completeness."
        ),
        "state": state,
    }
