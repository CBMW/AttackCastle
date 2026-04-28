from __future__ import annotations

from typing import Any

from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.gui.models import RunSnapshot


class RunSnapshotUpdater:
    """Applies live worker events to GUI run snapshots."""

    def refresh_issue_state(self, snapshot: RunSnapshot) -> None:
        issues = build_execution_issues(snapshot)
        issue_summary = summarize_execution_issues(snapshot, issues)
        snapshot.execution_issues = issues
        snapshot.execution_issues_summary = issue_summary
        snapshot.completeness_status = str(issue_summary.get("completeness_status") or "healthy")

    def append_unique(self, rows: list[dict[str, Any]], row: dict[str, Any], key: str) -> None:
        value = str(row.get(key) or "")
        if not value:
            return
        for idx, existing in enumerate(rows):
            if str(existing.get(key) or "") == value:
                rows[idx] = row
                return
        rows.append(row)

    @staticmethod
    def task_update_value_present(value: Any) -> bool:
        return value is not None and value != ""

    def apply_task_event(self, snapshot: RunSnapshot, event_name: str, payload: dict[str, Any]) -> None:
        task_key = str(payload.get("task") or "")
        if not task_key:
            return
        detail = {
            key: value
            for key, value in {
                "reason": payload.get("reason"),
                "attempt": payload.get("attempt"),
                "error": payload.get("error"),
            }.items()
            if self.task_update_value_present(value)
        }
        row = {
            "key": task_key,
            "label": payload.get("label") or task_key,
            "status": payload.get("status") or event_name.replace("task.", ""),
            "started_at": payload.get("started_at") or "",
            "ended_at": payload.get("ended_at") or "",
        }
        if detail:
            row["detail"] = detail
        for idx, existing in enumerate(snapshot.tasks):
            if str(existing.get("key") or "") == task_key:
                merged = dict(existing)
                if detail:
                    merged_detail = dict(existing.get("detail") or {})
                    merged_detail.update(detail)
                    merged["detail"] = merged_detail
                merged.update({k: v for k, v in row.items() if self.task_update_value_present(v)})
                snapshot.tasks[idx] = merged
                break
        else:
            snapshot.tasks.append(row)
        snapshot.current_task = str(payload.get("label") or task_key)
        terminal = {"completed", "skipped", "failed", "blocked", "cancelled"}
        snapshot.completed_tasks = len(
            [item for item in snapshot.tasks if str(item.get("status") or "") in terminal]
        )
        status = str(payload.get("status") or row["status"])
        if status in {"failed", "blocked"}:
            snapshot.state = "failed"
        elif status == "cancelled":
            snapshot.state = "cancelled"
        else:
            snapshot.state = "running"
        self.refresh_issue_state(snapshot)

    def apply_entity_event(self, snapshot: RunSnapshot, payload: dict[str, Any]) -> None:
        entity_type = str(payload.get("entity_type") or "")
        entity = payload.get("entity", {})
        if not isinstance(entity, dict):
            return
        key_by_type = {
            "asset": ("assets", "asset_id"),
            "service": ("services", "service_id"),
            "web_app": ("web_apps", "webapp_id"),
            "technology": ("technologies", "tech_id"),
            "endpoint": ("endpoints", "endpoint_id"),
            "parameter": ("parameters", "parameter_id"),
            "form": ("forms", "form_id"),
            "login_surface": ("login_surfaces", "login_surface_id"),
            "replay_request": ("replay_requests", "replay_request_id"),
            "surface_signal": ("surface_signals", "surface_signal_id"),
            "attack_path": ("attack_paths", "attack_path_id"),
            "investigation_step": ("investigation_steps", "investigation_step_id"),
            "playbook_execution": ("playbook_executions", "playbook_execution_id"),
            "coverage_decision": ("coverage_decisions", "coverage_decision_id"),
            "validation_result": ("validation_results", "validation_result_id"),
            "coverage_gap": ("coverage_gaps", "coverage_gap_id"),
        }
        if entity_type in key_by_type:
            rows_name, key = key_by_type[entity_type]
            self.append_unique(getattr(snapshot, rows_name), entity, key)
            return
        if entity_type == "evidence":
            self.append_unique(snapshot.evidence, entity, "evidence_id")
            artifact_path = str(entity.get("artifact_path") or "")
            if artifact_path:
                self.append_unique(
                    snapshot.artifacts,
                    {
                        "path": artifact_path,
                        "kind": entity.get("kind", ""),
                        "source_tool": entity.get("source_tool", ""),
                        "caption": entity.get("snippet", ""),
                    },
                    "path",
                )
            if str(entity.get("kind")) == "web_screenshot" and artifact_path:
                self.append_unique(
                    snapshot.screenshots,
                    {
                        "path": artifact_path,
                        "caption": entity.get("snippet", ""),
                        "source_tool": entity.get("source_tool", ""),
                    },
                    "path",
                )

    def apply_site_map_event(self, snapshot: RunSnapshot, payload: dict[str, Any]) -> None:
        source_map = {
            "urls": "web.discovery.urls",
            "js_endpoints": "web.discovery.js_endpoints",
            "graphql_endpoints": "web.discovery.graphql_endpoints",
            "source_maps": "web.discovery.source_maps",
        }
        entity_id = str(payload.get("webapp_id") or "")
        for field, source in source_map.items():
            values = payload.get(field, [])
            if not isinstance(values, list):
                continue
            for item in values:
                url = str(item).strip()
                if not url:
                    continue
                self.append_unique(
                    snapshot.site_map,
                    {"source": source, "url": url, "entity_id": entity_id},
                    "url",
                )
