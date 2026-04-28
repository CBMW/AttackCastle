from __future__ import annotations

from attackcastle.analysis import refresh_autonomy_state
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData
from attackcastle.core.runtime_events import emit_runtime_event
from attackcastle.normalization.mapper import merge_adapter_result


class TaskResultRecorder:
    """Merges adapter output and emits the runtime events derived from it."""

    def record_result(self, context: AdapterContext, run_data: RunData, result: AdapterResult) -> str | None:
        merge_adapter_result(run_data, result)
        self.emit_adapter_result_runtime_events(context, result)
        refresh_autonomy_state(run_data, context.config)
        return self.adapter_result_failure_message(result)

    @staticmethod
    def emit_adapter_result_runtime_events(context: AdapterContext, result: AdapterResult) -> None:
        entity_groups = (
            ("asset", result.assets),
            ("service", result.services),
            ("web_app", result.web_apps),
            ("technology", result.technologies),
            ("endpoint", result.endpoints),
            ("parameter", result.parameters),
            ("form", result.forms),
            ("login_surface", result.login_surfaces),
            ("replay_request", result.replay_requests),
            ("surface_signal", result.surface_signals),
            ("investigation_step", result.investigation_steps),
            ("playbook_execution", result.playbook_executions),
            ("coverage_decision", result.coverage_decisions),
            ("validation_result", result.validation_results),
            ("hypothesis", result.hypotheses),
            ("validation_task", result.validation_tasks),
            ("coverage_gap", result.coverage_gaps),
            ("evidence", result.evidence),
        )
        for entity_type, rows in entity_groups:
            for row in rows:
                emit_runtime_event(
                    context,
                    "entity.upserted",
                    {
                        "entity_type": entity_type,
                        "action": "upsert",
                        "source": getattr(row, "source_tool", None),
                        "entity": row,
                    },
                )

        for artifact in result.evidence_artifacts:
            emit_runtime_event(
                context,
                "artifact.available",
                {
                    "artifact_path": artifact.path,
                    "kind": artifact.kind,
                    "source_tool": artifact.source_tool,
                    "caption": artifact.caption or "",
                    "artifact_id": artifact.artifact_id,
                    "source_task_id": artifact.source_task_id,
                    "source_execution_id": artifact.source_execution_id,
                },
            )

        for task_result in result.task_results:
            emit_runtime_event(context, "task_result.recorded", {"result": task_result})

        for execution in result.tool_executions:
            emit_runtime_event(context, "tool_execution.recorded", {"execution": execution})

    @staticmethod
    def adapter_result_has_payload(result: AdapterResult) -> bool:
        payload_groups = (
            result.assets,
            result.services,
            result.web_apps,
            result.technologies,
            result.tls_assets,
            result.endpoints,
            result.parameters,
            result.forms,
            result.login_surfaces,
            result.replay_requests,
            result.surface_signals,
            result.investigation_steps,
            result.response_deltas,
            result.authorization_comparisons,
            result.proof_outcomes,
            result.playbook_executions,
            result.coverage_decisions,
            result.validation_results,
            result.hypotheses,
            result.validation_tasks,
            result.coverage_gaps,
            result.observations,
            result.evidence,
            result.evidence_artifacts,
            result.normalized_entities,
        )
        return any(bool(group) for group in payload_groups)

    @classmethod
    def adapter_result_failure_message(cls, result: AdapterResult) -> str | None:
        explicit_errors = [str(item).strip() for item in result.errors if str(item).strip()]
        if explicit_errors:
            return "; ".join(explicit_errors)
        statuses: list[tuple[str, str | None, str | None]] = []
        for execution in result.tool_executions:
            statuses.append(
                (
                    str(getattr(execution, "status", "") or "").lower(),
                    getattr(execution, "termination_reason", None),
                    getattr(execution, "termination_detail", None) or getattr(execution, "error_message", None),
                )
            )
        for task_result in result.task_results:
            statuses.append(
                (
                    str(getattr(task_result, "status", "") or "").lower(),
                    getattr(task_result, "termination_reason", None),
                    getattr(task_result, "termination_detail", None),
                )
            )
        failure_statuses = {"failed", "cancelled", "interrupted", "timeout"}
        failure_reasons = {"timeout", "nonzero_exit", "spawn_failure", "interrupted", "unknown_runner_failure"}
        meaningful_statuses = [
            (status, reason, detail)
            for status, reason, detail in statuses
            if status != "skipped" and str(reason or "").lower() != "missing_dependency"
        ]
        failures = [
            (status, reason, detail)
            for status, reason, detail in meaningful_statuses
            if status in failure_statuses or str(reason or "").lower() in failure_reasons
        ]
        if not failures or len(failures) != len(meaningful_statuses) or cls.adapter_result_has_payload(result):
            return None
        details = [str(detail).strip() for _status, _reason, detail in failures if str(detail or "").strip()]
        if details:
            return "; ".join(details[:3])
        return "all tool executions for the task failed without producing parsed data"
