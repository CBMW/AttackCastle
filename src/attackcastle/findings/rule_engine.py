from __future__ import annotations

import hashlib
import re
from typing import Any

from attackcastle.core.enums import Severity
from attackcastle.core.models import Finding, RunData, new_id
from attackcastle.findings.rule_context import RuleMatchContext, build_rule_contexts
from attackcastle.findings.rule_schema import normalize_definition, normalize_trigger


class DetectionRuleEngine:
    def __init__(self, definitions: list[dict[str, Any]]) -> None:
        self.definitions = [normalize_definition(item) for item in definitions]

    def generate(self, run_data: RunData) -> list[Finding]:
        contexts = build_rule_contexts(run_data)
        generated: list[Finding] = []
        dedupe = {str(finding.fingerprint or "") for finding in run_data.findings if finding.fingerprint}
        telemetry = dict(run_data.facts.get("findings.rule_telemetry", {})) if isinstance(run_data.facts.get("findings.rule_telemetry"), dict) else {}
        telemetry.setdefault("confirmed", 0)
        telemetry.setdefault("skipped_disabled", 0)

        for definition in self.definitions:
            if not definition.get("enabled", True):
                telemetry["skipped_disabled"] += 1
                continue
            detection = definition.get("detection")
            if not isinstance(detection, dict):
                continue
            triggers = [
                normalize_trigger(trigger)
                for trigger in detection.get("triggers", [])
                if isinstance(trigger, dict) and trigger.get("enabled", True)
            ]
            if not triggers:
                continue
            logic = str(detection.get("logic") or "any").lower()
            for context in contexts:
                matched, explanations = self._evaluate_triggers(triggers, logic, context)
                if not matched:
                    continue
                fingerprint = self._fingerprint(definition, context, explanations)
                if fingerprint in dedupe:
                    continue
                dedupe.add(fingerprint)
                finding = self._build_finding(definition, context, explanations, fingerprint)
                generated.append(finding)
                telemetry["confirmed"] += 1

        run_data.findings.extend(generated)
        run_data.facts["findings.rule_telemetry"] = telemetry
        return generated

    def _evaluate_triggers(
        self,
        triggers: list[dict[str, Any]],
        logic: str,
        context: RuleMatchContext,
    ) -> tuple[bool, list[dict[str, Any]]]:
        checks: list[tuple[bool, dict[str, Any]]] = []
        for trigger in triggers:
            if not self._tool_matches(str(trigger.get("tool") or ""), context):
                checks.append((False, self._explain(trigger, context, False, "tool did not match")))
                continue
            result, why = self._match_trigger(trigger, context)
            checks.append((result, self._explain(trigger, context, result, why)))
        if not checks:
            return False, []
        if logic == "all":
            return all(result for result, _explanation in checks), [explanation for result, explanation in checks if result]
        return any(result for result, _explanation in checks), [explanation for result, explanation in checks if result]

    def _tool_matches(self, tool: str, context: RuleMatchContext) -> bool:
        normalized = tool.strip().lower()
        return normalized in {"*", "any"} or normalized == context.tool.strip().lower()

    def _match_trigger(self, trigger: dict[str, Any], context: RuleMatchContext) -> tuple[bool, str]:
        operator = str(trigger.get("operator") or "").lower()
        scope = str(trigger.get("scope") or "")
        value = trigger.get("value")

        if operator in {"output contains", "output does not contain", "output matches regex"}:
            output = self._scoped_output(scope, context)
            needle = str(value or "")
            if operator == "output contains":
                matched = needle.lower() in output.lower()
                return matched, f"{scope} contains {needle!r}" if matched else f"{scope} did not contain {needle!r}"
            if operator == "output does not contain":
                matched = needle.lower() not in output.lower()
                return matched, f"{scope} does not contain {needle!r}" if matched else f"{scope} contained {needle!r}"
            try:
                matched = re.search(needle, output, re.IGNORECASE | re.MULTILINE) is not None
            except re.error as exc:
                return False, f"invalid regex: {exc}"
            return matched, f"{scope} matched regex {needle!r}" if matched else f"{scope} did not match regex {needle!r}"

        if operator in {"header exists", "header missing", "header equals"}:
            header_name, expected = self._split_header_value(value)
            normalized_name = header_name.lower()
            exists = normalized_name in context.headers
            if operator == "header exists":
                return exists, f"header {header_name} exists" if exists else f"header {header_name} missing"
            if operator == "header missing":
                return not exists, f"header {header_name} missing" if not exists else f"header {header_name} exists"
            actual = context.headers.get(normalized_name, "")
            matched = exists and actual.lower() == expected.lower()
            return matched, f"header {header_name} equals {expected!r}" if matched else f"header {header_name} was {actual!r}"

        if operator == "status code equals":
            try:
                expected_status = int(value)
            except (TypeError, ValueError):
                return False, "status value is not an integer"
            matched = context.status_code == expected_status
            return matched, f"status code equals {expected_status}" if matched else f"status code was {context.status_code}"

        if operator == "status code in list":
            values = [int(item) for item in value] if isinstance(value, list) else []
            matched = context.status_code in values
            return matched, f"status code {context.status_code} is in list" if matched else f"status code {context.status_code} not in list"

        if operator == "exit code equals":
            try:
                expected_exit = int(value)
            except (TypeError, ValueError):
                return False, "exit code value is not an integer"
            matched = context.exit_code == expected_exit
            return matched, f"exit code equals {expected_exit}" if matched else f"exit code was {context.exit_code}"

        if operator == "tool succeeded":
            matched = str(context.status).lower() in {"completed", "success", "succeeded"} and context.exit_code in {0, None}
            return matched, "tool succeeded" if matched else f"tool status was {context.status}"

        if operator == "tool failed":
            matched = str(context.status).lower() in {"failed", "cancelled", "interrupted", "timeout"} or (
                context.exit_code is not None and context.exit_code != 0
            )
            return matched, "tool failed" if matched else f"tool status was {context.status}"

        if operator == "timeout occurred":
            matched = bool(context.timed_out) or str(context.parsed_fields.get("termination_reason") or "").lower() == "timeout"
            return matched, "timeout occurred" if matched else "timeout did not occur"

        return False, f"unsupported operator {operator}"

    def _scoped_output(self, scope: str, context: RuleMatchContext) -> str:
        if scope == "stdout":
            return context.stdout
        if scope == "stderr":
            return context.stderr
        return context.combined_output

    def _split_header_value(self, value: Any) -> tuple[str, str]:
        if isinstance(value, dict):
            return str(value.get("name") or value.get("header") or "").strip(), str(value.get("value") or "")
        text = str(value or "")
        if "=" in text:
            name, expected = text.split("=", 1)
            return name.strip(), expected.strip()
        return text.strip(), ""

    def _explain(
        self,
        trigger: dict[str, Any],
        context: RuleMatchContext,
        matched: bool,
        why: str,
    ) -> dict[str, Any]:
        artifact_paths = context.artifact_paths
        return {
            "trigger_id": trigger.get("id"),
            "operator": trigger.get("operator"),
            "scope": trigger.get("scope"),
            "value": trigger.get("value"),
            "matched": matched,
            "why": why,
            "source_tool": context.tool,
            "source_task_id": context.source_task_id,
            "source_execution_id": context.source_execution_id,
            "artifact_paths": artifact_paths,
            "raw_artifact_path": artifact_paths[0] if artifact_paths else None,
            "parsed_fields": dict(context.parsed_fields),
        }

    def _build_finding(
        self,
        definition: dict[str, Any],
        context: RuleMatchContext,
        explanations: list[dict[str, Any]],
        fingerprint: str,
    ) -> Finding:
        severity = self._severity_from_text(str(definition.get("severity") or "info"))
        return Finding(
            finding_id=new_id("finding"),
            template_id=str(definition["id"]),
            title=str(definition.get("title") or definition["id"]),
            severity=severity,
            category=str(definition.get("category") or "General"),
            description=str(definition.get("description") or ""),
            impact=str(definition.get("impact") or ""),
            likelihood=str(definition.get("likelihood") or ""),
            recommendations=list(definition.get("recommendations", [])),
            references=list(definition.get("references", [])),
            tags=list(definition.get("tags", [])),
            affected_entities=[{"entity_type": context.entity_type, "entity_id": context.entity_id}],
            evidence_ids=list(context.evidence_ids),
            plextrac=dict(definition.get("plextrac", {})),
            fingerprint=fingerprint,
            status="confirmed",
            evidence_quality_score=1.0 if context.evidence_ids or context.artifact_paths else 0.5,
            corroboration={
                "matched_triggers": explanations,
                "source_tool": context.tool,
                "source_task_id": context.source_task_id,
                "source_execution_id": context.source_execution_id,
                "artifact_paths": context.artifact_paths,
                "raw_artifact_path": context.artifact_paths[0] if context.artifact_paths else None,
                "parsed_fields": dict(context.parsed_fields),
            },
            quality_notes=[],
        )

    def _severity_from_text(self, value: str) -> Severity:
        try:
            return Severity(value.lower())
        except ValueError:
            return Severity.INFO

    def _fingerprint(
        self,
        definition: dict[str, Any],
        context: RuleMatchContext,
        explanations: list[dict[str, Any]],
    ) -> str:
        trigger_ids = ",".join(sorted(str(item.get("trigger_id") or "") for item in explanations))
        artifact = context.artifact_paths[0] if context.artifact_paths else ""
        material = "|".join(
            [
                str(definition.get("id") or ""),
                context.entity_type,
                context.entity_id,
                trigger_ids,
                str(context.source_execution_id or context.source_task_id or ""),
                artifact,
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

