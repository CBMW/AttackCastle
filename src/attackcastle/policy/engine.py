from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from attackcastle.analysis import approval_class_for_task, approval_scope_key
from attackcastle.core.models import RunData
from attackcastle.orchestration.task_graph import TaskDefinition


@dataclass
class PolicyDecision:
    allow: bool
    action: str = "allow"
    reason: str = "allowed_by_policy"
    rule_id: str | None = None


def _read_policy_file(path_value: str | None) -> list[dict[str, Any]]:
    if not path_value:
        return []
    path = Path(path_value).expanduser().resolve()
    if not path.exists():
        return []
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return []
    return [item for item in rules if isinstance(item, dict)]


def _task_matcher(rule: dict[str, Any], task: TaskDefinition, profile_name: str) -> bool:
    match = rule.get("match", {})
    if not isinstance(match, dict):
        return True

    key = match.get("task_key")
    if key and str(key) != task.key:
        return False

    capability = match.get("capability")
    if capability and str(capability) != task.capability:
        return False

    stage = match.get("stage")
    if stage and str(stage) != task.stage:
        return False

    profile = match.get("profile")
    if profile and str(profile) != profile_name:
        return False
    return True


def _facts_matcher(rule: dict[str, Any], run_data: RunData) -> bool:
    when = rule.get("when", {})
    if not isinstance(when, dict):
        return True

    min_assets = when.get("min_assets")
    if min_assets is not None and len(run_data.assets) < int(min_assets):
        return False

    min_services = when.get("min_services")
    if min_services is not None and len(run_data.services) < int(min_services):
        return False

    max_services = when.get("max_services")
    if max_services is not None and len(run_data.services) > int(max_services):
        return False

    min_findings = when.get("min_findings")
    if min_findings is not None and len(run_data.findings) < int(min_findings):
        return False

    requires_fact = when.get("requires_fact")
    if isinstance(requires_fact, str):
        fact_value = run_data.facts.get(requires_fact)
        if not fact_value:
            return False
    elif isinstance(requires_fact, list):
        for key in requires_fact:
            if not run_data.facts.get(str(key)):
                return False

    tech_contains = when.get("tech_contains")
    if tech_contains:
        detected = {
            str(tech.name).lower() for tech in run_data.technologies if tech.name
        }
        if isinstance(tech_contains, str):
            if str(tech_contains).lower() not in detected:
                return False
        elif isinstance(tech_contains, list):
            normalized = {str(item).lower() for item in tech_contains}
            if not detected.intersection(normalized):
                return False

    return True


class PolicyEngine:
    def __init__(
        self,
        profile_name: str,
        policy_config: dict[str, Any],
        approvals_config: dict[str, Any] | None = None,
    ) -> None:
        self.profile_name = profile_name
        self.policy_config = policy_config
        self.approvals_config = approvals_config or {}
        inline_rules = policy_config.get("rules", [])
        if not isinstance(inline_rules, list):
            inline_rules = []
        file_rules = _read_policy_file(policy_config.get("policy_file"))
        self.rules = [item for item in [*inline_rules, *file_rules] if isinstance(item, dict)]

    @classmethod
    def from_config(cls, profile_name: str, config: dict[str, Any]) -> "PolicyEngine":
        policy = config.get("policy", {})
        if not isinstance(policy, dict):
            policy = {}
        approvals = config.get("approvals", {})
        if not isinstance(approvals, dict):
            approvals = {}
        return cls(profile_name=profile_name, policy_config=policy, approvals_config=approvals)

    def _built_in_dynamic_guard(self, task: TaskDefinition, run_data: RunData) -> PolicyDecision:
        max_services = self.policy_config.get("max_services_discovered")
        if (
            max_services is not None
            and task.stage in {"recon", "enumeration"}
            and len(run_data.services) > int(max_services)
        ):
            return PolicyDecision(
                allow=False,
                action="deny",
                reason=f"service budget exceeded ({len(run_data.services)} > {int(max_services)})",
                rule_id="builtin.max_services_discovered",
            )

        max_errors = self.policy_config.get("max_errors_before_pause")
        if (
            max_errors is not None
            and task.stage in {"recon", "enumeration"}
            and len(run_data.errors) >= int(max_errors)
        ):
            return PolicyDecision(
                allow=False,
                action="pause",
                reason=f"error threshold reached ({len(run_data.errors)} >= {int(max_errors)})",
                rule_id="builtin.max_errors_before_pause",
            )
        return PolicyDecision(allow=True)

    def _approval_guard(self, task: TaskDefinition, run_data: RunData) -> PolicyDecision:
        approval_class = approval_class_for_task(task.key, task.capability, {"approvals": self.approvals_config})
        auto_approve_classes = {
            str(item)
            for item in self.approvals_config.get("auto_approve_classes", ["safe_auto"])
            if str(item).strip()
        }
        disabled_classes = {
            str(item)
            for item in self.approvals_config.get("disabled_classes", ["disabled_bruteforce"])
            if str(item).strip()
        }
        if approval_class in auto_approve_classes:
            return PolicyDecision(allow=True)
        if approval_class in disabled_classes:
            return PolicyDecision(
                allow=False,
                action="deny",
                reason=f"approval class '{approval_class}' is disabled by policy",
                rule_id=f"approval.{approval_class}",
            )

        scope_key = approval_scope_key(task.key, approval_class)
        latest_decision = None
        for decision in sorted(run_data.approval_decisions, key=lambda item: item.created_at):
            if decision.scope_key == scope_key:
                latest_decision = decision
        if latest_decision is None:
            action = "pause" if bool(self.approvals_config.get("pause_on_required", True)) else "deny"
            return PolicyDecision(
                allow=False,
                action=action,
                reason=f"approval required for {approval_class}",
                rule_id=f"approval.{approval_class}",
            )
        if latest_decision.status == "approved":
            return PolicyDecision(allow=True)
        return PolicyDecision(
            allow=False,
            action="deny",
            reason=latest_decision.reason or f"approval rejected for {approval_class}",
            rule_id=f"approval.{approval_class}",
        )

    def evaluate_task(self, task: TaskDefinition, run_data: RunData) -> PolicyDecision:
        decision = self._built_in_dynamic_guard(task, run_data)
        if not decision.allow:
            return decision

        approval_decision = self._approval_guard(task, run_data)
        if not approval_decision.allow:
            return approval_decision

        for rule in self.rules:
            if not _task_matcher(rule, task, self.profile_name):
                continue
            if not _facts_matcher(rule, run_data):
                continue
            action = str(rule.get("action", "allow")).lower()
            reason = str(rule.get("reason", "policy_rule_matched"))
            rule_id = str(rule.get("id")) if rule.get("id") else None
            if action in {"allow", "permit"}:
                continue
            if action in {"deny", "block"}:
                return PolicyDecision(allow=False, action="deny", reason=reason, rule_id=rule_id)
            if action in {"pause", "hold"}:
                return PolicyDecision(allow=False, action="pause", reason=reason, rule_id=rule_id)
        return PolicyDecision(allow=True)
