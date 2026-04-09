from __future__ import annotations

from pathlib import Path

from attackcastle.core.models import RunData, RunMetadata, Service, Technology, now_utc
from attackcastle.orchestration.task_graph import TaskDefinition
from attackcastle.policy import PolicyEngine


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="policy-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def _task(key: str, capability: str, stage: str) -> TaskDefinition:
    return TaskDefinition(
        key=key,
        label=key,
        capability=capability,
        stage=stage,
        runner=lambda _context, _run_data: None,
        should_run=lambda _run_data: (True, "always"),
    )


def test_policy_engine_denies_when_service_budget_exceeded():
    run_data = _run_data()
    run_data.services.append(
        Service(
            service_id="svc-1",
            asset_id="asset-1",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
        )
    )
    engine = PolicyEngine(profile_name="standard", policy_config={"max_services_discovered": 0})
    decision = engine.evaluate_task(_task("run-nmap", "network_port_scan", "recon"), run_data)
    assert decision.allow is False
    assert decision.action == "deny"
    assert decision.rule_id == "builtin.max_services_discovered"


def test_policy_engine_pauses_when_error_threshold_reached():
    run_data = _run_data()
    run_data.errors.extend(["err-1", "err-2"])
    engine = PolicyEngine(profile_name="standard", policy_config={"max_errors_before_pause": 2})
    decision = engine.evaluate_task(_task("probe-web", "web_probe", "enumeration"), run_data)
    assert decision.allow is False
    assert decision.action == "pause"
    assert decision.rule_id == "builtin.max_errors_before_pause"


def test_policy_engine_applies_inline_rule_with_tech_match():
    run_data = _run_data()
    run_data.technologies.append(
        Technology(
            tech_id="tech-1",
            asset_id="asset-1",
            name="WordPress",
            version="6.5",
        )
    )
    engine = PolicyEngine(
        profile_name="standard",
        policy_config={
            "rules": [
                {
                    "id": "deny-wpscan-with-wordpress",
                    "match": {"task_key": "run-wpscan"},
                    "when": {"tech_contains": "wordpress"},
                    "action": "deny",
                    "reason": "manual_approval_required",
                }
            ]
        },
    )
    decision = engine.evaluate_task(_task("run-wpscan", "cms_wordpress_scan", "enumeration"), run_data)
    assert decision.allow is False
    assert decision.action == "deny"
    assert decision.rule_id == "deny-wpscan-with-wordpress"
    assert decision.reason == "manual_approval_required"


def test_policy_engine_loads_rules_from_file(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - id: deny_tls",
                "    match:",
                "      capability: tls_probe",
                "    action: deny",
                "    reason: tls_disabled_for_this_profile",
            ]
        ),
        encoding="utf-8",
    )
    config = {"policy_file": str(policy_path)}
    engine = PolicyEngine(profile_name="standard", policy_config=config)
    decision = engine.evaluate_task(_task("detect-tls", "tls_probe", "enumeration"), _run_data())
    assert decision.allow is False
    assert decision.reason == "tls_disabled_for_this_profile"
    assert decision.rule_id == "deny_tls"

