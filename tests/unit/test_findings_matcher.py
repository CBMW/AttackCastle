from attackcastle.core.models import Observation, RunData, RunMetadata, new_id, now_utc
from attackcastle.findings.matcher import build_observation_index, match_entities_for_template


def _blank_run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )


def test_match_template_all_logic():
    run_data = _blank_run_data()
    web_id = new_id("web")
    run_data.observations.extend(
        [
            Observation(
                observation_id=new_id("obs"),
                key="web.missing_security_headers",
                value=["x-frame-options"],
                entity_type="web_app",
                entity_id=web_id,
                source_tool="test",
            ),
            Observation(
                observation_id=new_id("obs"),
                key="web.forms.count",
                value=1,
                entity_type="web_app",
                entity_id=web_id,
                source_tool="test",
            ),
        ]
    )

    template = {
        "trigger": {
            "entity_type": "web_app",
            "logic": "all",
            "conditions": [
                {"key": "web.missing_security_headers", "op": "exists"},
                {"key": "web.forms.count", "op": "gte", "value": 1},
            ],
        }
    }
    index = build_observation_index(run_data)
    matched = match_entities_for_template(template, index)
    assert web_id in matched


def test_match_template_any_logic():
    run_data = _blank_run_data()
    tls_id = new_id("tls")
    run_data.observations.append(
        Observation(
            observation_id=new_id("obs"),
            key="tls.weak_protocol",
            value=True,
            entity_type="tls",
            entity_id=tls_id,
            source_tool="test",
        )
    )
    template = {
        "trigger": {
            "entity_type": "tls",
            "logic": "any",
            "conditions": [
                {"key": "tls.weak_protocol", "op": "eq", "value": True},
                {"key": "tls.cert.expiring_soon", "op": "eq", "value": True},
            ],
        }
    }
    index = build_observation_index(run_data)
    matched = match_entities_for_template(template, index)
    assert matched == [tls_id]

