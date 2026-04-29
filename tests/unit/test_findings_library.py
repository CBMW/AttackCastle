from __future__ import annotations

import json

from attackcastle.findings.library import FindingLibraryStore, definition_filename


def _definition(definition_id: str, title: str) -> dict[str, object]:
    return {
        "id": definition_id,
        "version": "1.0.0",
        "enabled": True,
        "title": title,
        "severity": "low",
        "category": "General",
        "description": "Description",
        "impact": "Impact",
        "likelihood": "Likelihood",
        "recommendations": ["Fix it"],
        "references": [],
        "tags": ["test"],
        "trigger": {
            "entity_type": "asset",
            "logic": "all",
            "conditions": [{"key": "entity.detected", "op": "exists"}],
        },
        "evidence_requirements": {"min_items": 0, "keys": []},
        "corroboration": {
            "min_observations": 1,
            "min_distinct_sources": 1,
            "min_confidence": 0.6,
            "required_assertions": [],
        },
        "plextrac": {},
    }


def test_user_library_overrides_builtin_definition(tmp_path):
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    user.mkdir()
    (builtin / "FINDING.json").write_text(json.dumps(_definition("FINDING", "Built In")), encoding="utf-8")
    override = _definition("FINDING", "User Override")
    override["enabled"] = False
    (user / "FINDING.json").write_text(json.dumps(override), encoding="utf-8")

    result = FindingLibraryStore(builtin_dir=builtin, user_dir=user).load_definitions()

    assert result.warnings == []
    assert [item["title"] for item in result.definitions] == ["User Override"]
    assert result.definitions[0]["enabled"] is False


def test_library_save_uses_stable_pretty_json(tmp_path):
    store = FindingLibraryStore(builtin_dir=tmp_path / "builtin", user_dir=tmp_path / "user")
    definition = _definition("My Finding", "Saved")

    path = store.save_definition(definition)

    assert path.name == definition_filename("My Finding")
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text)["id"] == "My Finding"


def test_invalid_user_definition_reports_warning_and_keeps_builtin(tmp_path):
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    user.mkdir()
    (builtin / "VALID.json").write_text(json.dumps(_definition("VALID", "Valid")), encoding="utf-8")
    invalid = _definition("INVALID", "Invalid")
    invalid["detection"] = {
        "logic": "any",
        "triggers": [{"id": "bad", "tool": "any", "operator": "output matches regex", "scope": "stdout", "value": "["}],
    }
    (user / "INVALID.json").write_text(json.dumps(invalid), encoding="utf-8")

    result = FindingLibraryStore(builtin_dir=builtin, user_dir=user).load_definitions()

    assert [item["id"] for item in result.definitions] == ["VALID"]
    assert any("invalid regex" in warning for warning in result.warnings)


def test_invalid_user_json_does_not_block_other_definitions(tmp_path):
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    user.mkdir()
    (builtin / "VALID.json").write_text(json.dumps(_definition("VALID", "Valid")), encoding="utf-8")
    (user / "USER_VALID.json").write_text(json.dumps(_definition("USER_VALID", "User Valid")), encoding="utf-8")
    (user / "BROKEN.json").write_text("{", encoding="utf-8")

    result = FindingLibraryStore(builtin_dir=builtin, user_dir=user).load_definitions()

    assert {item["id"] for item in result.definitions} == {"VALID", "USER_VALID"}
    assert any("invalid JSON" in warning for warning in result.warnings)
