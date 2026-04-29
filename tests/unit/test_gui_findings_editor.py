from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from attackcastle.findings.library import FindingLibraryStore
from attackcastle.gui.findings_editor import FindingDefinitionDialog, FindingsEditorTab, TriggerEditorWidget


def _definition(definition_id: str = "GUI_RULE") -> dict[str, object]:
    return {
        "id": definition_id,
        "version": "1.0.0",
        "enabled": True,
        "title": "GUI Rule",
        "severity": "low",
        "category": "General",
        "description": "Description",
        "impact": "Impact",
        "likelihood": "Likelihood",
        "recommendations": ["Fix"],
        "references": [],
        "tags": ["gui"],
        "trigger": {"entity_type": "asset", "logic": "all", "conditions": [{"key": "entity.detected", "op": "exists"}]},
        "evidence_requirements": {"min_items": 0, "keys": []},
        "corroboration": {"min_observations": 1, "min_distinct_sources": 1, "min_confidence": 0.6, "required_assertions": []},
        "plextrac": {},
        "detection": {
            "logic": "any",
            "triggers": [{"id": "trigger-1", "enabled": True, "tool": "any", "operator": "output contains", "scope": "stdout", "value": "needle"}],
        },
    }


def _app():
    return QApplication.instance() or QApplication([])


def test_trigger_editor_scopes_follow_operator() -> None:
    _ = _app()
    widget = TriggerEditorWidget()
    try:
        widget.operator_combo.setCurrentText("header missing")
        assert [widget.scope_combo.itemText(index) for index in range(widget.scope_combo.count())] == ["response_headers"]
        widget.operator_combo.setCurrentText("tool failed")
        assert [widget.scope_combo.itemText(index) for index in range(widget.scope_combo.count())] == ["tool_execution"]
        assert widget.value_edit.isEnabled() is False
    finally:
        widget.close()


def test_definition_dialog_builds_detection_payload() -> None:
    _ = _app()
    dialog = FindingDefinitionDialog(definition=_definition())
    try:
        payload = dialog.definition()
        assert payload["id"] == "GUI_RULE"
        assert payload["detection"]["triggers"][0]["operator"] == "output contains"
    finally:
        dialog.close()


def test_findings_editor_loads_and_saves_user_definition(tmp_path: Path) -> None:
    _ = _app()
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    (builtin / "GUI_RULE.json").write_text(json.dumps(_definition()), encoding="utf-8")
    tab = FindingsEditorTab(FindingLibraryStore(builtin_dir=builtin, user_dir=user))
    try:
        assert tab.definition_list.count() == 1
        definition = dict(_definition("USER_RULE"))
        tab._save_definition(definition)
        assert (user / "USER_RULE.json").exists()
        assert any(tab.definition_list.item(index).data(Qt.UserRole) == "USER_RULE" for index in range(tab.definition_list.count()))
    finally:
        tab.close()
