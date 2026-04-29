from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QMessageBox

from attackcastle.gui.tool_editor import ToolDefinitionDialog, ToolEditorTab
from attackcastle.tools.library import ToolLibraryStore


def _app():
    return QApplication.instance() or QApplication([])


def _tool(tool_id: str, *, install_command: str = "", enabled: bool = True) -> dict[str, object]:
    return {
        "id": tool_id,
        "display_name": tool_id.title(),
        "category": "utility",
        "platforms": ["linux", "windows", "darwin"],
        "enabled": enabled,
        "executable_name": tool_id,
        "install_command": install_command,
        "detection_command": f"{tool_id} --version",
        "timeout_seconds": 30,
    }


def test_tool_definition_dialog_builds_normalized_payload() -> None:
    _ = _app()
    dialog = ToolDefinitionDialog(definition=_tool("demo", install_command="echo install"))
    try:
        payload = dialog.definition()
        assert payload["id"] == "demo"
        assert payload["install_command"] == "echo install"
        assert payload["output"]["type"] == "raw"
    finally:
        dialog.close()


def test_tool_editor_loads_definitions_and_statuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _app()
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    (builtin / "demo.json").write_text(json.dumps(_tool("demo")), encoding="utf-8")
    monkeypatch.setattr(
        "attackcastle.gui.tool_editor.check_tool_status",
        lambda definition: type("Status", (), {"to_dict": lambda self: {"status": "installed", "version": "1.0"}})(),
    )

    tab = ToolEditorTab(ToolLibraryStore(builtin_dir=builtin, global_dir=tmp_path / "global"))
    try:
        assert tab.model.rowCount() == 1
        assert tab.model.data(tab.model.index(0, 0)) == "Installed"
        assert tab.model.data(tab.model.index(0, 4)) == "1.0"
    finally:
        tab.close()


def test_tool_editor_context_menu_exposes_required_actions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _app()
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    (builtin / "demo.json").write_text(json.dumps(_tool("demo")), encoding="utf-8")
    monkeypatch.setattr(
        "attackcastle.gui.tool_editor.check_tool_status",
        lambda definition: type("Status", (), {"to_dict": lambda self: {"status": "missing"}})(),
    )
    tab = ToolEditorTab(ToolLibraryStore(builtin_dir=builtin, global_dir=tmp_path / "global"))
    try:
        tab.table.selectRow(0)
        menu = tab.build_context_menu()
        assert [action.text() for action in menu.actions()] == [
            "Check Tool",
            "Download Tool",
            "Edit Tool",
            "Duplicate Tool",
            "Disable Tool",
        ]
    finally:
        tab.close()


def test_download_missing_queues_only_eligible_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _app()
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    (builtin / "missing-with-command.json").write_text(json.dumps(_tool("one", install_command="echo one")), encoding="utf-8")
    (builtin / "missing-no-command.json").write_text(json.dumps(_tool("two")), encoding="utf-8")
    monkeypatch.setattr(
        "attackcastle.gui.tool_editor.check_tool_status",
        lambda definition: type("Status", (), {"to_dict": lambda self: {"status": "missing"}})(),
    )
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    started: list[str] = []

    tab = ToolEditorTab(ToolLibraryStore(builtin_dir=builtin, global_dir=tmp_path / "global"))
    monkeypatch.setattr(tab, "_start_install", lambda definition: started.append(str(definition["id"])))
    try:
        tab.download_missing()
        assert started == ["one"]
        assert tab._statuses["two"]["status"] == "install_not_configured"
    finally:
        tab.close()
