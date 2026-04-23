from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QDialogButtonBox, QLabel, QMessageBox, QToolButton

from attackcastle.gui.dialogs import StartScanDialog, WorkspaceChooserDialog, WorkspaceDialog
from attackcastle.gui.extensions import ExtensionManifest, CommandHookExtensionConfig
from attackcastle.gui.models import Engagement, GuiProfile, Workspace
from attackcastle.gui.extensions import ExtensionRecord
from attackcastle.gui.workspace_store import WorkspaceStore, ad_hoc_output_home
from attackcastle.readiness import ReadinessReport


def _make_dialog() -> StartScanDialog:
    app = QApplication.instance() or QApplication([])
    _ = app
    profiles = [GuiProfile(name="Standard", description="Balanced", risk_mode="safe-active")]
    engagements = [Engagement(engagement_id="eng-1", name="Alpha")]
    return StartScanDialog(profiles, engagements, selected_engagement_id="eng-1")


def _readiness(status: str, *, can_launch: bool, partial_run: bool, missing_tools: list[str]) -> ReadinessReport:
    return ReadinessReport(
        status=status,
        can_launch=can_launch,
        partial_run=partial_run,
        risk_mode="safe-active",
        missing_tools=missing_tools,
        tool_impact=(
            [
                {
                    "tool": "nmap",
                    "capabilities": ["network_port_scan"],
                    "task_labels": ["Running Nmap"],
                }
            ]
            if missing_tools
            else []
        ),
        blocked_capabilities=["network_port_scan"] if missing_tools else [],
        recommended_actions=[
            "Install missing tools with `attackcastle doctor --install-missing --yes`."
        ]
        if missing_tools
        else ["Current environment is ready for the selected workflow."],
        selected_task_count=4,
        runnable_task_count=3 if missing_tools else 4,
        blocked_task_count=1 if missing_tools else 0,
        assessment_mode="targeted",
    )


def _complete_readiness(dialog: StartScanDialog) -> None:
    dialog._readiness_timer.stop()
    dialog._start_readiness_check()
    for _ in range(100):
        if dialog._readiness_result_is_current():
            return
        QTest.qWait(20)
    raise AssertionError("readiness check did not finish")


def test_launch_dialog_uses_inline_validation_for_missing_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    warnings: list[str] = []

    try:
        monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(str(args[2])) or QMessageBox.Ok)
        dialog.scan_name_edit.clear()
        dialog.target_input_edit.clear()

        dialog.accept()

        assert not warnings
        assert "Before launch:" in dialog.launch_validation_label.text()
        assert dialog.result() == 0
    finally:
        dialog.close()


def test_launch_dialog_has_no_profile_preset_controls() -> None:
    dialog = _make_dialog()

    try:
        dialog._refresh_launch_summary()

        assert "Coverage:" in dialog.launch_summary.text()
        assert "Active Validation:" not in dialog.launch_summary.text()
        assert not hasattr(dialog, "_apply_profile_recipe")
        assert not hasattr(dialog, "profile_preset_summary")
    finally:
        dialog.close()


def test_launch_dialog_skips_report_generation_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    readiness_kwargs: list[dict[str, object]] = []

    def fake_readiness(**kwargs: object) -> ReadinessReport:
        readiness_kwargs.append(kwargs)
        return _readiness("ready", can_launch=True, partial_run=False, missing_tools=[])

    try:
        monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", fake_readiness)
        dialog.scan_name_edit.setText("No Report")
        dialog.target_input_edit.setPlainText("example.com")
        dialog._readiness_report = None
        dialog._readiness_signature = ""
        dialog._active_readiness_requests.clear()
        _complete_readiness(dialog)

        request = dialog.build_request()

        assert dialog.export_html.isChecked() is False
        assert request.profile.export_html_report is False
        assert readiness_kwargs
        assert readiness_kwargs[-1]["no_report"] is True
    finally:
        dialog.close()


def test_launch_dialog_enables_report_generation_when_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    readiness_kwargs: list[dict[str, object]] = []

    def fake_readiness(**kwargs: object) -> ReadinessReport:
        readiness_kwargs.append(kwargs)
        return _readiness("ready", can_launch=True, partial_run=False, missing_tools=[])

    try:
        monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", fake_readiness)
        dialog.scan_name_edit.setText("With Report")
        dialog.target_input_edit.setPlainText("example.com")
        dialog.export_html.setChecked(True)
        dialog._readiness_report = None
        dialog._readiness_signature = ""
        dialog._active_readiness_requests.clear()
        _complete_readiness(dialog)

        request = dialog.build_request()

        assert request.profile.export_html_report is True
        assert readiness_kwargs
        assert readiness_kwargs[-1]["no_report"] is False
    finally:
        dialog.close()


def test_launch_dialog_tool_coverage_preserves_manual_overrides_across_profile_changes() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profiles = [
        GuiProfile(name="Cautious", base_profile="cautious", enable_nuclei=False, enable_sqlmap=False),
        GuiProfile(name="Aggressive", base_profile="aggressive", enable_nuclei=True, enable_sqlmap=False),
    ]
    dialog = StartScanDialog(profiles, None)

    try:
        assert dialog._profile_tool_defaults["enable_nuclei"] is False

        dialog.enable_sqlmap.setChecked(True)
        dialog.profile_picker.setCurrentIndex(1)

        assert dialog._profile_tool_defaults["enable_nuclei"] is True
        assert dialog.enable_sqlmap.isChecked() is True
        assert dialog._manual_tool_overrides["enable_sqlmap"] is True
    finally:
        dialog.close()


def test_launch_dialog_tool_coverage_marks_unwired_tools_unavailable() -> None:
    dialog = _make_dialog()

    try:
        disabled_rows = [
            checkbox
            for checkbox in dialog.findChildren(QCheckBox)
            if checkbox.objectName() == "toolCoverageCheckbox" and not checkbox.isEnabled()
        ]
        unavailable_names = {
            label.text()
            for label in dialog.findChildren(QLabel)
            if label.objectName() == "toolCoverageName" and label.property("available") is False
        }

        assert disabled_rows
        assert {"amass", "rustscan", "testssl.sh"} <= unavailable_names
    finally:
        dialog.close()


def test_launch_dialog_reused_tool_rows_are_independent() -> None:
    dialog = _make_dialog()

    try:
        rows = {
            str(checkbox.property("coverage_key")): checkbox
            for checkbox in dialog.findChildren(QCheckBox)
            if checkbox.objectName() == "toolCoverageCheckbox" and checkbox.isEnabled()
        }

        rows["port_discovery.nmap"].setChecked(False)

        assert rows["port_discovery.nmap"].isChecked() is False
        assert rows["service_detection.nmap"].isChecked() is True
        assert dialog._profile_from_form().tool_coverage_overrides == {"port_discovery.nmap": False}
    finally:
        dialog.close()


def test_launch_dialog_removes_playbook_and_preset_library_overrides() -> None:
    dialog = _make_dialog()

    try:
        section_titles = {button.text() for button in dialog.findChildren(QToolButton)}

        assert "Playbooks / Preset Libraries" not in section_titles
        assert not hasattr(dialog, "use_default_validation_presets_checkbox")
        assert not hasattr(dialog, "injection_preset_edit")
        assert not hasattr(dialog, "web_playbooks_checkbox")
    finally:
        dialog.close()


def test_launch_dialog_uses_profile_only_in_essentials() -> None:
    dialog = _make_dialog()

    try:
        assert not hasattr(dialog, "risk_posture_combo")
        assert dialog.profile_picker is not None
        assert dialog.use_scope_checkbox.text() == "Use scope"
    finally:
        dialog.close()


def test_launch_dialog_exposes_tooltips_for_primary_fields() -> None:
    dialog = _make_dialog()

    try:
        assert "clear name" in dialog.scan_name_edit.toolTip().lower()
        assert "saved gui profile" in dialog.profile_picker.toolTip().lower()
        assert "one target per line" in dialog.target_input_edit.toolTip().lower()
        assert "append the current project scope text" in dialog.use_scope_checkbox.toolTip().lower()
        assert "advanced profile override" in dialog.advanced_toggle.toolTip().lower()
    finally:
        dialog.close()


def test_launch_dialog_only_confirms_modally_for_elevated_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    confirmations: list[str] = []

    try:
        monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", lambda **kwargs: _readiness("ready", can_launch=True, partial_run=False, missing_tools=[]))
        dialog.scan_name_edit.setText("Authorized")
        dialog.target_input_edit.setPlainText("example.com")
        dialog.risk_mode_combo.setCurrentText("aggressive")
        _complete_readiness(dialog)
        monkeypatch.setattr(QMessageBox, "question", lambda *args: confirmations.append(str(args[2])) or QMessageBox.No)

        dialog.accept()

        assert confirmations
        assert "more aggressive options" in confirmations[0]
        assert dialog.result() == 0
    finally:
        dialog.close()


def test_launch_dialog_sizes_within_available_screen_bounds() -> None:
    dialog = _make_dialog()

    try:
        screen = dialog.screen() or QApplication.primaryScreen()
        assert screen is not None
        geometry = screen.availableGeometry()

        assert dialog.width() <= geometry.width()
        assert dialog.height() <= geometry.height()
        buttons = dialog.findChildren(QDialogButtonBox)
        assert buttons
    finally:
        dialog.close()


def test_workspace_dialog_accepts_typed_scope_text() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    dialog = WorkspaceDialog()

    try:
        dialog.name_edit.setText("Alpha")
        dialog.scope_edit.setFocus(Qt.FocusReason.MouseFocusReason)
        QTest.keyClicks(dialog.scope_edit, "example.com")

        workspace = dialog.build_workspace()

        assert dialog.scope_edit.toPlainText() == "example.com"
        assert workspace.scope_summary == "example.com"
    finally:
        dialog.close()


def test_launch_dialog_supports_no_workspace_session(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profiles = [GuiProfile(name="Standard", description="Balanced", risk_mode="safe-active")]
    dialog = StartScanDialog(profiles, None)

    try:
        dialog.scan_name_edit.setText("Ad Hoc Scan")
        dialog.target_input_edit.setPlainText("example.com")

        request = dialog.build_request()

        assert "Session" not in {label.text() for label in dialog.findChildren(QLabel)}
        assert request.workspace_id == ""
        assert request.workspace_name == ""
        assert request.output_directory == ad_hoc_output_home()
    finally:
        dialog.close()


def test_launch_dialog_use_scope_appends_workspace_scope_once() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profiles = [GuiProfile(name="Standard", description="Balanced", risk_mode="safe-active")]
    workspace = Workspace(workspace_id="ws-1", name="Alpha", scope_summary="example.com\n203.0.113.0/24")
    dialog = StartScanDialog(profiles, workspace)

    try:
        dialog.target_input_edit.setPlainText("api.example.com")

        dialog.use_scope_checkbox.setChecked(True)
        first_text = dialog.target_input_edit.toPlainText()
        dialog.use_scope_checkbox.setChecked(False)
        dialog.use_scope_checkbox.setChecked(True)

        assert first_text == "api.example.com\n\nexample.com\n203.0.113.0/24"
        assert dialog.target_input_edit.toPlainText() == first_text
        assert "already appended" in dialog.scope_status_label.text().lower()
    finally:
        dialog.close()


def test_launch_dialog_use_scope_is_disabled_without_workspace_scope() -> None:
    app = QApplication.instance() or QApplication([])  # noqa: F841
    profiles = [GuiProfile(name="Standard", description="Balanced", risk_mode="safe-active")]
    workspace = Workspace(workspace_id="ws-1", name="Alpha", scope_summary="")
    dialog = StartScanDialog(profiles, workspace)

    try:
        assert dialog.use_scope_checkbox.isEnabled() is False
        assert "no saved project scope" in dialog.scope_status_label.text().lower()
    finally:
        dialog.close()


def test_launch_dialog_serializes_selected_extension_ids(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profiles = [GuiProfile(name="Standard", description="Balanced", risk_mode="safe-active")]
    manifest = ExtensionManifest(
        schema_version="extensions/v1",
        extension_id="custom-tool",
        name="Custom Tool",
        version="1.0.0",
        capabilities=["command_hook"],
        command_hook=CommandHookExtensionConfig(command="python"),
    )
    extension_dir = tmp_path / "extensions" / "custom-tool"
    extension_dir.mkdir(parents=True)
    dialog = StartScanDialog(
        profiles,
        None,
        available_extensions=[
            ExtensionRecord(
                directory=extension_dir,
                manifest_path=extension_dir / "extension.json",
                manifest=manifest,
                raw_text="{}",
            )
        ],
    )

    try:
        dialog.scan_name_edit.setText("With Extension")
        dialog.target_input_edit.setPlainText("example.com")
        dialog.extension_list.item(0).setCheckState(Qt.CheckState.Checked)

        request = dialog.build_request()

        assert request.enabled_extension_ids == ["custom-tool"]
        assert "Extensions: custom-tool" in dialog.launch_summary.text()
    finally:
        dialog.close()


def test_launch_dialog_shows_ready_readiness_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", lambda **kwargs: _readiness("ready", can_launch=True, partial_run=False, missing_tools=[]))

    try:
        dialog.scan_name_edit.setText("Ready Scan")
        dialog.target_input_edit.setPlainText("example.com")
        _complete_readiness(dialog)

        assert "Readiness: Ready" in dialog.readiness_label.text()
        assert "Can launch: yes" in dialog.readiness_label.text()
    finally:
        dialog.close()


def test_launch_dialog_shows_partial_readiness_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", lambda **kwargs: _readiness("partial", can_launch=True, partial_run=True, missing_tools=["nmap"]))

    try:
        dialog.scan_name_edit.setText("Partial Scan")
        dialog.target_input_edit.setPlainText("example.com")
        _complete_readiness(dialog)

        assert "Readiness: Partial" in dialog.readiness_label.text()
        assert "Missing tools: nmap" in dialog.readiness_label.text()
        assert "Install missing tools" in dialog.launch_validation_label.text()
    finally:
        dialog.close()


def test_launch_dialog_blocks_accept_when_readiness_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    dialog = _make_dialog()
    monkeypatch.setattr("attackcastle.gui.dialogs.assess_readiness", lambda **kwargs: _readiness("blocked", can_launch=False, partial_run=False, missing_tools=["nmap"]))

    try:
        dialog.scan_name_edit.setText("Blocked Scan")
        dialog.target_input_edit.setPlainText("example.com")
        _complete_readiness(dialog)

        dialog.accept()

        assert dialog.result() == 0
        assert "Install missing tools" in dialog.launch_validation_label.text()
    finally:
        dialog.close()


def test_workspace_chooser_exposes_empty_state_and_launch_without_workspace(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    chooser = WorkspaceChooserDialog([], workspace_store=WorkspaceStore(tmp_path / "workspace.json"))

    try:
        assert chooser.workspace_list.isHidden()
        assert chooser.open_button.isEnabled() is False
        assert "Projects are saved contexts" in chooser.empty_state_label.text()

        chooser.no_workspace_button.click()

        assert chooser.result() != 0
        assert chooser.launch_action() == "launch_without_workspace"
    finally:
        chooser.close()


def test_workspace_chooser_can_create_workspace_and_preselect_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    store = WorkspaceStore(tmp_path / "workspace.json")
    chooser = WorkspaceChooserDialog([], workspace_store=store)

    created_workspace = Workspace(workspace_id="ws_alpha", name="Alpha", home_dir=str(tmp_path / "alpha"))
    monkeypatch.setattr(WorkspaceDialog, "exec", lambda self: QDialog.Accepted)
    monkeypatch.setattr(WorkspaceDialog, "build_workspace", lambda self: created_workspace)

    try:
        chooser.create_button.click()

        assert [store_workspace.workspace_id for store_workspace in store.load_workspaces()] == ["ws_alpha"]
        assert chooser.selected_workspace_id() == "ws_alpha"
        assert chooser.workspace_list.isHidden() is False
    finally:
        chooser.close()
