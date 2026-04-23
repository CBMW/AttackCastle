from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from attackcastle.gui.configuration_tab import ConfigurationTab
from attackcastle.gui.dialogs import StartScanDialog
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.main_window import MainWindow
from attackcastle.gui.models import Engagement, GuiProfile, GuiProxySettings, RunSnapshot, ScanRequest
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.runtime import profile_to_engine_overrides
from attackcastle.gui.workspace_store import WorkspaceStore


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_configuration_tab_omits_profile_proxy_fields(tmp_path: Path) -> None:
    _app()
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_profile(
        GuiProfile(
            name="Proxy Profile",
            proxy_enabled=True,
            proxy_url="http://127.0.0.1:8080",
        )
    )
    tab = ConfigurationTab(store, lambda profiles: None)

    try:
        names = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        tab.profile_list.setCurrentRow(names.index("Proxy Profile"))

        assert not hasattr(tab, "proxy_enabled_checkbox")
        assert not hasattr(tab, "proxy_url_edit")
        saved = next(item for item in store.load() if item.name == "Proxy Profile")
        assert saved.proxy_enabled is True
        assert saved.proxy_url == "http://127.0.0.1:8080"
    finally:
        tab.close()


def test_profile_to_engine_overrides_include_proxy_settings() -> None:
    overrides = profile_to_engine_overrides(
        GuiProfile(
            name="Proxy Profile",
            proxy_enabled=True,
            proxy_url="http://127.0.0.1:8080",
        )
    )

    assert overrides["proxy"]["url"] == "http://127.0.0.1:8080"


def test_start_scan_dialog_leaves_proxy_to_settings_page(tmp_path: Path) -> None:
    _app()
    profiles = [
        GuiProfile(
            name="Proxy Profile",
            output_directory=str(tmp_path),
            proxy_enabled=True,
            proxy_url="http://127.0.0.1:8080",
        )
    ]
    engagements = [Engagement(engagement_id="eng_1", name="Client Alpha")]
    dialog = StartScanDialog(profiles, engagements, selected_engagement_id="eng_1")

    try:
        dialog.scan_name_edit.setText("Proxy Scan")
        dialog.target_input_edit.setPlainText("example.com")
        dialog._refresh_launch_summary()

        request = dialog.build_request()

        assert "Proxy:" not in dialog.launch_summary.text()
        assert request.profile.proxy_enabled is False
        assert request.profile.proxy_url == ""
    finally:
        dialog.close()


def test_settings_proxy_page_persists_and_updates_attacker_proxy(tmp_path: Path) -> None:
    _app()
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    window = MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=workspace_store,
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )

    try:
        settings_sections = [window.settings_nav_list.item(idx).text() for idx in range(window.settings_nav_list.count())]
        assert "Proxy" in settings_sections

        window.proxy_global_url_edit.setText("http://127.0.0.1:8080")
        window.proxy_scanner_enabled_checkbox.setChecked(True)
        window.proxy_scanner_url_edit.setText("http://127.0.0.1:8081")
        window.proxy_attacker_enabled_checkbox.setChecked(True)
        window.proxy_attacker_url_edit.setText("http://127.0.0.1:8082")

        saved = workspace_store.load_proxy_settings()
        assert saved.global_proxy_url == "http://127.0.0.1:8080"
        assert saved.effective_scanner_proxy_url() == "http://127.0.0.1:8081"
        assert saved.effective_attacker_proxy_url() == "http://127.0.0.1:8082"
        assert window.attacker_tab._proxy_url == "http://127.0.0.1:8082"

        window.proxy_all_traffic_checkbox.setChecked(True)

        saved = workspace_store.load_proxy_settings()
        assert saved.effective_scanner_proxy_url() == "http://127.0.0.1:8080"
        assert saved.effective_attacker_proxy_url() == "http://127.0.0.1:8080"
        assert window.attacker_tab._proxy_url == "http://127.0.0.1:8080"
        assert not window.proxy_scanner_url_edit.isEnabled()
        assert not window.proxy_attacker_url_edit.isEnabled()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_main_window_applies_scanner_proxy_settings_to_launch_request(tmp_path: Path) -> None:
    _app()
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    workspace_store.save_proxy_settings(
        GuiProxySettings(
            scanner_proxy_enabled=True,
            scanner_proxy_url="http://127.0.0.1:8081",
        )
    )
    window = MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=workspace_store,
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )

    try:
        request = ScanRequest(
            scan_name="Proxy Scan",
            target_input="example.com",
            profile=GuiProfile(name="No Profile Proxy"),
            output_directory=str(tmp_path),
        )

        window._apply_proxy_settings_to_request(request)

        assert request.profile.proxy_enabled is True
        assert request.profile.proxy_url == "http://127.0.0.1:8081"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_retry_selected_run_uses_current_scanner_proxy_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app()
    window = MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )

    try:
        window.proxy_settings = GuiProxySettings(scanner_proxy_enabled=True, scanner_proxy_url="http://127.0.0.1:8088")
        run_dir = tmp_path / "run-retry"
        (run_dir / "data").mkdir(parents=True)
        (run_dir / "data" / "gui_session.json").write_text(
            json.dumps(
                {
                    "scan_name": "Retry Me",
                    "target_input": "example.com",
                    "engagement_id": "eng-1",
                    "engagement_name": "Client One",
                }
            ),
            encoding="utf-8",
        )
        (run_dir / "data" / "gui_requested_profile.json").write_text(
            json.dumps(
                {
                    "name": "Proxy Profile",
                    "proxy_enabled": True,
                    "proxy_url": "http://127.0.0.1:8080",
                }
            ),
            encoding="utf-8",
        )
        snapshot = RunSnapshot(
            run_id="run-retry",
            scan_name="Retry Me",
            run_dir=str(run_dir),
            state="failed",
            elapsed_seconds=30.0,
            eta_seconds=None,
            current_task="Nuclei",
            total_tasks=4,
            completed_tasks=4,
            workspace_id=window._active_workspace_id,
            workspace_name=window._active_workspace().name if window._active_workspace() is not None else "Client One",
            target_input="example.com",
        )
        launched_requests = []
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id
        monkeypatch.setattr(window, "_launch_request", lambda request: launched_requests.append(request))

        window._retry_selected_run()

        assert len(launched_requests) == 1
        window._apply_proxy_settings_to_request(launched_requests[0])
        assert launched_requests[0].profile.proxy_enabled is True
        assert launched_requests[0].profile.proxy_url == "http://127.0.0.1:8088"
    finally:
        window._refresh_timer.stop()
        window.close()
