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
from attackcastle.gui.models import Engagement, GuiProfile, RunSnapshot
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.runtime import profile_to_engine_overrides
from attackcastle.gui.workspace_store import WorkspaceStore


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_configuration_tab_loads_and_saves_proxy_fields(tmp_path: Path) -> None:
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

        assert tab.proxy_enabled_checkbox.isChecked() is True
        assert tab.proxy_url_edit.text() == "http://127.0.0.1:8080"

        tab.proxy_url_edit.setText("http://127.0.0.1:8081")
        tab._save_profile()

        saved = next(item for item in store.load() if item.name == "Proxy Profile")
        assert saved.proxy_enabled is True
        assert saved.proxy_url == "http://127.0.0.1:8081"
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


def test_start_scan_dialog_build_request_preserves_proxy_fields(tmp_path: Path) -> None:
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

        assert "Proxy: http://127.0.0.1:8080" in dialog.launch_summary.text()
        assert request.profile.proxy_enabled is True
        assert request.profile.proxy_url == "http://127.0.0.1:8080"
    finally:
        dialog.close()


def test_retry_selected_run_preserves_proxy_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app()
    window = MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )

    try:
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
        assert launched_requests[0].profile.proxy_enabled is True
        assert launched_requests[0].profile.proxy_url == "http://127.0.0.1:8080"
    finally:
        window._refresh_timer.stop()
        window.close()
