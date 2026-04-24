from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtWidgets import QApplication, QFrame, QLabel, QPlainTextEdit, QPushButton, QSplitter, QTabWidget

import attackcastle.gui.attacker_tab as attacker_tab_module
from attackcastle.gui.attacker_tab import (
    AttackerTab,
    _execute_http_request,
    _format_http_response,
    _parse_raw_http_request,
)
from attackcastle.gui.assets_tab import AssetsTab
from attackcastle.gui.models import AttackWorkspace, RunSnapshot, Workspace
from attackcastle.gui.workspace_store import WorkspaceStore


def _make_snapshot(tmp_path: Path) -> RunSnapshot:
    return RunSnapshot(
        run_id="run-attacker",
        scan_name="Attacker Run",
        run_dir=str(tmp_path / "run-attacker"),
        state="completed",
        elapsed_seconds=12.0,
        eta_seconds=0.0,
        current_task="Idle",
        total_tasks=1,
        completed_tasks=1,
        workspace_id="workspace-1",
        workspace_name="Workspace One",
        assets=[
            {
                "asset_id": "asset-1",
                "kind": "host",
                "name": "edge-1",
                "ip": "203.0.113.10",
                "aliases": ["edge.example.com"],
            }
        ],
        services=[
            {
                "service_id": "svc-1",
                "asset_id": "asset-1",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "name": "https",
            }
        ],
        web_apps=[
            {
                "web_app_id": "web-1",
                "asset_id": "asset-1",
                "url": "https://edge.example.com",
                "status_code": 200,
                "title": "Edge",
            }
        ],
    )


def test_workspace_store_persists_attack_workspaces(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save_workspace(Workspace(workspace_id="workspace-1", name="Workspace One"))
    workspace = AttackWorkspace(
        attack_workspace_id="attack-1",
        name="edge-1 - HTTP Replay",
        workspace_type="http",
    )

    store.save_attack_workspaces("workspace-1", [workspace])

    loaded = store.load_attack_workspaces("workspace-1")
    assert len(loaded) == 1
    assert loaded[0].attack_workspace_id == "attack-1"
    assert loaded[0].workspace_type == "http"


def test_attacker_tab_creates_typed_workspace_from_asset(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    stored: list[AttackWorkspace] = []

    def save_workspaces(_workspace_id: str, rows: list[AttackWorkspace]) -> None:
        stored.clear()
        stored.extend(rows)

    tab = AttackerTab(
        load_workspaces=lambda _workspace_id: list(stored),
        save_workspaces=save_workspaces,
    )
    snapshot = _make_snapshot(tmp_path)

    try:
        tab.set_workspace(snapshot.workspace_id)
        created = tab.add_workspace_from_asset("web_app", snapshot.web_apps[0], snapshot, "http")

        assert created.workspace_type == "http"
        assert created.target_objects[0].target == "https://edge.example.com"
        assert created.sessions[0].session_type == "http-replay"
        assert tab.workspace_tabs.count() == 1
        page = tab.workspace_tabs.widget(0)
        labels = {label.text() for label in page.findChildren(QLabel)}
        assert {"HTTP Repeater", "Request", "Response"}.issubset(labels)
        assert "Save Notes" not in {button.text() for button in page.findChildren(QPushButton)}
        assert "Send Request" in {button.text() for button in page.findChildren(QPushButton)}
        assert not page.findChildren(QTabWidget)
        assert not any(
            "Workspace notes" in edit.placeholderText()
            for edit in page.findChildren(QPlainTextEdit)
        )
        assert any(
            edit.placeholderText() == "Enter a raw HTTP request"
            for edit in page.findChildren(QPlainTextEdit)
        )
        assert stored[0].attack_workspace_id == created.attack_workspace_id
    finally:
        tab.close()


def test_attacker_tab_creates_browser_workspace_with_two_panes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    stored: list[AttackWorkspace] = []

    class FakeWebEngineView(QFrame):
        urlChanged = Signal(QUrl)

        def __init__(self, parent: QFrame | None = None) -> None:
            super().__init__(parent)
            self._url = QUrl()

        def setUrl(self, url: QUrl) -> None:  # noqa: N802
            self._url = QUrl(url)
            self.urlChanged.emit(self._url)

        def url(self) -> QUrl:
            return QUrl(self._url)

        def back(self) -> None:
            return

        def forward(self) -> None:
            return

        def reload(self) -> None:
            return

        def page(self) -> None:
            return None

    monkeypatch.setattr(attacker_tab_module, "QWebEngineView", FakeWebEngineView)

    def save_workspaces(_workspace_id: str, rows: list[AttackWorkspace]) -> None:
        stored.clear()
        stored.extend(rows)

    tab = AttackerTab(
        load_workspaces=lambda _workspace_id: list(stored),
        save_workspaces=save_workspaces,
    )
    snapshot = _make_snapshot(tmp_path)

    try:
        tab.set_workspace(snapshot.workspace_id)
        created = tab.add_workspace_from_asset("web_app", snapshot.web_apps[0], snapshot, "browser")

        assert created.workspace_type == "browser"
        assert len(created.sessions) == 2
        assert [session.session_type for session in created.sessions] == ["browser-pane", "browser-pane"]
        assert [session.metadata["automation_slot"] for session in created.sessions] == ["browser-1", "browser-2"]
        page = tab.workspace_tabs.widget(0)
        labels = {label.text() for label in page.findChildren(QLabel)}
        assert {"Browser", "Browser A", "Browser B"}.issubset(labels)
        assert len(page.findChildren(FakeWebEngineView)) == 2
        assert len([button for button in page.findChildren(QPushButton) if button.text() == "X"]) == 2
        splitters = [splitter for splitter in page.findChildren(QSplitter) if splitter.objectName() == "attackerBrowserSplit"]
        assert len(splitters) == 1
        assert splitters[0].orientation() == Qt.Vertical
        assert stored[0].attack_workspace_id == created.attack_workspace_id
    finally:
        tab.close()


def test_closing_both_browser_panes_closes_the_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    stored: list[AttackWorkspace] = []

    class FakeWebEngineView(QFrame):
        urlChanged = Signal(QUrl)

        def __init__(self, parent: QFrame | None = None) -> None:
            super().__init__(parent)
            self._url = QUrl()

        def setUrl(self, url: QUrl) -> None:  # noqa: N802
            self._url = QUrl(url)
            self.urlChanged.emit(self._url)

        def back(self) -> None:
            return

        def forward(self) -> None:
            return

        def reload(self) -> None:
            return

        def page(self) -> None:
            return None

    monkeypatch.setattr(attacker_tab_module, "QWebEngineView", FakeWebEngineView)

    def save_workspaces(_workspace_id: str, rows: list[AttackWorkspace]) -> None:
        stored.clear()
        stored.extend(rows)

    tab = AttackerTab(
        load_workspaces=lambda _workspace_id: list(stored),
        save_workspaces=save_workspaces,
    )

    try:
        tab.set_workspace("workspace-browser")
        workspace = tab.create_blank_workspace("browser")

        assert len(workspace.sessions) == 2
        first_session_id = workspace.sessions[0].session_id
        tab._close_browser_session(workspace, first_session_id)
        assert len(stored) == 1
        assert len(stored[0].sessions) == 1
        assert tab.workspace_tabs.count() == 1

        second_session_id = stored[0].sessions[0].session_id
        tab._close_browser_session(stored[0], second_session_id)
        assert stored == []
        assert tab.workspace_tabs.count() == 1
        assert tab.workspace_tabs.tabText(0) == "No Workspaces"
    finally:
        tab.close()


def test_http_replay_parser_accepts_absolute_and_relative_targets() -> None:
    method, url, headers, body = _parse_raw_http_request(
        "post /api/items HTTP/1.1\r\nHost: edge.example.com:443\r\nContent-Type: text/plain\r\n\r\nhello"
    )

    assert method == "POST"
    assert url == "https://edge.example.com:443/api/items"
    assert headers["Content-Type"] == "text/plain"
    assert body == b"hello"

    _method, absolute_url, _headers, _body = _parse_raw_http_request(
        "GET http://edge.example.com/status HTTP/1.1\nHost: ignored.example\n\n"
    )

    assert absolute_url == "http://edge.example.com/status"


def test_http_replay_response_format_includes_status_headers_and_body() -> None:
    formatted = _format_http_response(
        status_code=201,
        reason="Created",
        headers={"Content-Type": "text/plain"},
        body=b"created",
    )

    assert formatted == "HTTP/1.1 201 Created\nContent-Type: text/plain\n\ncreated"


def test_http_replay_execute_sends_request_and_returns_response() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"seen:" + body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f"127.0.0.1:{server.server_port}"
        response = _execute_http_request(
            f"POST /submit HTTP/1.1\nHost: {host}\nContent-Type: text/plain\nContent-Length: 4\n\nping"
        )
    finally:
        server.shutdown()
        server.server_close()

    assert "HTTP/1.1 202 Accepted" in response
    assert "Content-Type: text/plain" in response
    assert response.endswith("seen:ping")


def test_attacker_tab_exposes_only_supported_workspace_types() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab = AttackerTab(
        load_workspaces=lambda _workspace_id: [],
        save_workspaces=lambda _workspace_id, _rows: None,
    )

    try:
        assert tab.compatible_workspace_types("web_app") == ["http", "browser"]
        assert tab.compatible_workspace_types("asset") == []
        assert tab.browser_button.property("available") is True
        assert tab.metasploit_button.property("available") is False
        assert all(
            not any(label.objectName() == "attackerToolBadge" for label in card.findChildren(QLabel))
            for card in tab._tool_cards.values()
        )
        tab._tool_selected("metasploit")
        labels = {label.text() for label in tab.workspace_tabs.widget(0).findChildren(QLabel)}
        assert "Metasploit Check" in labels
        assert "Coming Soon" in labels
        assert tab.create_blank_workspace("metasploit").workspace_type == "http"
        assert tab.create_blank_workspace("sqlmap").workspace_type == "http"
        assert tab.create_blank_workspace("terminal").workspace_type == "http"
    finally:
        tab.close()


def test_assets_context_menu_exposes_send_to_attacker_when_callback_is_present(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    sent: list[tuple[str, str]] = []
    tab = AssetsTab(
        launch_scan=lambda _target, _label: None,
        load_notes=lambda _workspace_id: {},
        save_note=lambda _workspace_id, _note: None,
        send_to_attacker=lambda entity_kind, _row, _snapshot, workspace_type: sent.append((entity_kind, workspace_type)),
        attacker_action_types=lambda entity_kind: [("http", "HTTP Replay")]
        if entity_kind == "web_app"
        else [("metasploit", "Metasploit Check")],
    )
    snapshot = _make_snapshot(tmp_path)

    try:
        tab.set_snapshot(snapshot)
        app.processEvents()
        row = tab.web_apps_model.index(0, 0).data(Qt.UserRole)
        menu, _scan_action, _notes_action = tab._build_context_menu(tab.web_apps_view, "web_app", row)

        assert [action.text() for action in menu.actions()] == ["Scan Asset", "Send to Attacker", "Add Notes"]
        send_menu = menu.actions()[1].menu()
        assert send_menu is not None
        assert [action.text() for action in send_menu.actions()] == ["HTTP Replay"]
        assert send_menu.actions()[0].data()["workspace_type"] == "http"
    finally:
        tab.close()
