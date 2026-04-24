from __future__ import annotations

from dataclasses import dataclass
from threading import Thread
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request
from uuid import uuid4

from PySide6.QtCore import QObject, QPoint, Qt, QUrl, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.asset_inventory import entity_signature, row_label, scan_target_for_row
from attackcastle.gui.common import (
    PAGE_CARD_SPACING,
    PAGE_SECTION_SPACING,
    PANEL_CONTENT_PADDING,
    PersistentSplitterController,
    SURFACE_FLAT,
    SURFACE_PRIMARY,
    SURFACE_SECONDARY,
    apply_responsive_splitter,
    build_flat_container,
    build_inspector_panel,
    build_section_header,
    build_surface_frame,
    configure_scroll_surface,
    configure_tab_widget,
    refresh_widget_style,
    set_tooltip,
    style_button,
    title_case_label,
)
from attackcastle.gui.models import (
    AttackSession,
    AttackTargetObject,
    AttackWorkspace,
    RunSnapshot,
    now_iso,
)
from attackcastle.proxy import open_url

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
except ImportError:  # pragma: no cover - handled by fallback UI.
    QWebEngineView = None


HTTP_REPLAY_TIMEOUT_SECONDS = 30
HTTP_REPLAY_BODY_PREVIEW_BYTES = 1_000_000
BROWSER_DEFAULT_URL = "https://example.com/"


@dataclass(frozen=True)
class AttackerToolDefinition:
    key: str
    name: str
    workspace_label: str
    description: str
    session_type: str
    supported: frozenset[str]
    status: str
    enabled: bool = True


ATTACKER_TOOLS: tuple[AttackerToolDefinition, ...] = (
    AttackerToolDefinition(
        key="http",
        name="HTTP",
        workspace_label="HTTP Replay",
        description="",
        session_type="http-replay",
        supported=frozenset({"web_app", "endpoint", "parameter", "form", "login_surface", "site_map"}),
        status="",
    ),
    AttackerToolDefinition(
        key="browser",
        name="Browser",
        workspace_label="Browser",
        description="",
        session_type="browser-pane",
        supported=frozenset({"web_app", "endpoint", "parameter", "form", "login_surface", "site_map"}),
        status="",
    ),
    AttackerToolDefinition(
        key="metasploit",
        name="Metasploit",
        workspace_label="Metasploit Check",
        description="",
        session_type="metasploit-module",
        supported=frozenset({"asset", "service"}),
        status="Coming Soon",
        enabled=False,
    ),
)
ATTACKER_TOOL_LOOKUP = {tool.key: tool for tool in ATTACKER_TOOLS}
WORKSPACE_TYPES = {
    tool.key: {
        "label": tool.workspace_label,
        "session_type": tool.session_type,
        "supported": set(tool.supported),
    }
    for tool in ATTACKER_TOOLS
}
DISABLED_WORKSPACE_TYPES = {tool.key for tool in ATTACKER_TOOLS if not tool.enabled}


class _HttpReplayBridge(QObject):
    completed = Signal(str)


class AttackerToolCard(QFrame):
    selected = Signal(str)

    def __init__(self, tool: AttackerToolDefinition, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.tool = tool
        self.setObjectName("attackerToolCard")
        self.setProperty("active", False)
        self.setProperty("available", tool.enabled)
        self.setMinimumHeight(36)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, 5, PANEL_CONTENT_PADDING, 5)
        layout.setSpacing(3)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(8)
        name = QLabel(tool.name)
        name.setObjectName("attackerToolName")
        name.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        name.setWordWrap(False)
        header.addWidget(name, 1)

        layout.addLayout(header)
        if tool.description:
            description = QLabel(tool.description)
            description.setObjectName("attackerToolDescription")
            description.setWordWrap(True)
            layout.addWidget(description)
        tooltip_parts = [tool.name]
        if tool.description:
            tooltip_parts.append(tool.description)
        if tool.status:
            tooltip_parts.append(f"Status: {tool.status}")
        set_tooltip(self, ". ".join(tooltip_parts))

    def set_active(self, active: bool) -> None:
        self.setProperty("active", bool(active))
        refresh_widget_style(self)
        for label in self.findChildren(QLabel):
            refresh_widget_style(label)

    def mousePressEvent(self, event: Any) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.selected.emit(self.tool.key)
            event.accept()
            return
        super().mousePressEvent(event)


def _execute_http_request(raw_request: str, proxy_url: str = "") -> str:
    try:
        method, url, headers, body = _parse_raw_http_request(raw_request)
    except ValueError as exc:
        return f"Request error: {exc}"

    try:
        request = Request(
            url,
            data=body if body else None,
            headers=headers,
            method=method,
        )
        with open_url(request, timeout=HTTP_REPLAY_TIMEOUT_SECONDS, proxy_url=proxy_url) as response:
            return _format_http_response(
                status_code=response.status,
                reason=response.reason,
                headers=dict(response.headers.items()),
                body=response.read(HTTP_REPLAY_BODY_PREVIEW_BYTES + 1),
            )
    except HTTPError as exc:
        return _format_http_response(
            status_code=exc.code,
            reason=exc.reason,
            headers=dict(exc.headers.items()) if exc.headers is not None else {},
            body=exc.read(HTTP_REPLAY_BODY_PREVIEW_BYTES + 1),
        )
    except URLError as exc:
        return f"Request failed: {exc.reason}"
    except ValueError as exc:
        return f"Request failed: {exc}"
    except OSError as exc:
        return f"Request failed: {exc}"


def _parse_raw_http_request(raw_request: str) -> tuple[str, str, dict[str, str], bytes]:
    normalized = str(raw_request or "").replace("\r\n", "\n").replace("\r", "\n")
    head, separator, body_text = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise ValueError("enter a raw HTTP request first")

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("request line must look like 'GET /path HTTP/1.1'")

    method = parts[0].upper()
    target = parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, header_separator, value = line.partition(":")
        if not header_separator:
            raise ValueError(f"invalid header line: {line}")
        headers[name.strip()] = value.strip()

    url = _request_target_to_url(target, headers)
    body = body_text.encode("utf-8") if separator else b""
    return method, url, headers, body


def _request_target_to_url(target: str, headers: dict[str, str]) -> str:
    parsed = urlsplit(target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return target

    host = next((value for name, value in headers.items() if name.lower() == "host"), "")
    if not host:
        raise ValueError("relative request targets need a Host header")
    scheme = "https" if host.endswith(":443") else "http"
    path = target if target.startswith("/") else f"/{target}"
    return f"{scheme}://{host}{path}"


def _format_http_response(
    *,
    status_code: int,
    reason: str,
    headers: dict[str, str],
    body: bytes,
) -> str:
    truncated = len(body) > HTTP_REPLAY_BODY_PREVIEW_BYTES
    preview = body[:HTTP_REPLAY_BODY_PREVIEW_BYTES]
    header_lines = [f"HTTP/1.1 {status_code} {reason}".rstrip()]
    header_lines.extend(f"{name}: {value}" for name, value in headers.items())
    text = preview.decode("utf-8", errors="replace")
    if truncated:
        text += "\n\n[Response body truncated at 1 MB]"
    return "\n".join(header_lines) + "\n\n" + text


class AttackerTab(QWidget):
    def __init__(
        self,
        load_workspaces: Callable[[str], list[AttackWorkspace]],
        save_workspaces: Callable[[str, list[AttackWorkspace]], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("attackerCanvas")
        self.setProperty("surface", SURFACE_FLAT)
        self._load_workspaces = load_workspaces
        self._save_workspaces = save_workspaces
        self._workspace_id = ""
        self._proxy_url = ""
        self._snapshot: RunSnapshot | None = None
        self._workspaces: list[AttackWorkspace] = []
        self._active_attack_workspace_id = ""
        self._preview_tool_key = ""
        self._rendering = False
        self._http_replay_bridges: list[_HttpReplayBridge] = []
        self._browser_views: dict[str, Any] = {}
        self._tool_cards: dict[str, AttackerToolCard] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        self.main_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (1, 4))
        self.main_split_controller = PersistentSplitterController(
            self.main_split,
            "attacker_main_split",
            layout_loader,
            layout_saver,
            self,
        )

        tool_sidebar, tool_sidebar_layout = build_surface_frame(
            object_name="attackerToolSidebar",
            surface=SURFACE_PRIMARY,
            spacing=PAGE_CARD_SPACING,
        )
        tool_sidebar.setMinimumWidth(260)
        tool_sidebar.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        rail_title = QLabel("Attack Modules")
        rail_title.setObjectName("attackerRailTitle")
        tool_sidebar_layout.addWidget(rail_title)
        for tool in ATTACKER_TOOLS:
            card = AttackerToolCard(tool)
            card.selected.connect(self._tool_selected)
            self._tool_cards[tool.key] = card
            if tool.key == "http":
                self.http_button = card
            elif tool.key == "browser":
                self.browser_button = card
            elif tool.key == "metasploit":
                self.metasploit_button = card
            tool_sidebar_layout.addWidget(card)
        tool_sidebar_layout.addStretch(1)
        self.main_split.addWidget(tool_sidebar)

        self.workspace_tabs = QTabWidget()
        configure_tab_widget(self.workspace_tabs, role="group")
        self.workspace_tabs.setTabsClosable(True)
        self.workspace_tabs.setMovable(True)
        self.workspace_tabs.setUsesScrollButtons(True)
        self.workspace_tabs.currentChanged.connect(self._tab_changed)
        self.workspace_tabs.tabCloseRequested.connect(self._close_workspace_at)
        self.workspace_tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.workspace_tabs.tabBar().customContextMenuRequested.connect(self._open_tab_context_menu)
        set_tooltip(self.workspace_tabs.tabBar(), "Right-click a workspace tab to rename, duplicate, or close it.")

        workspace_shell, workspace_shell_layout = build_surface_frame(
            object_name="attackerWorkspaceShell",
            surface=SURFACE_PRIMARY,
            spacing=PAGE_SECTION_SPACING,
        )
        workspace_shell_layout.addWidget(self.workspace_tabs, 1)
        self.main_split.addWidget(workspace_shell)
        layout.addWidget(self.main_split, 1)
        self._render_workspaces()

    def set_proxy_url(self, proxy_url: str) -> None:
        self._proxy_url = str(proxy_url or "").strip()

    def set_workspace(self, workspace_id: str) -> None:
        workspace_id = str(workspace_id or "")
        if workspace_id == self._workspace_id:
            return
        self._workspace_id = workspace_id
        self._workspaces = self._load_workspaces(workspace_id)
        self._active_attack_workspace_id = self._workspaces[0].attack_workspace_id if self._workspaces else ""
        self._preview_tool_key = ""
        self._render_workspaces()

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot

    def sync_responsive_mode(self, width: int) -> None:
        self.main_split.setOrientation(Qt.Horizontal if width >= 1180 else Qt.Vertical)
        if width >= 1180:
            self.main_split_controller.apply([max(int(width * 0.18), 250), max(int(width * 0.82), 880)])
        else:
            self.main_split_controller.apply([170, max(int(self.height() * 0.74), 420)])

    def create_blank_workspace(self, workspace_type: str = "http") -> AttackWorkspace:
        workspace_type = workspace_type if self._workspace_type_enabled(workspace_type) else "http"
        self._preview_tool_key = ""
        label = WORKSPACE_TYPES[workspace_type]["label"]
        workspace = AttackWorkspace(
            attack_workspace_id=f"attack-{uuid4().hex}",
            name=f"{label} {len(self._workspaces) + 1}",
            workspace_type=workspace_type,
            sessions=self._initial_sessions_for_workspace(workspace_type),
        )
        self._workspaces.append(workspace)
        self._active_attack_workspace_id = workspace.attack_workspace_id
        self._persist()
        self._render_workspaces()
        return workspace

    def _tool_selected(self, workspace_type: str) -> None:
        if self._workspace_type_enabled(workspace_type):
            self.create_blank_workspace(workspace_type)
            return
        self._preview_tool_key = workspace_type if workspace_type in WORKSPACE_TYPES else ""
        self._render_workspaces()

    def add_workspace_from_asset(
        self,
        entity_kind: str,
        row: dict[str, Any],
        snapshot: RunSnapshot | None,
        workspace_type: str = "http",
    ) -> AttackWorkspace:
        workspace_type = workspace_type if self._workspace_type_enabled(workspace_type) else "http"
        target = self._target_from_row(entity_kind, row, snapshot)
        name = self._workspace_name_for_target(workspace_type, target)
        workspace = AttackWorkspace(
            attack_workspace_id=f"attack-{uuid4().hex}",
            name=name,
            workspace_type=workspace_type,
            target_objects=[target],
            sessions=self._initial_sessions_for_workspace(workspace_type, target=target),
            status="draft",
        )
        self._workspaces.append(workspace)
        self._active_attack_workspace_id = workspace.attack_workspace_id
        self._persist()
        self._render_workspaces()
        return workspace

    def compatible_workspace_types(self, entity_kind: str) -> list[str]:
        normalized = str(entity_kind or "").strip()
        compatible = [
            key
            for key, config in WORKSPACE_TYPES.items()
            if self._workspace_type_enabled(key) and normalized in config["supported"]
        ]
        return compatible

    def _workspace_type_enabled(self, workspace_type: str) -> bool:
        return workspace_type in WORKSPACE_TYPES and workspace_type not in DISABLED_WORKSPACE_TYPES

    def _target_from_row(
        self,
        entity_kind: str,
        row: dict[str, Any],
        snapshot: RunSnapshot | None,
    ) -> AttackTargetObject:
        label = str(row.get("__label") or "")
        target = str(row.get("__target") or "")
        signature = str(row.get("__signature") or "")
        if snapshot is not None:
            label = label or row_label(entity_kind, row, snapshot)
            target = target or scan_target_for_row(entity_kind, row, snapshot)
            signature = signature or entity_signature(entity_kind, row, snapshot)
        return AttackTargetObject(
            target_object_id=f"target-{uuid4().hex}",
            entity_kind=str(entity_kind or row.get("__entity_kind") or "asset"),
            label=label or title_case_label(entity_kind),
            target=target,
            signature=signature,
            source_run_id=snapshot.run_id if snapshot is not None else "",
            data={
                key: value
                for key, value in row.items()
                if not str(key).startswith("__")
            },
        )

    def _workspace_name_for_target(self, workspace_type: str, target: AttackTargetObject) -> str:
        prefix = WORKSPACE_TYPES[workspace_type]["label"]
        label = target.target or target.label or title_case_label(target.entity_kind)
        return f"{label} - {prefix}"

    def _initial_sessions_for_workspace(
        self,
        workspace_type: str,
        target: AttackTargetObject | None = None,
    ) -> list[AttackSession]:
        if workspace_type == "browser":
            home_url = self._browser_seed_url(target)
            return [
                self._new_session(workspace_type, target=target, pane_index=0, home_url=home_url),
                self._new_session(workspace_type, target=target, pane_index=1, home_url=home_url),
            ]
        return [self._new_session(workspace_type, target=target)]

    def _new_session(
        self,
        workspace_type: str,
        target: AttackTargetObject | None = None,
        *,
        pane_index: int = 0,
        home_url: str = "",
    ) -> AttackSession:
        config = WORKSPACE_TYPES.get(workspace_type, WORKSPACE_TYPES["http"])
        session_type = config["session_type"]
        label = config["label"]
        command = ""
        request = ""
        metadata: dict[str, Any] = {}
        if workspace_type == "metasploit":
            command = "msfconsole -qx \"use auxiliary/scanner/; set RHOSTS <target>; check; exit\""
        elif workspace_type == "http":
            target_value = target.target if target is not None else "https://example.com/"
            request = f"GET {target_value} HTTP/1.1\nHost: {target_value.replace('https://', '').replace('http://', '').split('/')[0]}\n\n"
        elif workspace_type == "browser":
            request = home_url or self._browser_seed_url(target)
            label = f"Browser {'AB'[pane_index] if pane_index in {0, 1} else pane_index + 1}"
            metadata = {
                "pane_index": pane_index,
                "browser_id": f"browser-{uuid4().hex}",
                "automation_slot": f"browser-{pane_index + 1}",
                "home_url": request,
                "current_url": request,
            }
        return AttackSession(
            session_id=f"session-{uuid4().hex}",
            session_type=session_type,
            label=label,
            command=command,
            request=request,
            metadata=metadata,
        )

    def _browser_seed_url(self, target: AttackTargetObject | None) -> str:
        if target is None:
            return BROWSER_DEFAULT_URL
        raw_target = str(target.target or target.label or "").strip()
        if not raw_target:
            return BROWSER_DEFAULT_URL
        return self._normalize_browser_url(raw_target)

    def _normalize_browser_url(self, raw_url: str) -> str:
        text = str(raw_url or "").strip()
        if not text:
            return BROWSER_DEFAULT_URL
        normalized = QUrl.fromUserInput(text).toString()
        return normalized or text

    def _persist(self) -> None:
        for workspace in self._workspaces:
            workspace.updated_at = now_iso()
        self._save_workspaces(self._workspace_id, self._workspaces)

    def _render_workspaces(self) -> None:
        self._rendering = True
        try:
            self._browser_views.clear()
            while self.workspace_tabs.count():
                widget = self.workspace_tabs.widget(0)
                self.workspace_tabs.removeTab(0)
                widget.deleteLater()
            if self._preview_tool_key and not self._workspace_type_enabled(self._preview_tool_key):
                self.workspace_tabs.setTabsClosable(False)
                self.workspace_tabs.addTab(
                    self._build_unavailable_tool_page(self._preview_tool_key),
                    WORKSPACE_TYPES.get(self._preview_tool_key, WORKSPACE_TYPES["http"])["label"],
                )
                return
            if not self._workspaces:
                self.workspace_tabs.setTabsClosable(False)
                empty = self._build_empty_state()
                self.workspace_tabs.addTab(empty, "No Workspaces")
                return
            self.workspace_tabs.setTabsClosable(True)
            for index, workspace in enumerate(self._workspaces, start=1):
                self.workspace_tabs.addTab(
                    self._build_workspace_page(workspace),
                    f"{index} {workspace.name}",
                )
            active_index = self._index_for_workspace_id(self._active_attack_workspace_id)
            self.workspace_tabs.setCurrentIndex(max(active_index, 0))
        finally:
            self._rendering = False
            self._sync_tool_navigation()

    def _build_empty_state(self) -> QWidget:
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)
        empty_panel, empty_layout = build_surface_frame(
            object_name="attackerEmptyState",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )
        header, _title, summary = build_section_header(
            "No Attack Workspace Open",
            summary="Start with the HTTP module, open a Browser workspace, or send an asset from the inventory for focused validation.",
        )
        summary.setVisible(True)
        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(PAGE_CARD_SPACING)

        create_http = QPushButton("New HTTP Repeater")
        create_http.setObjectName("attackerPrimaryAction")
        style_button(create_http, min_height=34)
        create_http.clicked.connect(lambda _checked=False: self.create_blank_workspace("http"))
        create_browser = QPushButton("New Browser")
        style_button(create_browser, role="secondary", min_height=34)
        create_browser.clicked.connect(lambda _checked=False: self.create_blank_workspace("browser"))
        empty_layout.addWidget(header)
        actions.addWidget(create_http, 0)
        actions.addWidget(create_browser, 0)
        actions.addStretch(1)
        empty_layout.addLayout(actions)
        layout.addWidget(empty_panel)
        layout.addStretch(1)
        return page

    def _build_unavailable_tool_page(self, workspace_type: str) -> QWidget:
        tool = ATTACKER_TOOL_LOOKUP.get(workspace_type, ATTACKER_TOOL_LOOKUP["http"])
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        panel, panel_layout = build_surface_frame(
            object_name="attackerComingSoonPanel",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(PAGE_CARD_SPACING)
        title_stack = QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(4)
        title = QLabel(tool.workspace_label)
        title.setObjectName("attackerWorkspaceTitle")
        subtitle = QLabel(tool.description)
        subtitle.setObjectName("attackerWorkspaceSubtitle")
        subtitle.setWordWrap(True)
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        badge = QLabel(tool.status)
        badge.setObjectName("attackerToolBadge")
        badge.setProperty("state", "coming-soon")
        header.addLayout(title_stack, 1)
        header.addWidget(badge, 0, Qt.AlignTop | Qt.AlignRight)
        panel_layout.addLayout(header)

        body = QLabel("Metasploit module checks are not implemented yet. This slot is reserved for msf-backed validation once the runtime checks and safety controls exist.")
        body.setObjectName("attackerComingSoonText")
        body.setWordWrap(True)
        panel_layout.addWidget(body)
        layout.addWidget(panel)
        layout.addStretch(1)
        return page

    def _build_workspace_page(self, workspace: AttackWorkspace) -> QWidget:
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)
        layout.addWidget(self._build_work_panel(workspace), 1)
        return page

    def _build_work_panel(self, workspace: AttackWorkspace) -> QWidget:
        if workspace.workspace_type == "http":
            sessions = workspace.sessions or [self._new_session(workspace.workspace_type)]
            return self._build_http_workspace(workspace, sessions[0])
        if workspace.workspace_type == "browser":
            sessions = workspace.sessions or self._initial_sessions_for_workspace(
                workspace.workspace_type,
                workspace.target_objects[0] if workspace.target_objects else None,
            )
            return self._build_browser_workspace(workspace, sessions[:2])

        body = build_flat_container()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        header = QHBoxLayout()
        title = QLabel(workspace.name)
        title.setObjectName("sectionTitle")
        header.addWidget(title, 1)
        status_combo = QComboBox()
        status_combo.addItems(["draft", "running", "completed"])
        status_combo.setCurrentText(workspace.status if workspace.status in {"draft", "running", "completed"} else "draft")
        status_combo.currentTextChanged.connect(lambda value, item=workspace: self._set_workspace_status(item, value))
        header.addWidget(status_combo)
        layout.addLayout(header)

        session_tabs = QTabWidget()
        configure_tab_widget(session_tabs, role="inspector")
        for session in workspace.sessions or [self._new_session(workspace.workspace_type)]:
            session_tabs.addTab(self._build_session_editor(workspace, session), session.label or title_case_label(session.session_type))
        layout.addWidget(session_tabs, 1)

        panel, _title, helper = build_inspector_panel(
            WORKSPACE_TYPES.get(workspace.workspace_type, WORKSPACE_TYPES["http"])["label"],
            body,
            summary_text="Run structured checks or replay requests against the selected target.",
        )
        helper.setVisible(True)
        return panel

    def _build_browser_workspace(self, workspace: AttackWorkspace, sessions: list[AttackSession]) -> QWidget:
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        layout.addWidget(self._build_browser_header(workspace, sessions))

        if len(sessions) > 1:
            browser_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (1, 1), handle_width=4)
            browser_split.setObjectName("attackerBrowserSplit")
            for index, session in enumerate(sessions):
                browser_split.addWidget(self._build_browser_panel(workspace, session, index))
            browser_split.setSizes([400, 400])
            layout.addWidget(browser_split, 1)
        elif sessions:
            layout.addWidget(self._build_browser_panel(workspace, sessions[0], 0), 1)
        else:
            layout.addWidget(QLabel("No browser panes are open."), 0, Qt.AlignCenter)
        return page

    def _build_browser_header(self, workspace: AttackWorkspace, sessions: list[AttackSession]) -> QWidget:
        header, header_layout = build_surface_frame(
            object_name="attackerToolHeader",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(PAGE_SECTION_SPACING * 2)

        title_stack = QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(4)
        title = QLabel("Browser")
        title.setObjectName("attackerWorkspaceTitle")
        title_stack.addWidget(title)

        context_row = QHBoxLayout()
        context_row.setContentsMargins(0, 0, 0, 0)
        context_row.setSpacing(PAGE_CARD_SPACING)
        for text, state in (
            (self._browser_target_label(workspace, sessions), "target"),
            (f"{len(sessions)} pane{'s' if len(sessions) != 1 else ''} open", "neutral"),
            (workspace.status.title() if workspace.status else "Draft", workspace.status or "draft"),
        ):
            context_row.addWidget(self._build_pill(text, state))
        context_row.addStretch(1)
        title_stack.addLayout(context_row)

        helper = QLabel("Each pane keeps its own session identity so future automation can bind to a stable browser target.")
        helper.setObjectName("attackerPanelHelper")
        helper.setWordWrap(True)
        title_stack.addWidget(helper)

        row.addLayout(title_stack, 1)
        header_layout.addLayout(row)
        return header

    def _build_browser_panel(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        pane_index: int,
    ) -> QWidget:
        current_url = self._browser_session_url(session)
        session.metadata = {
            **session.metadata,
            "pane_index": session.metadata.get("pane_index", pane_index),
            "automation_slot": session.metadata.get("automation_slot", f"browser-{pane_index + 1}"),
            "browser_id": session.metadata.get("browser_id") or f"browser-{uuid4().hex}",
            "home_url": session.metadata.get("home_url") or current_url,
            "current_url": current_url,
        }

        panel, panel_layout = build_surface_frame(
            object_name="attackerBrowserPanel",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(PAGE_CARD_SPACING)
        title_stack = QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(2)
        title_label = QLabel(session.label or f"Browser {pane_index + 1}")
        title_label.setObjectName("attackerPanelTitle")
        helper_label = QLabel(f"Automation slot: {session.metadata['automation_slot']}")
        helper_label.setObjectName("attackerPanelHelper")
        helper_label.setWordWrap(True)
        title_stack.addWidget(title_label)
        title_stack.addWidget(helper_label)
        header.addLayout(title_stack, 1)

        close_button = QPushButton("X")
        close_button.setObjectName("attackerBrowserCloseButton")
        style_button(close_button, role="secondary", min_height=30)
        set_tooltip(close_button, "Close this browser pane. Closing both panes removes the Browser module.")
        close_button.clicked.connect(
            lambda _checked=False, item=workspace, session_id=session.session_id: self._close_browser_session(item, session_id)
        )
        header.addWidget(close_button, 0, Qt.AlignRight | Qt.AlignTop)
        panel_layout.addLayout(header)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(PAGE_CARD_SPACING)
        back_button = QPushButton("<")
        forward_button = QPushButton(">")
        reload_button = QPushButton("Reload")
        go_button = QPushButton("Go")
        for button in (back_button, forward_button, reload_button):
            style_button(button, role="secondary", min_height=30)
        style_button(go_button, min_height=30)
        address = QLineEdit(current_url)
        address.setObjectName("attackerBrowserAddress")
        address.setPlaceholderText("Enter a URL")
        controls.addWidget(back_button, 0)
        controls.addWidget(forward_button, 0)
        controls.addWidget(reload_button, 0)
        controls.addWidget(address, 1)
        controls.addWidget(go_button, 0)
        panel_layout.addLayout(controls)

        if QWebEngineView is None:
            fallback = QLabel(
                "Qt WebEngine is unavailable in this environment, so the browser pane cannot render yet. "
                "The pane still preserves its URL and automation metadata."
            )
            fallback.setWordWrap(True)
            fallback.setAlignment(Qt.AlignCenter)
            fallback.setObjectName("attackerComingSoonText")
            panel_layout.addWidget(fallback, 1)
            back_button.setEnabled(False)
            forward_button.setEnabled(False)
            reload_button.setEnabled(False)
            go_button.clicked.connect(
                lambda _checked=False, item=workspace, sess=session, field=address, index=pane_index: self._save_browser_session_state(
                    item,
                    sess,
                    field.text(),
                    index,
                )
            )
            address.returnPressed.connect(go_button.click)
            return panel

        browser = QWebEngineView()
        browser.setObjectName("attackerBrowserView")
        browser.setProperty("attackWorkspaceId", workspace.attack_workspace_id)
        browser.setProperty("attackSessionId", session.session_id)
        self._browser_views[session.session_id] = browser

        def navigate() -> None:
            target_url = self._save_browser_session_state(workspace, session, address.text(), pane_index)
            browser.setUrl(QUrl.fromUserInput(target_url))

        def sync_address(url: QUrl) -> None:
            normalized = url.toString()
            if normalized:
                address.setText(normalized)
                self._save_browser_session_state(workspace, session, normalized, pane_index)

        browser.urlChanged.connect(sync_address)
        back_button.clicked.connect(browser.back)
        forward_button.clicked.connect(browser.forward)
        reload_button.clicked.connect(browser.reload)
        go_button.clicked.connect(navigate)
        address.returnPressed.connect(navigate)
        browser.setUrl(QUrl.fromUserInput(current_url))
        panel_layout.addWidget(browser, 1)
        return panel

    def _build_http_workspace(self, workspace: AttackWorkspace, session: AttackSession) -> QWidget:
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        request = configure_scroll_surface(QPlainTextEdit())
        request.setObjectName("attackerConsoleText")
        request.setPlainText(session.request)
        request.setPlaceholderText("Enter a raw HTTP request")

        response = configure_scroll_surface(QPlainTextEdit())
        response.setObjectName("attackerConsoleText")
        response.setReadOnly(True)
        response.setPlainText(session.response)
        response.setPlaceholderText("HTTP response")

        send_request = QPushButton("Send Request")
        send_request.setObjectName("attackerPrimaryAction")
        style_button(send_request, min_height=34)
        send_request.clicked.connect(
            lambda _checked=False, item=workspace, sess=session, req=request, resp=response, button=send_request: self._send_http_session(
                item,
                sess,
                req.toPlainText(),
                resp,
                button,
            )
        )

        layout.addWidget(self._build_http_header(workspace, session, send_request))

        editor_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (3, 2), handle_width=4)
        editor_split.setObjectName("attackerHttpEditorSplit")
        editor_split.addWidget(
            self._build_http_editor_panel(
                "Request",
                "",
                request,
                metadata=self._request_metadata(session.request),
            )
        )
        editor_split.addWidget(
            self._build_http_editor_panel(
                "Response",
                "",
                response,
                metadata=self._response_metadata(session.response),
            )
        )
        editor_split.setSizes([420, 320])
        layout.addWidget(editor_split, 1)
        return page

    def _build_http_header(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        send_request: QPushButton,
    ) -> QWidget:
        header, header_layout = build_surface_frame(
            object_name="attackerToolHeader",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(PAGE_SECTION_SPACING * 2)

        title_stack = QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(4)
        title = QLabel("HTTP Repeater")
        title.setObjectName("attackerWorkspaceTitle")
        title_stack.addWidget(title)

        context_row = QHBoxLayout()
        context_row.setContentsMargins(0, 0, 0, 0)
        context_row.setSpacing(PAGE_CARD_SPACING)
        for text, state in (
            (self._workspace_target_label(workspace, session), "target"),
            (self._http_method_label(session.request), "method"),
            (workspace.status.title() if workspace.status else "Draft", workspace.status or "draft"),
        ):
            context_row.addWidget(self._build_pill(text, state))
        context_row.addStretch(1)
        title_stack.addLayout(context_row)

        row.addLayout(title_stack, 1)
        row.addWidget(send_request, 0, Qt.AlignRight | Qt.AlignVCenter)
        header_layout.addLayout(row)
        return header

    def _build_http_editor_panel(
        self,
        title: str,
        helper: str,
        editor: QWidget,
        *,
        metadata: str = "",
    ) -> QWidget:
        panel, panel_layout = build_surface_frame(
            object_name="attackerEditorPanel",
            surface=SURFACE_SECONDARY,
            spacing=PAGE_CARD_SPACING,
        )
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(PAGE_CARD_SPACING)
        title_label = QLabel(title)
        title_label.setObjectName("attackerPanelTitle")
        title_stack = QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(2)
        title_stack.addWidget(title_label)
        if helper:
            helper_label = QLabel(helper)
            helper_label.setObjectName("attackerPanelHelper")
            helper_label.setWordWrap(True)
            title_stack.addWidget(helper_label)
        header.addLayout(title_stack, 1)
        if metadata:
            meta = QLabel(metadata)
            meta.setObjectName("attackerPanelMeta")
            header.addWidget(meta, 0, Qt.AlignRight | Qt.AlignTop)
        panel_layout.addLayout(header)
        panel_layout.addWidget(editor, 1)
        return panel

    def _build_session_editor(self, workspace: AttackWorkspace, session: AttackSession) -> QWidget:
        page = build_flat_container()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        if session.session_type == "http-replay":
            request = configure_scroll_surface(QPlainTextEdit())
            request.setObjectName("consoleText")
            request.setPlainText(session.request)
            request.setPlaceholderText("Raw HTTP request")
            response = configure_scroll_surface(QPlainTextEdit())
            response.setObjectName("consoleText")
            response.setPlainText(session.response)
            response.setPlaceholderText("HTTP response")
            layout.addWidget(QLabel("Request"))
            layout.addWidget(request, 2)
            layout.addWidget(QLabel("Response"))
            layout.addWidget(response, 2)
            send_request = QPushButton("Send Request")
            style_button(send_request)
            send_request.clicked.connect(
                lambda _checked=False, item=workspace, sess=session, req=request, resp=response, button=send_request: self._send_http_session(
                    item,
                    sess,
                    req.toPlainText(),
                    resp,
                    button,
                )
            )
            layout.addWidget(send_request)
            return page

        form = QFormLayout()
        command = QLineEdit()
        command.setText(session.command)
        command.setPlaceholderText("Command or tool sequence")
        output = configure_scroll_surface(QPlainTextEdit())
        output.setObjectName("consoleText")
        output.setPlainText(session.response)
        output.setPlaceholderText("Paste command output or tool result here")
        form.addRow("Command", command)
        layout.addLayout(form)
        layout.addWidget(output, 1)
        save_session = QPushButton("Save Tool Output")
        style_button(save_session)
        save_session.clicked.connect(
            lambda _checked=False, item=workspace, sess=session, cmd=command, out=output: self._save_tool_session(
                item,
                sess,
                cmd.text(),
                out.toPlainText(),
            )
        )
        layout.addWidget(save_session)
        return page

    def _build_pill(self, text: str, state: str = "") -> QLabel:
        pill = QLabel(text or "--")
        pill.setObjectName("attackerPill")
        pill.setProperty("state", state or "neutral")
        pill.setAlignment(Qt.AlignCenter)
        return pill

    def _browser_session_url(self, session: AttackSession) -> str:
        metadata_url = str(session.metadata.get("current_url") or session.metadata.get("home_url") or "").strip()
        if metadata_url:
            return self._normalize_browser_url(metadata_url)
        return self._normalize_browser_url(session.request or BROWSER_DEFAULT_URL)

    def _browser_target_label(self, workspace: AttackWorkspace, sessions: list[AttackSession]) -> str:
        target = next((item.target or item.label for item in workspace.target_objects if item.target or item.label), "")
        if target:
            return target
        if sessions:
            return self._browser_session_url(sessions[0])
        return "No target"

    def _save_browser_session_state(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        raw_url: str,
        pane_index: int,
    ) -> str:
        normalized = self._normalize_browser_url(raw_url)
        session.request = normalized
        session.updated_at = now_iso()
        session.metadata = {
            **session.metadata,
            "pane_index": pane_index,
            "automation_slot": session.metadata.get("automation_slot", f"browser-{pane_index + 1}"),
            "browser_id": session.metadata.get("browser_id") or f"browser-{uuid4().hex}",
            "home_url": session.metadata.get("home_url") or normalized,
            "current_url": normalized,
        }
        self._persist()
        return normalized

    def _close_browser_session(self, workspace: AttackWorkspace, session_id: str) -> None:
        remaining = [session for session in workspace.sessions if session.session_id != session_id]
        if len(remaining) == len(workspace.sessions):
            return
        self._browser_views.pop(session_id, None)
        if not remaining:
            index = self._index_for_workspace_id(workspace.attack_workspace_id)
            if index >= 0:
                self._close_workspace_at(index)
            return
        workspace.sessions = remaining
        self._persist_and_refresh(workspace.attack_workspace_id)

    def browser_automation_targets(self, attack_workspace_id: str = "") -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        for workspace in self._workspaces:
            if attack_workspace_id and workspace.attack_workspace_id != attack_workspace_id:
                continue
            for session in workspace.sessions:
                if session.session_type != "browser-pane":
                    continue
                view = self._browser_views.get(session.session_id)
                targets.append(
                    {
                        "attack_workspace_id": workspace.attack_workspace_id,
                        "session_id": session.session_id,
                        "browser_id": session.metadata.get("browser_id", ""),
                        "automation_slot": session.metadata.get("automation_slot", ""),
                        "url": self._browser_session_url(session),
                        "view": view,
                        "page": view.page() if view is not None and hasattr(view, "page") else None,
                    }
                )
        return targets

    def _workspace_target_label(self, workspace: AttackWorkspace, session: AttackSession) -> str:
        target = next((item.target or item.label for item in workspace.target_objects if item.target or item.label), "")
        if target:
            return target
        try:
            _method, url, _headers, _body = _parse_raw_http_request(session.request)
        except ValueError:
            return "No target"
        parsed = urlsplit(url)
        return parsed.netloc or url or "No target"

    def _http_method_label(self, raw_request: str) -> str:
        first_line = str(raw_request or "").strip().splitlines()[0:1]
        if not first_line:
            return "METHOD"
        method = first_line[0].split()[0:1]
        return method[0].upper() if method else "METHOD"

    def _request_metadata(self, raw_request: str) -> str:
        line_count = len([line for line in str(raw_request or "").splitlines() if line.strip()])
        method = self._http_method_label(raw_request)
        return f"{method} / {line_count} lines" if line_count else "Empty request"

    def _response_metadata(self, raw_response: str) -> str:
        text = str(raw_response or "")
        if not text.strip():
            return "Waiting"
        first_line = text.strip().splitlines()[0]
        return first_line[:72]

    def _sync_tool_navigation(self) -> None:
        active_type = self._preview_tool_key
        if not active_type:
            active_workspace = self._workspace_at(self._index_for_workspace_id(self._active_attack_workspace_id))
            active_type = active_workspace.workspace_type if active_workspace is not None else "http"
        for key, card in self._tool_cards.items():
            card.set_active(key == active_type)

    def _save_http_session(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        request: str,
        response: str,
    ) -> None:
        session.request = request
        session.response = response
        session.updated_at = now_iso()
        workspace.status = "completed"
        self._persist_and_refresh(workspace.attack_workspace_id)

    def _send_http_session(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        request: str,
        response_editor: QPlainTextEdit,
        send_button: QPushButton,
    ) -> None:
        session.request = request
        session.updated_at = now_iso()
        workspace.status = "running"
        self._persist()
        response_editor.setPlainText("Sending request...")
        send_button.setEnabled(False)
        send_button.setText("Sending...")

        bridge = _HttpReplayBridge(self)
        self._http_replay_bridges.append(bridge)

        def finish(response_text: str) -> None:
            if bridge in self._http_replay_bridges:
                self._http_replay_bridges.remove(bridge)
            response_editor.setPlainText(response_text)
            send_button.setEnabled(True)
            send_button.setText("Send Request")
            self._save_http_session(workspace, session, request, response_text)

        bridge.completed.connect(finish)

        def worker() -> None:
            bridge.completed.emit(_execute_http_request(request, self._proxy_url))

        Thread(target=worker, daemon=True).start()

    def _save_tool_session(
        self,
        workspace: AttackWorkspace,
        session: AttackSession,
        command: str,
        output: str,
    ) -> None:
        session.command = command
        session.response = output
        session.updated_at = now_iso()
        workspace.status = "completed"
        self._persist_and_refresh(workspace.attack_workspace_id)

    def _set_workspace_status(self, workspace: AttackWorkspace, status: str) -> None:
        if self._rendering:
            return
        workspace.status = status
        self._persist()

    def _persist_and_refresh(self, active_id: str) -> None:
        self._active_attack_workspace_id = active_id
        self._persist()
        self._render_workspaces()

    def _tab_changed(self, index: int) -> None:
        if self._rendering:
            return
        if 0 <= index < len(self._workspaces):
            self._preview_tool_key = ""
            self._active_attack_workspace_id = self._workspaces[index].attack_workspace_id
            self._sync_tool_navigation()

    def _index_for_workspace_id(self, attack_workspace_id: str) -> int:
        for index, workspace in enumerate(self._workspaces):
            if workspace.attack_workspace_id == attack_workspace_id:
                return index
        return -1

    def _workspace_at(self, index: int) -> AttackWorkspace | None:
        if 0 <= index < len(self._workspaces):
            return self._workspaces[index]
        return None

    def _open_tab_context_menu(self, point: QPoint) -> None:
        index = self.workspace_tabs.tabBar().tabAt(point)
        workspace = self._workspace_at(index)
        if workspace is None:
            return
        menu = QMenu(self)
        rename_action = menu.addAction("Rename")
        duplicate_action = menu.addAction("Duplicate")
        close_action = menu.addAction("Close")
        action = menu.exec(self.workspace_tabs.tabBar().mapToGlobal(point))
        if action is rename_action:
            self._rename_workspace(workspace)
        elif action is duplicate_action:
            self._duplicate_workspace(workspace)
        elif action is close_action:
            self._close_workspace_at(index)

    def _rename_workspace(self, workspace: AttackWorkspace) -> None:
        name, accepted = QInputDialog.getText(self, "Rename Attack Workspace", "Name", text=workspace.name)
        if not accepted:
            return
        name = name.strip()
        if not name:
            return
        workspace.name = name
        self._persist_and_refresh(workspace.attack_workspace_id)

    def _duplicate_workspace(self, workspace: AttackWorkspace) -> None:
        cloned = AttackWorkspace.from_dict(workspace.to_dict())
        cloned.attack_workspace_id = f"attack-{uuid4().hex}"
        cloned.name = f"{workspace.name} Copy"
        cloned.created_at = now_iso()
        cloned.updated_at = cloned.created_at
        self._workspaces.append(cloned)
        self._persist_and_refresh(cloned.attack_workspace_id)

    def _close_workspace_at(self, index: int) -> None:
        workspace = self._workspace_at(index)
        if workspace is None:
            return
        self._workspaces = [
            item
            for item in self._workspaces
            if item.attack_workspace_id != workspace.attack_workspace_id
        ]
        self._active_attack_workspace_id = self._workspaces[min(index, len(self._workspaces) - 1)].attack_workspace_id if self._workspaces else ""
        self._persist()
        self._render_workspaces()
