from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    apply_form_layout_defaults,
    build_flat_container,
    configure_tab_widget,
    configure_scroll_surface,
    refresh_widget_style,
    set_tooltip,
    set_tooltips,
    size_dialog_to_screen,
    style_button,
    title_case_label,
)
from attackcastle.gui.extensions import ExtensionRecord
from attackcastle.gui.forms import ProfileFieldsMixin
from attackcastle.gui.runtime import profile_to_engine_overrides, write_yaml_like_json
from attackcastle.gui.models import GuiProfile, ScanRequest, Workspace, now_iso
from attackcastle.readiness import ReadinessReport, assess_readiness
from attackcastle.gui.workspace_store import NO_WORKSPACE_SCOPE_ID, WorkspaceStore, ad_hoc_output_home


class WorkspaceDialog(QDialog):
    def __init__(self, workspace: Workspace | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Project")
        self.setModal(True)
        self.setMinimumSize(560, 520)
        size_dialog_to_screen(self, default_width=760, default_height=720, min_width=560, min_height=520)
        self._workspace = workspace

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        content_scroll = configure_scroll_surface(QScrollArea())
        content_scroll.setWidgetResizable(True)
        content_scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(content_scroll, 1)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 6, 0)
        content_layout.setSpacing(14)
        content_scroll.setWidget(content)

        helper = QLabel("Create a project with a name, path, client, and scope.")
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        content_layout.addWidget(helper)

        self.validation_label = QLabel("Enter a project name before saving.")
        self.validation_label.setObjectName("attentionBanner")
        self.validation_label.setProperty("tone", "neutral")
        self.validation_label.setWordWrap(True)
        content_layout.addWidget(self.validation_label)

        form = QFormLayout()
        apply_form_layout_defaults(form)
        self.name_edit = QLineEdit()
        self.home_dir_edit = QLineEdit()
        self.client_edit = QLineEdit()
        self.scope_edit = configure_scroll_surface(QPlainTextEdit())
        self.scope_edit.setMinimumHeight(78)
        set_tooltips(
            (
                (self.name_edit, "Name the project as you want it to appear throughout the GUI."),
                (self.home_dir_edit, "Choose the home directory where project-scoped data should live."),
                (self.client_edit, "Record the client or engagement owner for this project."),
                (self.scope_edit, "Paste a short scope summary or engagement notes for this project."),
            )
        )
        form.addRow("Project Name", self.name_edit)
        form.addRow("Project Path", self.home_dir_edit)
        form.addRow("Client Name", self.client_edit)
        form.addRow("Scope", self.scope_edit)
        content_layout.addLayout(form)

        self.name_edit.textChanged.connect(self._refresh_validation)
        self.scope_edit.textChanged.connect(self._refresh_validation)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        if buttons.button(QDialogButtonBox.Ok) is not None:
            style_button(buttons.button(QDialogButtonBox.Ok))
        if buttons.button(QDialogButtonBox.Cancel) is not None:
            style_button(buttons.button(QDialogButtonBox.Cancel), role="secondary")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if workspace is not None:
            self.name_edit.setText(workspace.name)
            self.home_dir_edit.setText(workspace.home_dir)
            self.client_edit.setText(workspace.client_name)
            self.scope_edit.setPlainText(workspace.scope_summary)
        self._refresh_validation()

    def _refresh_validation(self) -> None:
        missing_name = not self.name_edit.text().strip()
        missing_scope = not self.scope_edit.toPlainText().strip()
        if missing_name:
            self.validation_label.setText("Add a project name before saving.")
            self.validation_label.setProperty("tone", "warning")
        elif missing_scope:
            self.validation_label.setText("Scope is empty. You can save now, but the project brief will stay incomplete.")
            self.validation_label.setProperty("tone", "neutral")
        else:
            self.validation_label.setText("Ready to save. The project will be available from startup selection and the project editor.")
            self.validation_label.setProperty("tone", "ok")
        refresh_widget_style(self.validation_label)

    def build_workspace(self) -> Workspace:
        existing = self._workspace
        workspace_id = existing.workspace_id if existing is not None else f"ws_{now_iso().replace(':', '').replace('-', '')[-12:]}"
        return Workspace(
            workspace_id=workspace_id,
            name=self.name_edit.text().strip() or "Untitled Project",
            home_dir=self.home_dir_edit.text().strip() or f"./output/{workspace_id}",
            client_name=self.client_edit.text().strip(),
            scope_summary=self.scope_edit.toPlainText().strip(),
            created_at=existing.created_at if existing is not None else now_iso(),
            last_opened_at=existing.last_opened_at if existing is not None else "",
            updated_at=now_iso(),
        )

    def accept(self) -> None:
        if not self.name_edit.text().strip():
            self.validation_label.setText("Add a project name before saving.")
            self.validation_label.setProperty("tone", "warning")
            refresh_widget_style(self.validation_label)
            self.name_edit.setFocus()
            return
        super().accept()


class DebugLogDialog(QDialog):
    def __init__(
        self,
        title: str,
        overview_text: str,
        combined_log_text: str,
        current_task_text: str,
        *,
        current_task_title: str = "Current Task",
        initial_tab: int = 0,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(False)
        self.setMinimumSize(760, 600)
        size_dialog_to_screen(self, default_width=1220, default_height=860, min_width=760, min_height=600)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        helper = QLabel("Read-only debug details for the selected run. Text includes persisted command lines and captured file output when available.")
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        layout.addWidget(helper)

        self.tabs = QTabWidget()
        configure_tab_widget(self.tabs, role="group")
        layout.addWidget(self.tabs, 1)

        self.overview_text = self._build_text_tab(overview_text)
        self.combined_log_text = self._build_text_tab(combined_log_text)
        self.current_task_text = self._build_text_tab(current_task_text)
        self.tabs.addTab(self.overview_text, "Overview")
        self.tabs.addTab(self.combined_log_text, "Combined Log")
        self.tabs.addTab(self.current_task_text, current_task_title)
        self.tabs.setCurrentIndex(max(0, min(initial_tab, self.tabs.count() - 1)))

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Close).clicked.connect(self.close)
        if buttons.button(QDialogButtonBox.Close) is not None:
            style_button(buttons.button(QDialogButtonBox.Close), role="secondary")
        layout.addWidget(buttons)

    def _build_text_tab(self, text: str) -> QWidget:
        container = build_flat_container()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        editor = configure_scroll_surface(QPlainTextEdit())
        editor.setObjectName("consoleText")
        editor.setReadOnly(True)
        editor.setPlainText(text)
        container_layout.addWidget(editor)
        return container


class StartScanDialog(QDialog, ProfileFieldsMixin):
    def __init__(
        self,
        profiles: list[GuiProfile],
        workspace: Workspace | list[Workspace] | None,
        available_extensions: list[ExtensionRecord] | None = None,
        selected_engagement_id: str | QWidget = "",
        prefill_scan_name: str = "",
        prefill_target_input: str = "",
        preferred_profile_name: str = "",
        parent: QWidget | None = None,
    ) -> None:
        if isinstance(available_extensions, str):
            selected_engagement_id = available_extensions
            available_extensions = None
        if isinstance(available_extensions, QWidget) and parent is None and not isinstance(selected_engagement_id, QWidget):
            parent = available_extensions
            available_extensions = None
        if isinstance(selected_engagement_id, QWidget) and parent is None:
            parent = selected_engagement_id
            selected_engagement_id = ""
        super().__init__(parent)
        self.setWindowTitle("Launch Scan")
        self.setModal(True)
        self.setMinimumSize(760, 620)
        size_dialog_to_screen(self, default_width=1080, default_height=900, min_width=760, min_height=620)
        self._profiles = profiles
        if isinstance(workspace, list):
            selected = None
            for item in workspace:
                if item.workspace_id == selected_engagement_id or item.engagement_id == selected_engagement_id:
                    selected = item
                    break
            self._workspace = selected or (workspace[0] if workspace else None)
        else:
            self._workspace = workspace
        self._advanced_visible = False
        self._scope_text = self._workspace.scope_summary.strip() if self._workspace is not None else ""
        self._scope_appended = False
        self._available_extensions = [item for item in (available_extensions or []) if item.manifest is not None]
        self._readiness_report: ReadinessReport | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        content_scroll = configure_scroll_surface(QScrollArea())
        content_scroll.setWidgetResizable(True)
        content_scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(content_scroll, 1)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 6, 0)
        content_layout.setSpacing(14)
        content_scroll.setWidget(content)

        helper = QLabel("Start with the essentials, then open advanced overrides only when the session needs extra tuning.")
        helper.setWordWrap(True)
        helper.setObjectName("helperText")
        content_layout.addWidget(helper)

        self.scan_name_edit = QLineEdit()
        self.scan_name_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.target_input_edit = configure_scroll_surface(QPlainTextEdit())
        self.target_input_edit.setMinimumHeight(110)
        self.target_input_edit.setPlaceholderText("example.com\n203.0.113.0/24\nhttps://portal.example.com")
        self.profile_picker = QComboBox()
        self.use_scope_checkbox = QCheckBox("Use scope")
        self.use_scope_checkbox.toggled.connect(self._use_scope_toggled)
        self.scope_status_label = QLabel("")
        self.scope_status_label.setObjectName("helperText")
        self.scope_status_label.setWordWrap(True)

        for profile in profiles:
            self.profile_picker.addItem(profile.name)
        self.profile_picker.currentIndexChanged.connect(self._profile_changed)
        set_tooltips(
            (
                (self.scan_name_edit, "Give this run a clear name so it is easy to find later."),
                (self.profile_picker, "Choose a saved GUI profile to prefill scan defaults."),
                (self.target_input_edit, "Enter one target per line, such as domains, URLs, IPs, or CIDRs."),
                (self.use_scope_checkbox, "Append the current project scope text into Target Input one time for this launch."),
            )
        )
        target_input_panel = QWidget()
        target_input_layout = QVBoxLayout(target_input_panel)
        target_input_layout.setContentsMargins(0, 0, 0, 0)
        target_input_layout.setSpacing(8)
        target_input_layout.addWidget(self.target_input_edit)
        target_input_layout.addWidget(self.use_scope_checkbox)
        target_input_layout.addWidget(self.scope_status_label)

        essentials = QGroupBox("Launch Essentials")
        essentials_layout = QFormLayout(essentials)
        essentials_layout.setContentsMargins(16, 16, 16, 16)
        apply_form_layout_defaults(essentials_layout)
        essentials_layout.addRow("Scan Name", self.scan_name_edit)
        essentials_layout.addRow("Profile", self.profile_picker)
        essentials_layout.addRow("Target Input", target_input_panel)
        content_layout.addWidget(essentials)

        self.profile_description_label = QLabel("")
        self.profile_description_label.setObjectName("infoBanner")
        self.profile_description_label.setWordWrap(True)
        content_layout.addWidget(self.profile_description_label)

        self.launch_summary = QLabel("")
        self.launch_summary.setWordWrap(True)
        self.launch_summary.setObjectName("attentionBanner")
        self.launch_summary.setProperty("tone", "neutral")
        content_layout.addWidget(self.launch_summary)
        self.readiness_label = QLabel("")
        self.readiness_label.setObjectName("attentionBanner")
        self.readiness_label.setProperty("tone", "neutral")
        self.readiness_label.setWordWrap(True)
        content_layout.addWidget(self.readiness_label)
        self.launch_validation_label = QLabel("")
        self.launch_validation_label.setObjectName("helperText")
        self.launch_validation_label.setWordWrap(True)
        content_layout.addWidget(self.launch_validation_label)

        extension_group = QGroupBox("GUI Extensions")
        extension_layout = QVBoxLayout(extension_group)
        extension_layout.setContentsMargins(16, 16, 16, 16)
        extension_layout.setSpacing(10)
        extension_helper = QLabel("Select enabled GUI-only command hook extensions to run after the core scan and before report generation.")
        extension_helper.setObjectName("helperText")
        extension_helper.setWordWrap(True)
        self.extension_list = configure_scroll_surface(QListWidget())
        self.extension_list.setObjectName("sidebarList")
        self.extension_list.setMinimumHeight(120)
        self.extension_empty_label = QLabel("")
        self.extension_empty_label.setObjectName("helperText")
        self.extension_empty_label.setWordWrap(True)
        set_tooltips(
            (
                (self.extension_list, "Enable command hook extensions that should run for this scan."),
            )
        )
        extension_layout.addWidget(extension_helper)
        extension_layout.addWidget(self.extension_list)
        extension_layout.addWidget(self.extension_empty_label)
        content_layout.addWidget(extension_group)
        self._populate_extensions()

        self.advanced_toggle = QPushButton("Show Advanced Overrides")
        self.advanced_toggle.setCheckable(True)
        style_button(self.advanced_toggle, role="secondary")
        self.advanced_toggle.toggled.connect(self._toggle_advanced_options)
        set_tooltip(self.advanced_toggle, "Show or hide the full advanced profile override form for this launch.")
        content_layout.addWidget(self.advanced_toggle, 0, Qt.AlignLeft)

        frame = QFrame()
        frame.setObjectName("subtlePanel")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.addWidget(
            self._profile_form(
                include_identity=False,
                collapsible_sections=True,
                preset_header="Scan Presets",
                preset_helper="Choose a workstation preset to align tool coverage and defaults before touching expert overrides.",
            )
        )
        self.advanced_scroll = frame
        self.advanced_scroll.setVisible(False)
        self.advanced_scroll.setMinimumHeight(0)
        content_layout.addWidget(self.advanced_scroll)

        self.target_input_edit.textChanged.connect(self._refresh_launch_summary)
        self.output_dir_edit.textChanged.connect(self._refresh_launch_summary)
        self.rate_mode_combo.currentTextChanged.connect(self._refresh_launch_summary)
        self.risk_mode_combo.currentTextChanged.connect(self._refresh_launch_summary)
        self.proxy_enabled_checkbox.toggled.connect(self._refresh_launch_summary)
        self.proxy_url_edit.textChanged.connect(self._refresh_launch_summary)
        self.enable_sqlmap.toggled.connect(self._refresh_launch_summary)
        self.enable_nuclei.toggled.connect(self._refresh_launch_summary)
        self.enable_nmap.toggled.connect(self._refresh_launch_summary)
        self.enable_wpscan.toggled.connect(self._refresh_launch_summary)
        self.endpoint_wordlist_edit.textChanged.connect(self._refresh_launch_summary)
        self.parameter_wordlist_edit.textChanged.connect(self._refresh_launch_summary)
        self.payload_wordlist_edit.textChanged.connect(self._refresh_launch_summary)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        if buttons.button(QDialogButtonBox.Ok) is not None:
            style_button(buttons.button(QDialogButtonBox.Ok))
        if buttons.button(QDialogButtonBox.Cancel) is not None:
            style_button(buttons.button(QDialogButtonBox.Cancel), role="secondary")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if profiles:
            self._apply_profile_to_form(profiles[0])
            self.scan_name_edit.setText(f"{profiles[0].name} Scan")
        else:
            self.profile_name_edit.setText("Custom Profile")
        self.output_dir_edit.setText(self._session_home_dir())
        self.output_dir_edit.setReadOnly(True)
        set_tooltip(self.output_dir_edit, "This run writes into the active project home directory or the ad-hoc session directory.")
        for button in self.findChildren(QPushButton):
            if button.text() == "Browse":
                button.hide()
        self._sync_scope_controls()
        if preferred_profile_name:
            for index, profile in enumerate(self._profiles):
                if profile.name == preferred_profile_name:
                    self.profile_picker.setCurrentIndex(index)
                    break
        if prefill_scan_name.strip():
            self.scan_name_edit.setText(prefill_scan_name.strip())
        if prefill_target_input.strip():
            self.target_input_edit.setPlainText(prefill_target_input.strip())
        self._refresh_profile_description()
        self._refresh_launch_summary()
        self.sync_profile_form_width(self.width())

    def _populate_extensions(self) -> None:
        self.extension_list.clear()
        if not self._available_extensions:
            self.extension_empty_label.setText("No enabled command hook extensions are installed yet. Theme extensions continue to work from the main Extensions page.")
            self.extension_list.setEnabled(False)
            return
        self.extension_empty_label.setText("Unchecked means the extension stays installed but will not run for this scan.")
        self.extension_list.setEnabled(True)
        for record in self._available_extensions:
            item = QListWidgetItem(f"{record.display_name} | {', '.join(record.capabilities)}")
            item.setData(Qt.UserRole, record.extension_id)
            item.setCheckState(Qt.Unchecked)
            if record.manifest is not None:
                item.setToolTip(record.manifest.description or record.extension_id)
            self.extension_list.addItem(item)
        self.extension_list.itemChanged.connect(lambda _item: self._refresh_launch_summary())

    def _profile_changed(self, index: int) -> None:
        if 0 <= index < len(self._profiles):
            profile = self._profiles[index]
            self._apply_profile_to_form(profile, preserve_manual_overrides=True)
            self.profile_name_edit.setText(profile.name)
            self.description_edit.setText(profile.description)
            if not self.scan_name_edit.text().strip():
                self.scan_name_edit.setText(f"{profile.name} Scan")
        self._refresh_profile_description()
        self._refresh_launch_summary()

    def _session_home_dir(self) -> str:
        return self._workspace.home_dir if self._workspace is not None else ad_hoc_output_home()

    def _sync_scope_controls(self) -> None:
        has_scope = bool(self._scope_text)
        self.use_scope_checkbox.blockSignals(True)
        self.use_scope_checkbox.setChecked(False)
        self.use_scope_checkbox.setEnabled(has_scope)
        self.use_scope_checkbox.blockSignals(False)
        if has_scope:
            summary = self._workspace.name if self._workspace is not None else "project"
            self.scope_status_label.setText(f"Append the saved scope from {summary} into Target Input.")
        else:
            self.scope_status_label.setText("No saved project scope is available for this launch.")

    def _use_scope_toggled(self, checked: bool) -> None:
        if not checked or not self._scope_text:
            return
        if self._scope_appended:
            self.scope_status_label.setText("Project scope was already appended to Target Input for this launch.")
            return
        existing = self.target_input_edit.toPlainText().strip()
        pieces = [piece for piece in (existing, self._scope_text) if piece]
        self.target_input_edit.setPlainText("\n\n".join(pieces))
        self._scope_appended = True
        self.scope_status_label.setText("Project scope appended to Target Input.")
        self._refresh_launch_summary()

    def _refresh_profile_description(self) -> None:
        if not self._profiles:
            self.profile_description_label.setText("No saved GUI profiles are available yet. Start with a scan preset and tune overrides if needed.")
            return
        index = self.profile_picker.currentIndex()
        if not (0 <= index < len(self._profiles)):
            self.profile_description_label.setText("Select a profile to see its default posture and recommended use.")
            return
        profile = self._profiles[index]
        description = profile.description or "Custom profile with no description yet."
        self.profile_description_label.setText(
            f"{profile.name}: {description} | Base posture: {title_case_label(profile.base_profile)} | Stored risk mode: {title_case_label(profile.risk_mode)}"
        )

    def _toggle_advanced_options(self, visible: bool) -> None:
        self._advanced_visible = visible
        self.advanced_scroll.setVisible(visible)
        self.advanced_toggle.setText("Hide Advanced Overrides" if visible else "Show Advanced Overrides")

    def _validation_issues(self) -> list[str]:
        issues: list[str] = []
        if not self.target_input_edit.toPlainText().strip():
            issues.append("Add at least one target before launching.")
        if not self.scan_name_edit.text().strip():
            issues.append("Give the scan a name so it is easy to find later.")
        if self.proxy_enabled_checkbox.isChecked() and not self.proxy_url_edit.text().strip():
            issues.append("Add a proxy URL or disable proxy routing.")
        return issues

    def _enabled_tools(self) -> list[str]:
        return [
            name
            for name, checkbox in (
                ("subfinder", self.enable_subfinder),
                ("dnsx", self.enable_dnsx),
                ("dig / host", self.enable_dig_host),
                ("nmap", self.enable_nmap),
                ("httpx", self.enable_web_probe),
                ("openssl", self.enable_openssl_tls),
                ("whatweb", self.enable_whatweb),
                ("nikto", self.enable_nikto),
                ("nuclei", self.enable_nuclei),
                ("wpscan", self.enable_wpscan),
                ("sqlmap", self.enable_sqlmap),
            )
            if checkbox.isChecked()
        ]

    def _build_readiness_report(self) -> ReadinessReport | None:
        target_input = self.target_input_edit.toPlainText().strip()
        if not target_input:
            return None
        profile = self._profile_from_form()
        profile.name = self.profile_picker.currentText() or profile.name
        profile.output_directory = self._session_home_dir()
        temp_dir = Path(tempfile.mkdtemp(prefix="attackcastle-gui-readiness-"))
        try:
            override_path = write_yaml_like_json(
                temp_dir / "gui_profile_override.yaml",
                profile_to_engine_overrides(profile),
            )
            return assess_readiness(
                target_input=target_input,
                profile=profile.base_profile,
                user_config_path=str(override_path),
                risk_mode=profile.risk_mode,
                proxy_url=profile.proxy_url.strip() if profile.proxy_enabled else None,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _refresh_readiness_banner(self) -> None:
        report = self._readiness_report
        if report is None:
            self.readiness_label.setText("Readiness will appear here once target input is present.")
            self.readiness_label.setProperty("tone", "neutral")
            refresh_widget_style(self.readiness_label)
            return
        tone = {
            "ready": "ok",
            "partial": "warning",
            "blocked": "alert",
        }.get(report.status, "neutral")
        impact = []
        for entry in report.tool_impact[:3]:
            labels = [str(item) for item in entry.get("task_labels", []) if str(item).strip()]
            if labels:
                impact.append(f"{entry.get('tool')}: {', '.join(labels[:2])}")
        impact_text = f" Impact: {'; '.join(impact)}." if impact else ""
        self.readiness_label.setText(
            f"Readiness: {title_case_label(report.status)} | Can launch: {'yes' if report.can_launch else 'no'}"
            f" | Missing tools: {', '.join(report.missing_tools) or 'none'}."
            f"{impact_text}"
        )
        self.readiness_label.setProperty("tone", tone)
        refresh_widget_style(self.readiness_label)

    def _refresh_launch_summary(self) -> None:
        targets = [line.strip() for line in self.target_input_edit.toPlainText().splitlines() if line.strip()]
        warnings: list[str] = []
        if self.risk_mode_combo.currentText() == "aggressive":
            warnings.append("aggressive risk mode")
        if self.active_validation_mode_combo.currentText() == "aggressive":
            warnings.append("aggressive active validation")
        if self.rate_mode_combo.currentText() == "aggressive":
            warnings.append("aggressive rate mode")
        if self.enable_sqlmap.isChecked():
            warnings.append("sqlmap enabled")
        wordlists = [
            label
            for label, value in (
                ("endpoint", self.endpoint_wordlist_edit.text().strip()),
                ("parameter", self.parameter_wordlist_edit.text().strip()),
                ("payload", self.payload_wordlist_edit.text().strip()),
            )
            if value
        ]
        proxy_text = self.proxy_url_edit.text().strip() if self.proxy_enabled_checkbox.isChecked() else "disabled"
        issues = self._validation_issues()
        tools_text = ", ".join(self._enabled_tools()[:6]) + (" ..." if len(self._enabled_tools()) > 6 else "")
        validation_mode = self.active_validation_mode_combo.currentText()
        validation_behavior = (
            "Queue only"
            if validation_mode == "passive"
            else "Low-risk replay auto-runs"
            if validation_mode == "safe-active"
            else "Replay plus aggressive probes auto-run"
        )
        selected_extensions = self._selected_extension_ids()
        self._readiness_report = self._build_readiness_report()
        self.launch_summary.setText(
            "<b>Launch Snapshot</b><br>"
            f"Targets: {len(targets)} | Profile: {self.profile_picker.currentText() or self.profile_name_edit.text().strip() or 'Custom'}<br>"
            f"Risk: {title_case_label(self.risk_mode_combo.currentText())} | Rate: {title_case_label(self.rate_mode_combo.currentText())} | Output: {self.output_dir_edit.text().strip() or './output'}<br>"
            f"Active Validation: {title_case_label(validation_mode)} | Replay: {'enabled' if self.request_replay_enabled_checkbox.isChecked() else 'disabled'} | Budget: {self.validation_budget_spin.value()} per target | {validation_behavior}<br>"
            f"Proxy: {proxy_text or 'disabled'}<br>"
            f"Coverage: {tools_text or 'none enabled'}<br>"
            f"Extensions: {', '.join(selected_extensions) if selected_extensions else 'none selected'}<br>"
            f"Wordlists: {', '.join(wordlists) if wordlists else 'none selected'}"
        )
        tone = "alert" if warnings else "neutral"
        if self._readiness_report is not None:
            tone = {
                "ready": tone,
                "partial": "warning",
                "blocked": "alert",
            }.get(self._readiness_report.status, tone)
        if issues:
            tone = "warning"
        self.launch_summary.setProperty("tone", tone)
        refresh_widget_style(self.launch_summary)
        self._refresh_readiness_banner()
        if issues:
            self.launch_validation_label.setText("Before launch: " + " ".join(issues))
        elif self._readiness_report is not None and not self._readiness_report.can_launch:
            self.launch_validation_label.setText(
                self._readiness_report.recommended_actions[0]
                if self._readiness_report.recommended_actions
                else "Readiness checks blocked this launch."
            )
        elif self._readiness_report is not None and self._readiness_report.partial_run:
            self.launch_validation_label.setText(
                self._readiness_report.recommended_actions[0]
                if self._readiness_report.recommended_actions
                else "Launch will proceed with reduced tool coverage."
            )
        elif warnings:
            self.launch_validation_label.setText("Elevated options selected. AttackCastle will ask for confirmation before launch.")
        else:
            self.launch_validation_label.setText("Ready to launch. Advanced overrides stay available for experienced operators, but the essentials are already complete.")

    def build_request(self) -> ScanRequest:
        profile = self._profile_from_form()
        profile.name = self.profile_picker.currentText() or self._active_recipe_name or self.profile_name_edit.text().strip() or "Custom Profile"
        profile.output_directory = self._session_home_dir()
        return ScanRequest(
            scan_name=self.scan_name_edit.text().strip() or "Untitled Scan",
            target_input=self.target_input_edit.toPlainText().strip(),
            profile=profile,
            output_directory=self._session_home_dir(),
            workspace_id=self._workspace.workspace_id if self._workspace is not None else "",
            workspace_name=self._workspace.name if self._workspace is not None else "",
            enabled_extension_ids=self._selected_extension_ids(),
        )

    def _selected_extension_ids(self) -> list[str]:
        selected: list[str] = []
        for index in range(self.extension_list.count()):
            item = self.extension_list.item(index)
            if item.checkState() == Qt.Checked:
                selected.append(str(item.data(Qt.UserRole) or ""))
        return [item for item in selected if item]

    def accept(self) -> None:
        issues = self._validation_issues()
        if issues:
            self.launch_summary.setProperty("tone", "warning")
            refresh_widget_style(self.launch_summary)
            self.launch_validation_label.setText("Before launch: " + " ".join(issues))
            if not self.scan_name_edit.text().strip():
                self.scan_name_edit.setFocus()
            elif not self.target_input_edit.toPlainText().strip():
                self.target_input_edit.setFocus()
            return
        if self._readiness_report is not None and not self._readiness_report.can_launch:
            self.launch_summary.setProperty("tone", "alert")
            refresh_widget_style(self.launch_summary)
            self.launch_validation_label.setText(
                self._readiness_report.recommended_actions[0]
                if self._readiness_report.recommended_actions
                else "Readiness checks blocked this launch."
            )
            self.target_input_edit.setFocus()
            return
        if (
            self.risk_mode_combo.currentText() == "aggressive"
            or self.active_validation_mode_combo.currentText() == "aggressive"
            or self.enable_sqlmap.isChecked()
        ):
            decision = QMessageBox.question(
                self,
                "Confirm Elevated Risk",
                "This launch includes more aggressive options. Confirm the engagement authorizes them before continuing.",
            )
            if decision != QMessageBox.Yes:
                return
        super().accept()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_profile_form_width(max(self.width() - 120, 0))


class WorkspaceChooserDialog(QDialog):
    def __init__(
        self,
        workspaces: list[Workspace],
        selected_workspace_id: str = "",
        workspace_store: WorkspaceStore | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Open Project")
        self.setModal(True)
        self.setMinimumSize(560, 420)
        size_dialog_to_screen(self, default_width=760, default_height=640, min_width=560, min_height=420)
        self._workspaces = workspaces
        self._workspace_store = workspace_store
        self._launch_action = "cancel"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        self.helper_label = QLabel("")
        self.helper_label.setObjectName("helperText")
        self.helper_label.setWordWrap(True)
        layout.addWidget(self.helper_label)

        self.workspace_list = configure_scroll_surface(QListWidget())
        set_tooltip(self.workspace_list, "Choose which saved project should become the active context for this GUI session.")
        layout.addWidget(self.workspace_list, 1)

        self.empty_state_label = QLabel("")
        self.empty_state_label.setObjectName("infoBanner")
        self.empty_state_label.setWordWrap(True)
        layout.addWidget(self.empty_state_label)

        self.detail_label = QLabel("")
        self.detail_label.setObjectName("infoBanner")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

        self.workspace_list.currentRowChanged.connect(self._selection_changed)
        action_row = QHBoxLayout()
        self.open_button = QPushButton("Open Project")
        self.create_button = QPushButton("Create Project")
        self.no_workspace_button = QPushButton("Launch Without a Project")
        cancel_button = QPushButton("Cancel")
        self.open_button.clicked.connect(self._open_selected_workspace)
        self.create_button.clicked.connect(self._create_workspace)
        self.no_workspace_button.clicked.connect(self._launch_without_workspace)
        cancel_button.clicked.connect(self.reject)
        style_button(self.open_button)
        style_button(self.create_button, role="secondary")
        style_button(self.no_workspace_button, role="secondary")
        style_button(cancel_button, role="secondary")
        set_tooltips(
            (
                (self.open_button, "Open the selected project and make it the active session context."),
                (self.create_button, "Create a new project before entering the main GUI."),
                (self.no_workspace_button, "Start the GUI in ad-hoc mode without binding the session to a project."),
                (cancel_button, "Close the chooser without opening the main GUI."),
            )
        )
        action_row.addWidget(self.open_button)
        action_row.addWidget(self.create_button)
        action_row.addWidget(self.no_workspace_button)
        action_row.addStretch(1)
        action_row.addWidget(cancel_button)
        layout.addLayout(action_row)
        self._reload_workspaces(selected_workspace_id)

    def _reload_workspaces(self, selected_workspace_id: str = "") -> None:
        self.workspace_list.blockSignals(True)
        self.workspace_list.clear()
        if self._workspace_store is not None:
            self._workspaces = self._workspace_store.load_workspaces()
        for workspace in self._workspaces:
            subtitle = workspace.client_name or "No client"
            item = QListWidgetItem(f"{workspace.name} | {subtitle}")
            item.setData(Qt.UserRole, workspace.workspace_id)
            self.workspace_list.addItem(item)
        self.workspace_list.blockSignals(False)
        if self._workspaces:
            index = 0
            for idx, workspace in enumerate(self._workspaces):
                if workspace.workspace_id == selected_workspace_id:
                    index = idx
                    break
            self.workspace_list.setCurrentRow(index)
        else:
            self.workspace_list.setCurrentRow(-1)
        self._refresh_state()

    def _selection_changed(self, row: int) -> None:
        self._refresh_state(row)

    def _refresh_state(self, row: int | None = None) -> None:
        has_workspaces = bool(self._workspaces)
        self.helper_label.setText(
            "Choose a project for this GUI session, create a new one, or launch the app without a project."
        )
        self.workspace_list.setVisible(has_workspaces)
        self.empty_state_label.setVisible(not has_workspaces)
        if not has_workspaces:
            self.empty_state_label.setText(
                "Projects are saved contexts. Create one for an engagement, or launch without a project for ad-hoc work."
            )
            self.detail_label.setText("No saved projects yet.")
            self.open_button.setEnabled(False)
            return
        current_row = self.workspace_list.currentRow() if row is None else row
        self.empty_state_label.clear()
        self.open_button.setEnabled(0 <= current_row < len(self._workspaces))
        if not (0 <= current_row < len(self._workspaces)):
            self.detail_label.setText("Select a project to continue.")
            return
        workspace = self._workspaces[current_row]
        self.detail_label.setText(
            f"{workspace.name}\nClient: {workspace.client_name or 'Unassigned'}\nHome: {workspace.home_dir}"
        )

    def selected_workspace_id(self) -> str:
        item = self.workspace_list.currentItem()
        return str(item.data(Qt.UserRole) or "") if item is not None else ""

    def launch_action(self) -> str:
        return self._launch_action

    def _open_selected_workspace(self) -> None:
        if not self.selected_workspace_id():
            self.detail_label.setText("Select a project to continue.")
            return
        self._launch_action = "open_workspace"
        super().accept()

    def _create_workspace(self) -> None:
        dialog = WorkspaceDialog(parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        workspace = dialog.build_workspace()
        if self._workspace_store is not None:
            self._workspace_store.save_workspace(workspace)
        else:
            self._workspaces = [item for item in self._workspaces if item.workspace_id != workspace.workspace_id] + [workspace]
            self._workspaces.sort(key=lambda item: item.name.lower())
        self._reload_workspaces(workspace.workspace_id)
        self.detail_label.setText(f"Created project {workspace.name}. Select Open Project to continue, or launch without a project.")

    def _launch_without_workspace(self) -> None:
        self._launch_action = "launch_without_workspace"
        super().accept()


class WorkspaceMigrationDialog(QDialog):
    def __init__(
        self,
        workspaces: list[Workspace],
        import_roots: list[str],
        pending_runs: list[dict[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Migrate Legacy Projects")
        self.setModal(True)
        self.setMinimumSize(720, 520)
        size_dialog_to_screen(self, default_width=920, default_height=760, min_width=720, min_height=520)
        self._workspaces = workspaces
        self._pending_combos: dict[str, QComboBox] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        helper = QLabel(
            "AttackCastle found legacy engagement-based GUI data. Assign every discovered legacy run to a project before continuing."
        )
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        layout.addWidget(helper)

        summary = QLabel(
            f"Projects prepared: {len(workspaces)} | Legacy runs requiring review: {len(pending_runs)}"
        )
        summary.setObjectName("infoBanner")
        summary.setWordWrap(True)
        layout.addWidget(summary)

        roots_label = QLabel("Import roots:\n" + ("\n".join(import_roots) if import_roots else "(none detected)"))
        roots_label.setObjectName("helperText")
        roots_label.setWordWrap(True)
        layout.addWidget(roots_label)

        scroll = configure_scroll_surface(QScrollArea())
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(scroll, 1)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 6, 0)
        content_layout.setSpacing(10)
        scroll.setWidget(content)

        for run_info in pending_runs:
            run_dir = run_info.get("run_dir", "")
            guessed = run_info.get("workspace_id", "")
            panel = QFrame()
            panel.setObjectName("subtlePanel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(12, 12, 12, 12)
            panel_layout.setSpacing(8)
            title = QLabel(run_info.get("scan_name") or Path(run_dir).name)
            title.setObjectName("sectionTitle")
            detail = QLabel(f"Run: {run_dir}")
            detail.setObjectName("helperText")
            detail.setWordWrap(True)
            combo = QComboBox()
            for workspace in workspaces:
                combo.addItem(workspace.name, workspace.workspace_id)
            combo.addItem("No Project (Ad-Hoc Session)", NO_WORKSPACE_SCOPE_ID)
            combo_index = combo.findData(guessed)
            fallback_index = combo.findData(NO_WORKSPACE_SCOPE_ID) if not workspaces else 0
            combo.setCurrentIndex(combo_index if combo_index >= 0 else fallback_index)
            set_tooltip(combo, "Assign this legacy run to the project that should own its findings, audit, and run history.")
            panel_layout.addWidget(title)
            panel_layout.addWidget(detail)
            panel_layout.addWidget(combo)
            content_layout.addWidget(panel)
            self._pending_combos[run_dir] = combo

        self.validation_label = QLabel("")
        self.validation_label.setObjectName("attentionBanner")
        self.validation_label.setProperty("tone", "neutral")
        self.validation_label.setWordWrap(True)
        layout.addWidget(self.validation_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._refresh_validation()

    def _refresh_validation(self) -> None:
        unresolved = [path for path, combo in self._pending_combos.items() if not str(combo.currentData() or "")]
        if unresolved:
            self.validation_label.setText("Assign every legacy run to a project before continuing.")
            self.validation_label.setProperty("tone", "warning")
        else:
            self.validation_label.setText("Migration assignments are complete.")
            self.validation_label.setProperty("tone", "ok")
        refresh_widget_style(self.validation_label)

    def selected_assignments(self) -> dict[str, str]:
        return {path: str(combo.currentData() or "") for path, combo in self._pending_combos.items()}

    def accept(self) -> None:
        self._refresh_validation()
        if any(not workspace_id for workspace_id in self.selected_assignments().values()):
            return
        super().accept()


EngagementDialog = WorkspaceDialog
