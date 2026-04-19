from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import Card, FlowButtonRow, PAGE_CARD_SPACING, PANEL_CONTENT_PADDING, set_tooltip, set_tooltips
from attackcastle.gui.common import apply_form_layout_defaults, style_button
from attackcastle.gui.models import GuiProfile


PROFILE_RECIPES: dict[str, dict[str, object]] = {
    "Recon": {
        "description": "Low-noise discovery posture for early external scoping and infrastructure mapping.",
        "base_profile": "cautious",
        "concurrency": 3,
        "cpu_cores": 0,
        "max_ports": 800,
        "delay_ms_between_requests": 200,
        "rate_limit_mode": "careful",
        "risk_mode": "safe-active",
        "adaptive_execution_enabled": True,
        "enable_nmap": True,
        "enable_web_probe": True,
        "enable_whatweb": True,
        "enable_nikto": False,
        "enable_nuclei": False,
        "enable_wpscan": False,
        "enable_sqlmap": False,
        "export_html_report": True,
        "export_json_data": True,
    },
    "Web": {
        "description": "Balanced web-application posture with discovery, fingerprinting, and safe validation.",
        "base_profile": "standard",
        "concurrency": 4,
        "cpu_cores": 0,
        "max_ports": 1000,
        "delay_ms_between_requests": 100,
        "rate_limit_mode": "balanced",
        "risk_mode": "safe-active",
        "adaptive_execution_enabled": True,
        "enable_nmap": True,
        "enable_web_probe": True,
        "enable_whatweb": True,
        "enable_nikto": True,
        "enable_nuclei": True,
        "enable_wpscan": False,
        "enable_sqlmap": False,
        "export_html_report": True,
        "export_json_data": True,
    },
    "WordPress": {
        "description": "Web-focused posture tuned for WordPress surface identification and plugin/theme review.",
        "base_profile": "prototype",
        "concurrency": 5,
        "cpu_cores": 0,
        "max_ports": 1200,
        "delay_ms_between_requests": 75,
        "rate_limit_mode": "balanced",
        "risk_mode": "safe-active",
        "adaptive_execution_enabled": True,
        "enable_nmap": True,
        "enable_web_probe": True,
        "enable_whatweb": True,
        "enable_nikto": True,
        "enable_nuclei": True,
        "enable_wpscan": True,
        "enable_sqlmap": False,
        "export_html_report": True,
        "export_json_data": True,
    },
    "Full External": {
        "description": "Broader external coverage for mature engagements while keeping invasive checks opt-in.",
        "base_profile": "prototype",
        "concurrency": 6,
        "cpu_cores": 0,
        "max_ports": 1500,
        "delay_ms_between_requests": 50,
        "rate_limit_mode": "balanced",
        "risk_mode": "safe-active",
        "adaptive_execution_enabled": True,
        "enable_nmap": True,
        "enable_web_probe": True,
        "enable_whatweb": True,
        "enable_nikto": True,
        "enable_nuclei": True,
        "enable_wpscan": True,
        "enable_sqlmap": False,
        "export_html_report": True,
        "export_json_data": True,
    },
}

TOOL_FIELDS = (
    "enable_nmap",
    "enable_web_probe",
    "enable_whatweb",
    "enable_nikto",
    "enable_nuclei",
    "enable_wpscan",
    "enable_sqlmap",
)

TOOL_GROUPS: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Surface Discovery",
        "Infrastructure and host enumeration for rapid external mapping with Nmap handling both discovery and service profiling.",
        (("nmap", "Host discovery, port coverage, and service verification"),),
    ),
    (
        "Web Fingerprinting",
        "HTTP reachability, stack identification, and route-focused discovery.",
        (("web_probe", "HTTP probing and screenshots"), ("whatweb", "Technology fingerprinting")),
    ),
    (
        "Validation & Exposure",
        "Safe validation checks for common web weaknesses and internet-facing issues.",
        (("nikto", "Web server exposure checks"), ("nuclei", "Template-driven validation"), ("wpscan", "WordPress enumeration")),
    ),
    (
        "Targeted Exploitation",
        "Keep disabled unless the engagement explicitly authorizes deeper active testing.",
        (("sqlmap", "Focused SQLi exploitation workflows"),),
    ),
)


class CollapsibleSection(QFrame):
    def __init__(self, title: str, description: str, body: QWidget, expanded: bool = True, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("collapsibleSection")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_CARD_SPACING)
        self.toggle_button = QToolButton()
        self.toggle_button.setObjectName("sectionToggle")
        self.toggle_button.setText(title)
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(expanded)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)
        self.toggle_button.toggled.connect(self._sync_expanded)
        layout.addWidget(self.toggle_button)
        self.description_label = QLabel(description)
        self.description_label.setObjectName("helperText")
        self.description_label.setWordWrap(True)
        layout.addWidget(self.description_label)
        self.body = body
        self.body.setVisible(expanded)
        layout.addWidget(self.body)

    def _sync_expanded(self, expanded: bool) -> None:
        self.toggle_button.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)
        self.body.setVisible(expanded)

    def set_expanded(self, expanded: bool) -> None:
        self.toggle_button.setChecked(expanded)


class ProfileFieldsMixin:
    def _form_section(self, title: str, description: str, widget: QWidget) -> QWidget:
        return self._profile_card(title, description, widget)

    def _profile_card(self, title: str, description: str, widget: QWidget, *, surface: str = "primary") -> Card:
        card = Card(
            title,
            summary=description,
            object_name="profileCard",
            surface=surface,
            padding=18,
            spacing=12,
        )
        card.content_layout.addWidget(widget)
        return card

    def _profile_form(
        self,
        *,
        include_identity: bool = True,
        collapsible_sections: bool = False,
        preset_header: str = "Quick Presets",
        preset_helper: str = "Apply a tuned preset, then adjust only the fields the engagement needs.",
    ) -> QWidget:
        container = QWidget()
        container.setObjectName("formContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)

        self._build_profile_fields()

        sections: list[tuple[str, str, QWidget, bool]] = []
        if include_identity:
            sections.append(
                (
                    "Profile Posture",
                    "Define the operator-facing identity, baseline posture, risk mode, rate mode, and default output location.",
                    self._build_identity_posture_form(),
                    True,
                ),
            )
        else:
            sections.append(
                (
                    "Profile Posture",
                    "Define the built-in baseline, stored risk posture, rate mode, and where run artifacts should be written.",
                    self._build_scope_form(),
                    True,
                )
            )
        if preset_header:
            sections.append((preset_header, preset_helper, self._build_preset_panel_body(), True))
        sections.extend(
            [
                (
                    "Performance",
                    "Tune scan speed and resource pressure. Lower values reduce noise, higher values finish faster but increase load.",
                    self._build_performance_form(),
                    False,
                ),
                (
                    "Proxy",
                    "Route supported HTTP tooling through Burp or another HTTP(S) proxy while raw network discovery remains direct.",
                    self._build_proxy_form(),
                    False,
                ),
                (
                    "Active Validation",
                    "Control validation posture, request replay, budget, target revisit windows, and strategic behavior.",
                    self._build_active_validation_form(),
                    True,
                ),
                (
                    "Playbooks / Preset Libraries",
                    "Choose the investigation lanes and optional preset files that guide deeper validation.",
                    self._build_playbook_libraries_form(),
                    True,
                ),
                (
                    "Tool Coverage",
                    "Use families and recommended posture first, then reveal expert toggles only when needed.",
                    self._build_tool_form(),
                    True,
                ),
                (
                    "Wordlists",
                    "Attach optional endpoint, parameter, and payload lists when you want broader discovery or richer fuzzing inputs.",
                    self._build_wordlists_form(),
                    False,
                ),
                (
                    "Run Output Exports",
                    "Decide which analyst-facing outputs should be written automatically at the end of each run.",
                    self._build_export_form(),
                    False,
                ),
            ]
        )

        for title, description, widget, expanded in sections:
            if collapsible_sections:
                layout.addWidget(CollapsibleSection(title, description, widget, expanded=expanded))
            else:
                layout.addWidget(self._profile_card(title, description, widget))

        layout.addStretch(1)
        self._update_tool_family_cards()
        self._refresh_preset_summary()
        return container

    def _build_profile_fields(self) -> None:
        self.profile_name_edit = QLineEdit()
        self.description_edit = QLineEdit()
        self.base_profile_combo = QComboBox()
        self.base_profile_combo.addItems(["cautious", "standard", "prototype", "aggressive"])
        self.output_dir_edit = QLineEdit("./output")
        self.endpoint_wordlist_edit = QLineEdit()
        self.parameter_wordlist_edit = QLineEdit()
        self.payload_wordlist_edit = QLineEdit()
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 128)
        self.concurrency_spin.setValue(4)
        self.cpu_cores_spin = QSpinBox()
        self.cpu_cores_spin.setRange(0, 128)
        self.adaptive_execution_checkbox = QCheckBox("Adaptive execution controller")
        self.adaptive_execution_checkbox.setChecked(True)
        self.max_ports_spin = QSpinBox()
        self.max_ports_spin.setRange(1, 65535)
        self.max_ports_spin.setValue(1000)
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 5000)
        self.delay_spin.setValue(100)
        self.masscan_rate_spin = QSpinBox()
        self.masscan_rate_spin.setRange(1, 500000)
        self.masscan_rate_spin.setValue(2000)
        self.risk_mode_combo = QComboBox()
        self.risk_mode_combo.addItems(["safe-active", "aggressive", "passive"])
        self.rate_mode_combo = QComboBox()
        self.rate_mode_combo.addItems(["careful", "balanced", "aggressive"])
        self.proxy_enabled_checkbox = QCheckBox("Route HTTP-capable tooling through an HTTP(S) proxy")
        self.proxy_url_edit = QLineEdit()
        self.proxy_url_edit.setPlaceholderText("http://127.0.0.1:8080")
        self.active_validation_mode_combo = QComboBox()
        self.active_validation_mode_combo.addItems(["passive", "safe-active", "aggressive"])
        self.request_replay_enabled_checkbox = QCheckBox("Enable built-in request replay")
        self.request_replay_enabled_checkbox.setChecked(True)
        self.validation_budget_spin = QSpinBox()
        self.validation_budget_spin.setRange(1, 100)
        self.validation_budget_spin.setValue(6)
        self.target_duration_spin = QSpinBox()
        self.target_duration_spin.setRange(1, 168)
        self.target_duration_spin.setValue(24)
        self.revisit_enabled_checkbox = QCheckBox("Revisit surfaces as new evidence appears")
        self.revisit_enabled_checkbox.setChecked(True)
        self.breadth_first_checkbox = QCheckBox("Breadth-first coverage before deepening individual surfaces")
        self.breadth_first_checkbox.setChecked(True)
        self.unauthenticated_only_checkbox = QCheckBox("Unauthenticated-only coverage lane")
        self.unauthenticated_only_checkbox.setChecked(True)
        self.web_playbooks_checkbox = QCheckBox("Enable web playbook group")
        self.web_playbooks_checkbox.setChecked(True)
        self.tls_playbooks_checkbox = QCheckBox("Enable TLS and HTTPS edge playbook group")
        self.tls_playbooks_checkbox.setChecked(True)
        self.service_playbooks_checkbox = QCheckBox("Enable non-web service playbook group")
        self.service_playbooks_checkbox.setChecked(True)
        self.object_access_playbook_checkbox = QCheckBox("Object Access playbook")
        self.object_access_playbook_checkbox.setChecked(True)
        self.input_reflection_playbook_checkbox = QCheckBox("Input Reflection / Injection playbook")
        self.input_reflection_playbook_checkbox.setChecked(True)
        self.api_expansion_playbook_checkbox = QCheckBox("API Expansion playbook")
        self.api_expansion_playbook_checkbox.setChecked(True)
        self.admin_debug_playbook_checkbox = QCheckBox("Admin / Debug Exposure playbook")
        self.admin_debug_playbook_checkbox.setChecked(True)
        self.client_artifact_playbook_checkbox = QCheckBox("Client Artifact Exposure playbook")
        self.client_artifact_playbook_checkbox.setChecked(True)
        self.framework_component_playbook_checkbox = QCheckBox("Framework / Component Exposure playbook")
        self.framework_component_playbook_checkbox.setChecked(True)
        self.web_misconfiguration_playbook_checkbox = QCheckBox("Web Misconfiguration Breadth playbook")
        self.web_misconfiguration_playbook_checkbox.setChecked(True)
        self.use_default_validation_presets_checkbox = QCheckBox("Use bundled preset libraries unless overridden")
        self.use_default_validation_presets_checkbox.setChecked(True)
        self.injection_preset_edit = QLineEdit()
        self.xss_preset_edit = QLineEdit()
        self.sqli_preset_edit = QLineEdit()
        self.auth_rate_limit_preset_edit = QLineEdit()
        self.misconfig_preset_edit = QLineEdit()
        self.data_exposure_preset_edit = QLineEdit()
        self.api_idor_preset_edit = QLineEdit()
        self.upload_preset_edit = QLineEdit()
        self.component_preset_edit = QLineEdit()
        self.infra_preset_edit = QLineEdit()
        for field in (
            self.profile_name_edit,
            self.description_edit,
            self.output_dir_edit,
            self.injection_preset_edit,
            self.xss_preset_edit,
            self.sqli_preset_edit,
            self.auth_rate_limit_preset_edit,
            self.misconfig_preset_edit,
            self.data_exposure_preset_edit,
            self.api_idor_preset_edit,
            self.upload_preset_edit,
            self.component_preset_edit,
            self.infra_preset_edit,
            self.endpoint_wordlist_edit,
            self.parameter_wordlist_edit,
            self.payload_wordlist_edit,
            self.proxy_url_edit,
        ):
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.enable_masscan = QCheckBox("masscan")
        self.enable_nmap = QCheckBox("nmap")
        self.enable_web_probe = QCheckBox("web probe")
        self.enable_whatweb = QCheckBox("whatweb")
        self.enable_nikto = QCheckBox("nikto")
        self.enable_nuclei = QCheckBox("nuclei")
        self.enable_wpscan = QCheckBox("wpscan")
        self.enable_sqlmap = QCheckBox("sqlmap")
        for checkbox in self._tool_checkboxes():
            checkbox.setChecked(True)
            checkbox.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.enable_sqlmap.setChecked(False)

        self.export_html = QCheckBox("HTML report")
        self.export_html.setChecked(True)
        self.export_json = QCheckBox("JSON data")
        self.export_json.setChecked(True)

        set_tooltips(
            (
                (self.profile_name_edit, "Enter a short profile name operators can recognize in the launch dialog."),
                (self.description_edit, "Describe when this profile should be used and what posture it applies."),
                (self.base_profile_combo, "Choose the built-in baseline posture before applying custom overrides."),
                (self.output_dir_edit, "Set the default directory for run artifacts, evidence, and generated reports."),
                (self.concurrency_spin, "Control how many parallel activities AttackCastle schedules at once."),
                (self.cpu_cores_spin, "Cap CPU-heavy stages to a fixed number of cores. Use 0 to let AttackCastle decide."),
                (self.adaptive_execution_checkbox, "Let the adaptive controller rebalance execution based on runtime conditions."),
                (self.max_ports_spin, "Limit the maximum number of ports considered during service discovery."),
                (self.delay_spin, "Add a delay between HTTP requests to reduce pressure on targets."),
                (self.risk_mode_combo, "Choose the overall activity posture for the scan."),
                (self.rate_mode_combo, "Choose how aggressively request pacing and runtime rate limits are applied."),
                (self.proxy_enabled_checkbox, "Route supported HTTP-capable tooling through a proxy such as Burp."),
                (self.proxy_url_edit, "Enter the proxy URL that supported HTTP tooling should use."),
                (self.active_validation_mode_combo, "Choose how assertively active validation playbooks should probe findings."),
                (self.request_replay_enabled_checkbox, "Replay captured requests when the validation engine needs higher confidence."),
                (self.validation_budget_spin, "Limit how many validation attempts AttackCastle spends per target."),
                (self.target_duration_spin, "Set the target revisit window used by active validation playbooks."),
                (self.revisit_enabled_checkbox, "Allow AttackCastle to revisit earlier surfaces when new evidence appears."),
                (self.breadth_first_checkbox, "Cover more surfaces first before deepening individual targets."),
                (self.unauthenticated_only_checkbox, "Keep validation limited to unauthenticated flows."),
                (self.web_playbooks_checkbox, "Enable playbooks focused on HTTP and web application behavior."),
                (self.tls_playbooks_checkbox, "Enable TLS and HTTPS edge checks."),
                (self.service_playbooks_checkbox, "Enable playbooks for non-web exposed services."),
                (self.object_access_playbook_checkbox, "Look for object access and authorization drift patterns."),
                (self.input_reflection_playbook_checkbox, "Probe reflective input handling and injection-oriented signals."),
                (self.api_expansion_playbook_checkbox, "Expand API coverage when the surface suggests more routes or objects."),
                (self.admin_debug_playbook_checkbox, "Look for admin and debug interfaces exposed to the internet."),
                (self.client_artifact_playbook_checkbox, "Inspect client-side assets for secrets, source maps, and exposure clues."),
                (self.framework_component_playbook_checkbox, "Inspect framework- and component-specific exposure signals."),
                (self.web_misconfiguration_playbook_checkbox, "Broaden common web misconfiguration coverage."),
                (self.use_default_validation_presets_checkbox, "Keep using bundled preset libraries unless you explicitly override them."),
                (self.injection_preset_edit, "Optional path to a custom injection preset list."),
                (self.xss_preset_edit, "Optional path to a custom XSS preset list."),
                (self.sqli_preset_edit, "Optional path to a custom SQL injection preset list."),
                (self.auth_rate_limit_preset_edit, "Optional path to a custom auth and rate-limit preset list."),
                (self.misconfig_preset_edit, "Optional path to a custom misconfiguration preset list."),
                (self.data_exposure_preset_edit, "Optional path to a custom data exposure preset list."),
                (self.api_idor_preset_edit, "Optional path to a custom API and IDOR preset list."),
                (self.upload_preset_edit, "Optional path to a custom upload preset list."),
                (self.component_preset_edit, "Optional path to a custom component preset list."),
                (self.infra_preset_edit, "Optional path to a custom infrastructure preset list."),
                (self.endpoint_wordlist_edit, "Optional endpoint wordlist used to expand route discovery."),
                (self.parameter_wordlist_edit, "Optional parameter wordlist used during parameter discovery and replay."),
                (self.payload_wordlist_edit, "Optional payload wordlist shared by supported validation tools."),
                (self.enable_nmap, "Enable service verification and host profiling with nmap."),
                (self.enable_web_probe, "Enable HTTP probing, reachability checks, and screenshots."),
                (self.enable_whatweb, "Enable technology fingerprinting with whatweb."),
                (self.enable_nikto, "Enable nikto for common web exposure checks."),
                (self.enable_nuclei, "Enable nuclei template-based checks."),
                (self.enable_wpscan, "Enable WordPress-focused enumeration when supported."),
                (self.enable_sqlmap, "Enable targeted SQL injection exploitation workflows when authorized."),
                (self.export_html, "Write an HTML report at the end of the run."),
                (self.export_json, "Write structured JSON output for downstream analysis."),
            )
        )

        self._active_recipe_name = ""
        self._recipe_buttons: dict[str, QPushButton] = {}
        self._tool_family_summary_labels: list[QLabel] = []
        self._suspend_recipe_tracking = False

        for signal in (
            self.base_profile_combo.currentTextChanged,
            self.output_dir_edit.textChanged,
            self.concurrency_spin.valueChanged,
            self.cpu_cores_spin.valueChanged,
            self.adaptive_execution_checkbox.toggled,
            self.max_ports_spin.valueChanged,
            self.delay_spin.valueChanged,
            self.risk_mode_combo.currentTextChanged,
            self.rate_mode_combo.currentTextChanged,
            self.proxy_enabled_checkbox.toggled,
            self.proxy_url_edit.textChanged,
            self.active_validation_mode_combo.currentTextChanged,
            self.request_replay_enabled_checkbox.toggled,
            self.validation_budget_spin.valueChanged,
            self.target_duration_spin.valueChanged,
            self.revisit_enabled_checkbox.toggled,
            self.breadth_first_checkbox.toggled,
            self.unauthenticated_only_checkbox.toggled,
            self.web_playbooks_checkbox.toggled,
            self.tls_playbooks_checkbox.toggled,
            self.service_playbooks_checkbox.toggled,
            self.object_access_playbook_checkbox.toggled,
            self.input_reflection_playbook_checkbox.toggled,
            self.api_expansion_playbook_checkbox.toggled,
            self.admin_debug_playbook_checkbox.toggled,
            self.client_artifact_playbook_checkbox.toggled,
            self.framework_component_playbook_checkbox.toggled,
            self.web_misconfiguration_playbook_checkbox.toggled,
            self.use_default_validation_presets_checkbox.toggled,
            self.injection_preset_edit.textChanged,
            self.xss_preset_edit.textChanged,
            self.sqli_preset_edit.textChanged,
            self.auth_rate_limit_preset_edit.textChanged,
            self.misconfig_preset_edit.textChanged,
            self.data_exposure_preset_edit.textChanged,
            self.api_idor_preset_edit.textChanged,
            self.upload_preset_edit.textChanged,
            self.component_preset_edit.textChanged,
            self.infra_preset_edit.textChanged,
            self.endpoint_wordlist_edit.textChanged,
            self.parameter_wordlist_edit.textChanged,
            self.payload_wordlist_edit.textChanged,
            self.export_html.toggled,
            self.export_json.toggled,
        ):
            signal.connect(self._mark_recipe_as_custom)
        for checkbox in self._tool_checkboxes():
            checkbox.toggled.connect(self._tool_settings_changed)

    def _build_preset_panel(self, title: str, helper: str) -> QWidget:
        return self._profile_card(title, helper, self._build_preset_panel_body(), surface="secondary")

    def _build_preset_panel_body(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("profilePresetPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)
        chip_row = FlowButtonRow()
        for name in PROFILE_RECIPES:
            button = QPushButton(name)
            button.setCheckable(True)
            style_button(button, role="chip")
            button.clicked.connect(lambda checked=False, preset=name: self._apply_profile_recipe(preset))
            set_tooltip(button, f"{PROFILE_RECIPES[name]['description']} Apply this preset to quickly align tools and guardrails.")
            self._recipe_buttons[name] = button
            chip_row.addWidget(button)
        self.profile_preset_summary = QLabel("Custom posture. Use a preset to quickly align tools and guardrails.")
        self.profile_preset_summary.setObjectName("infoBanner")
        self.profile_preset_summary.setWordWrap(True)
        layout.addWidget(chip_row)
        layout.addWidget(self.profile_preset_summary)
        return panel

    def _build_identity_form(self) -> QWidget:
        identity_form = QWidget()
        identity_layout = QFormLayout(identity_form)
        apply_form_layout_defaults(identity_layout)
        identity_layout.addRow("Name", self.profile_name_edit)
        identity_layout.addRow("Description", self.description_edit)
        return identity_form

    def _build_identity_posture_form(self) -> QWidget:
        identity_posture_form = QWidget()
        identity_posture_layout = QFormLayout(identity_posture_form)
        apply_form_layout_defaults(identity_posture_layout)
        identity_posture_layout.addRow("Name", self.profile_name_edit)
        identity_posture_layout.addRow("Description", self.description_edit)
        identity_posture_layout.addRow("Base Profile", self.base_profile_combo)
        identity_posture_layout.addRow("Risk Mode", self.risk_mode_combo)
        identity_posture_layout.addRow("Rate Mode", self.rate_mode_combo)
        identity_posture_layout.addRow(
            "Output Directory",
            self._directory_row(self.output_dir_edit, self._browse_output_dir),
        )
        return identity_posture_form

    def _build_scope_form(self) -> QWidget:
        browse_button = QPushButton("Browse")
        browse_button.setObjectName("browseButton")
        browse_button.clicked.connect(self._browse_output_dir)
        style_button(browse_button, role="secondary")
        set_tooltip(browse_button, "Choose the folder where AttackCastle should write run artifacts and reports for this profile.")
        output_row = QWidget()
        output_row.setObjectName("profileBrowseRow")
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(PAGE_CARD_SPACING)
        output_layout.addWidget(self.output_dir_edit)
        output_layout.addWidget(browse_button)

        scope_form = QWidget()
        scope_layout = QFormLayout(scope_form)
        apply_form_layout_defaults(scope_layout)
        scope_layout.addRow("Base Profile", self.base_profile_combo)
        scope_layout.addRow("Risk Mode", self.risk_mode_combo)
        scope_layout.addRow("Rate Mode", self.rate_mode_combo)
        scope_layout.addRow("Output Directory", output_row)
        return scope_form

    def _build_performance_form(self) -> QWidget:
        performance_form = QWidget()
        performance_layout = QFormLayout(performance_form)
        apply_form_layout_defaults(performance_layout)
        performance_layout.addRow("Concurrency", self.concurrency_spin)
        performance_layout.addRow("CPU Cores", self.cpu_cores_spin)
        performance_layout.addRow("Adaptive Control", self.adaptive_execution_checkbox)
        performance_layout.addRow("Max Ports", self.max_ports_spin)
        performance_layout.addRow("Request Delay (ms)", self.delay_spin)
        return performance_form

    def _build_proxy_form(self) -> QWidget:
        proxy_form = QWidget()
        proxy_layout = QFormLayout(proxy_form)
        apply_form_layout_defaults(proxy_layout)
        helper = QLabel(
            "Applies to AttackCastle HTTP requests, browser screenshots, and supported web scanners. Raw network discovery remains direct."
        )
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        proxy_layout.addRow(self.proxy_enabled_checkbox)
        proxy_layout.addRow("Proxy URL", self.proxy_url_edit)
        proxy_layout.addRow("", helper)
        return proxy_form

    def _build_active_validation_form(self) -> QWidget:
        active_validation_form = QWidget()
        active_validation_layout = QVBoxLayout(active_validation_form)
        active_validation_layout.setContentsMargins(0, 0, 0, 0)
        active_validation_layout.setSpacing(PANEL_CONTENT_PADDING)

        posture_form = QWidget()
        posture_layout = QFormLayout(posture_form)
        apply_form_layout_defaults(posture_layout)
        posture_layout.addRow("Validation Mode", self.active_validation_mode_combo)
        posture_layout.addRow(self.request_replay_enabled_checkbox)
        posture_layout.addRow("Budget Per Target", self.validation_budget_spin)
        posture_layout.addRow("Target Duration (Hours)", self.target_duration_spin)
        active_validation_layout.addWidget(posture_form)
        active_validation_layout.addWidget(
            self._checkbox_group(
                "Strategic Behavior",
                "Shape how validation spends attention before deeper playbooks run.",
                (
                    self.revisit_enabled_checkbox,
                    self.breadth_first_checkbox,
                    self.unauthenticated_only_checkbox,
                ),
            )
        )
        helper = QLabel(
            "Safe-active keeps replay focused on low-risk read-only checks. Aggressive enables replay-based injection probes and deeper confirmation where conditions justify them."
        )
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        active_validation_layout.addWidget(helper)
        return active_validation_form

    def _build_playbook_libraries_form(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)
        layout.addWidget(
            self._checkbox_group(
                "Coverage Lanes",
                "Open the broad playbook families needed for the surface under review.",
                (
                    self.web_playbooks_checkbox,
                    self.tls_playbooks_checkbox,
                    self.service_playbooks_checkbox,
                ),
            )
        )
        layout.addWidget(
            self._checkbox_group(
                "Web Investigation",
                "Compact investigation loops for access control, injection signals, APIs, and web misconfiguration.",
                (
                    self.object_access_playbook_checkbox,
                    self.input_reflection_playbook_checkbox,
                    self.api_expansion_playbook_checkbox,
                    self.web_misconfiguration_playbook_checkbox,
                ),
            )
        )
        layout.addWidget(
            self._checkbox_group(
                "Exposure Review",
                "Focused checks for debug surfaces, client artifacts, and framework or component exposure.",
                (
                    self.admin_debug_playbook_checkbox,
                    self.client_artifact_playbook_checkbox,
                    self.framework_component_playbook_checkbox,
                ),
            )
        )

        preset_card = QFrame()
        preset_card.setObjectName("profileSubCard")
        preset_layout = QVBoxLayout(preset_card)
        preset_layout.setContentsMargins(14, 14, 14, 14)
        preset_layout.setSpacing(PANEL_CONTENT_PADDING)
        preset_title = QLabel("Preset Libraries")
        preset_title.setObjectName("profileGroupTitle")
        preset_helper = QLabel("Use bundled validation presets by default, or point specific lanes at local files.")
        preset_helper.setObjectName("helperText")
        preset_helper.setWordWrap(True)
        preset_form = QWidget()
        preset_form_layout = QFormLayout(preset_form)
        apply_form_layout_defaults(preset_form_layout)
        preset_form_layout.addRow(self.use_default_validation_presets_checkbox)
        preset_form_layout.addRow(
            "Injection Presets",
            self._file_row(self.injection_preset_edit, lambda: self._browse_file(self.injection_preset_edit, "Select injection preset list")),
        )
        preset_form_layout.addRow(
            "XSS Presets",
            self._file_row(self.xss_preset_edit, lambda: self._browse_file(self.xss_preset_edit, "Select XSS preset list")),
        )
        preset_form_layout.addRow(
            "SQLi Presets",
            self._file_row(self.sqli_preset_edit, lambda: self._browse_file(self.sqli_preset_edit, "Select SQLi preset list")),
        )
        preset_form_layout.addRow(
            "Auth / Rate Limit",
            self._file_row(
                self.auth_rate_limit_preset_edit,
                lambda: self._browse_file(self.auth_rate_limit_preset_edit, "Select auth and rate-limit preset list"),
            ),
        )
        preset_form_layout.addRow(
            "Misconfig",
            self._file_row(self.misconfig_preset_edit, lambda: self._browse_file(self.misconfig_preset_edit, "Select misconfiguration preset list")),
        )
        preset_form_layout.addRow(
            "Data Exposure",
            self._file_row(self.data_exposure_preset_edit, lambda: self._browse_file(self.data_exposure_preset_edit, "Select data-exposure preset list")),
        )
        preset_form_layout.addRow(
            "API / IDOR",
            self._file_row(self.api_idor_preset_edit, lambda: self._browse_file(self.api_idor_preset_edit, "Select API or IDOR preset list")),
        )
        preset_form_layout.addRow(
            "Upload Presets",
            self._file_row(self.upload_preset_edit, lambda: self._browse_file(self.upload_preset_edit, "Select upload preset list")),
        )
        preset_form_layout.addRow(
            "Component Presets",
            self._file_row(self.component_preset_edit, lambda: self._browse_file(self.component_preset_edit, "Select component preset list")),
        )
        preset_form_layout.addRow(
            "Infra Presets",
            self._file_row(self.infra_preset_edit, lambda: self._browse_file(self.infra_preset_edit, "Select infrastructure preset list")),
        )
        preset_layout.addWidget(preset_title)
        preset_layout.addWidget(preset_helper)
        preset_layout.addWidget(preset_form)
        layout.addWidget(preset_card)
        return container

    def _checkbox_group(self, title: str, helper: str, checkboxes: tuple[QCheckBox, ...]) -> QWidget:
        group = QFrame()
        group.setObjectName("profileSubCard")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(PAGE_CARD_SPACING)
        title_label = QLabel(title)
        title_label.setObjectName("profileGroupTitle")
        helper_label = QLabel(helper)
        helper_label.setObjectName("helperText")
        helper_label.setWordWrap(True)
        grid_host = QWidget()
        grid_layout = QGridLayout(grid_host)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setHorizontalSpacing(PANEL_CONTENT_PADDING)
        grid_layout.setVerticalSpacing(PAGE_CARD_SPACING)
        for index, checkbox in enumerate(checkboxes):
            grid_layout.addWidget(checkbox, index // 2, index % 2)
        layout.addWidget(title_label)
        layout.addWidget(helper_label)
        layout.addWidget(grid_host)
        return group

    def _build_tool_form(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)

        actions = FlowButtonRow()
        self.enable_recommended_button = QPushButton("Enable Recommended")
        self.enable_recommended_button.clicked.connect(self._enable_recommended_tools)
        self.reset_preset_button = QPushButton("Reset To Preset")
        self.reset_preset_button.clicked.connect(self._reset_tools_to_active_recipe)
        self.expert_toggle_button = QPushButton("Show Expert Toggles")
        self.expert_toggle_button.setCheckable(True)
        self.expert_toggle_button.toggled.connect(self._toggle_expert_tools)
        style_button(self.enable_recommended_button, role="secondary")
        style_button(self.reset_preset_button, role="secondary")
        style_button(self.expert_toggle_button, role="secondary")
        set_tooltips(
            (
                (self.enable_recommended_button, "Turn on the tool set recommended for the current base or preset posture."),
                (self.reset_preset_button, "Restore tool toggles to the currently selected preset posture."),
                (self.expert_toggle_button, "Show or hide direct per-tool toggles for expert fine-tuning."),
            )
        )
        actions.addWidget(self.enable_recommended_button)
        actions.addWidget(self.reset_preset_button)
        actions.addWidget(self.expert_toggle_button)
        layout.addWidget(actions)

        helper = QLabel("Coverage is grouped by operator outcome so enabled tools read as a scan posture, not a raw checklist.")
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        layout.addWidget(helper)

        self.tool_family_grid = QGridLayout()
        self.tool_family_grid.setHorizontalSpacing(PANEL_CONTENT_PADDING)
        self.tool_family_grid.setVerticalSpacing(PANEL_CONTENT_PADDING)
        self._tool_family_cards: list[QFrame] = []
        self._tool_family_summary_labels = []
        for idx, (title, description, entries) in enumerate(TOOL_GROUPS):
            card = QFrame()
            card.setObjectName("toolFamilyCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 14, 14, 14)
            card_layout.setSpacing(PAGE_CARD_SPACING)
            title_label = QLabel(title)
            title_label.setObjectName("profileGroupTitle")
            body_label = QLabel(description)
            body_label.setObjectName("helperText")
            body_label.setWordWrap(True)
            summary_label = QLabel("")
            summary_label.setObjectName("profileToolSummary")
            summary_label.setWordWrap(True)
            self._tool_family_summary_labels.append(summary_label)
            checklist = QLabel("\n".join(f"- {name}: {detail}" for name, detail in entries))
            checklist.setObjectName("profileToolList")
            checklist.setWordWrap(True)
            card_layout.addWidget(title_label)
            card_layout.addWidget(body_label)
            card_layout.addWidget(summary_label)
            card_layout.addWidget(checklist)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            self._tool_family_cards.append(card)
            self.tool_family_grid.addWidget(card, idx // 2, idx % 2)
        layout.addLayout(self.tool_family_grid)

        self.expert_tool_panel = QWidget()
        self.expert_tool_panel.setObjectName("expertToolPanel")
        self.expert_layout = QGridLayout(self.expert_tool_panel)
        self.expert_layout.setContentsMargins(0, 0, 0, 0)
        self.expert_layout.setHorizontalSpacing(PANEL_CONTENT_PADDING)
        self.expert_layout.setVerticalSpacing(PANEL_CONTENT_PADDING)
        for idx, checkbox in enumerate(self._tool_checkboxes()):
            self.expert_layout.addWidget(checkbox, idx // 2, idx % 2)
        self.expert_tool_panel.setVisible(False)
        layout.addWidget(self.expert_tool_panel)
        return container

    def _build_wordlists_form(self) -> QWidget:
        wordlists_form = QWidget()
        wordlists_form_layout = QFormLayout(wordlists_form)
        apply_form_layout_defaults(wordlists_form_layout)
        wordlists_form_layout.addRow(
            "Endpoint Wordlist",
            self._file_row(self.endpoint_wordlist_edit, lambda: self._browse_file(self.endpoint_wordlist_edit, "Select endpoint wordlist")),
        )
        wordlists_form_layout.addRow(
            "Parameter Wordlist",
            self._file_row(self.parameter_wordlist_edit, lambda: self._browse_file(self.parameter_wordlist_edit, "Select parameter wordlist")),
        )
        wordlists_form_layout.addRow(
            "Payload Wordlist",
            self._file_row(self.payload_wordlist_edit, lambda: self._browse_file(self.payload_wordlist_edit, "Select payload wordlist")),
        )
        return wordlists_form

    def _build_export_form(self) -> QWidget:
        export_row = QWidget()
        export_layout = FlowButtonRow(export_row)
        export_layout.addWidget(self.export_html)
        export_layout.addWidget(self.export_json)
        return export_row

    def _tool_checkboxes(self) -> tuple[QCheckBox, ...]:
        return (
            self.enable_nmap,
            self.enable_web_probe,
            self.enable_whatweb,
            self.enable_nikto,
            self.enable_nuclei,
            self.enable_wpscan,
            self.enable_sqlmap,
        )

    def _enable_recommended_tools(self) -> None:
        recommended = self._recommended_tool_state()
        for field, checkbox in zip(TOOL_FIELDS, self._tool_checkboxes(), strict=True):
            checkbox.setChecked(bool(recommended.get(field, False)))
        self._mark_recipe_as_custom()

    def _reset_tools_to_active_recipe(self) -> None:
        if self._active_recipe_name and self._active_recipe_name in PROFILE_RECIPES:
            self._apply_profile_recipe(self._active_recipe_name)
            return
        self._enable_recommended_tools()

    def _toggle_expert_tools(self, visible: bool) -> None:
        self.expert_tool_panel.setVisible(visible)
        self.expert_toggle_button.setText("Hide Expert Toggles" if visible else "Show Expert Toggles")

    def _apply_profile_recipe(self, preset_name: str) -> None:
        recipe = PROFILE_RECIPES.get(preset_name)
        if recipe is None:
            return
        self._suspend_recipe_tracking = True
        self._apply_recipe_values(recipe)
        self._suspend_recipe_tracking = False
        self._active_recipe_name = preset_name
        self._sync_recipe_buttons()
        self._update_tool_family_cards()
        self._refresh_preset_summary()

    def _apply_recipe_values(self, recipe: dict[str, object]) -> None:
        self.base_profile_combo.setCurrentText(str(recipe.get("base_profile", self.base_profile_combo.currentText())))
        self.concurrency_spin.setValue(int(recipe.get("concurrency", self.concurrency_spin.value())))
        self.cpu_cores_spin.setValue(int(recipe.get("cpu_cores", self.cpu_cores_spin.value())))
        self.adaptive_execution_checkbox.setChecked(bool(recipe.get("adaptive_execution_enabled", self.adaptive_execution_checkbox.isChecked())))
        self.max_ports_spin.setValue(int(recipe.get("max_ports", self.max_ports_spin.value())))
        self.delay_spin.setValue(int(recipe.get("delay_ms_between_requests", self.delay_spin.value())))
        self.risk_mode_combo.setCurrentText(str(recipe.get("risk_mode", self.risk_mode_combo.currentText())))
        self.rate_mode_combo.setCurrentText(str(recipe.get("rate_limit_mode", self.rate_mode_combo.currentText())))
        for field in TOOL_FIELDS:
            checkbox = getattr(self, field)
            checkbox.setChecked(bool(recipe.get(field, checkbox.isChecked())))
        self.export_html.setChecked(bool(recipe.get("export_html_report", self.export_html.isChecked())))
        self.export_json.setChecked(bool(recipe.get("export_json_data", self.export_json.isChecked())))

    def _recommended_tool_state(self) -> dict[str, bool]:
        if self._active_recipe_name and self._active_recipe_name in PROFILE_RECIPES:
            recipe = PROFILE_RECIPES[self._active_recipe_name]
            return {field: bool(recipe.get(field, False)) for field in TOOL_FIELDS}
        base_profile = self.base_profile_combo.currentText().strip().lower()
        if base_profile == "cautious":
            return {
                "enable_nmap": True,
                "enable_web_probe": True,
                "enable_whatweb": True,
                "enable_nikto": False,
                "enable_nuclei": False,
                "enable_wpscan": False,
                "enable_sqlmap": False,
            }
        if base_profile == "aggressive":
            return {
                "enable_nmap": True,
                "enable_web_probe": True,
                "enable_whatweb": True,
                "enable_nikto": True,
                "enable_nuclei": True,
                "enable_wpscan": True,
                "enable_sqlmap": True,
            }
        return {
            "enable_nmap": True,
            "enable_web_probe": True,
            "enable_whatweb": True,
            "enable_nikto": True,
            "enable_nuclei": True,
            "enable_wpscan": base_profile == "prototype",
            "enable_sqlmap": False,
        }

    def _tool_settings_changed(self, _checked: bool) -> None:
        self._update_tool_family_cards()
        self._mark_recipe_as_custom()

    def _update_tool_family_cards(self) -> None:
        active_names = {
            "nmap": self.enable_nmap.isChecked(),
            "web_probe": self.enable_web_probe.isChecked(),
            "whatweb": self.enable_whatweb.isChecked(),
            "nikto": self.enable_nikto.isChecked(),
            "nuclei": self.enable_nuclei.isChecked(),
            "wpscan": self.enable_wpscan.isChecked(),
            "sqlmap": self.enable_sqlmap.isChecked(),
        }
        for summary_label, (_title, _description, entries) in zip(self._tool_family_summary_labels, TOOL_GROUPS, strict=False):
            enabled = [name for name, _detail in entries if active_names.get(name, False)]
            summary_label.setText(
                f"Active: {', '.join(enabled) if enabled else 'None'} | {len(enabled)}/{len(entries)} enabled"
            )

    def _mark_recipe_as_custom(self, *_args: object) -> None:
        if self._suspend_recipe_tracking:
            return
        self._active_recipe_name = ""
        self._sync_recipe_buttons()
        self._update_tool_family_cards()
        self._refresh_preset_summary()

    def _sync_recipe_buttons(self) -> None:
        for name, button in self._recipe_buttons.items():
            button.blockSignals(True)
            button.setChecked(name == self._active_recipe_name)
            button.blockSignals(False)

    def _refresh_preset_summary(self) -> None:
        if self._active_recipe_name and self._active_recipe_name in PROFILE_RECIPES:
            recipe = PROFILE_RECIPES[self._active_recipe_name]
            enabled_count = sum(1 for field in TOOL_FIELDS if bool(recipe.get(field, False)))
            self.profile_preset_summary.setText(
                f"{self._active_recipe_name}: {recipe['description']} | {enabled_count} tools active | Risk posture: {self.risk_mode_combo.currentText()}"
            )
            return
        enabled_count = sum(1 for checkbox in self._tool_checkboxes() if checkbox.isChecked())
        self.profile_preset_summary.setText(
            f"Custom posture. {enabled_count} tools active | Base profile: {self.base_profile_combo.currentText()} | Risk posture: {self.risk_mode_combo.currentText()}"
        )

    def _browse_output_dir(self) -> None:
        selected = QFileDialog.getExistingDirectory(None, "Select output directory", self.output_dir_edit.text())
        if selected:
            self.output_dir_edit.setText(selected)

    def _browse_file(self, target_edit: QLineEdit, title: str) -> None:
        selected, _ = QFileDialog.getOpenFileName(None, title, target_edit.text() or "", "Text Files (*.txt *.lst *.list);;All Files (*.*)")
        if selected:
            target_edit.setText(selected)

    def _directory_row(self, edit: QLineEdit, browse_callback: Callable[[], None]) -> QWidget:
        row = QWidget()
        row.setObjectName("profileBrowseRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(PAGE_CARD_SPACING)
        row_layout.addWidget(edit)
        browse_button = QPushButton("Browse")
        browse_button.setObjectName("browseButton")
        browse_button.clicked.connect(browse_callback)
        style_button(browse_button, role="secondary")
        set_tooltip(browse_button, "Choose the folder where AttackCastle should write run artifacts and reports for this profile.")
        row_layout.addWidget(browse_button)
        return row

    def _file_row(self, edit: QLineEdit, browse_callback: Callable[[], None]) -> QWidget:
        row = QWidget()
        row.setObjectName("profileBrowseRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(PAGE_CARD_SPACING)
        row_layout.addWidget(edit)
        browse_button = QPushButton("Browse")
        browse_button.setObjectName("browseButton")
        browse_button.clicked.connect(browse_callback)
        style_button(browse_button, role="secondary")
        set_tooltip(browse_button, "Choose a file from disk and place its path into this field.")
        row_layout.addWidget(browse_button)
        return row

    def _profile_from_form(self) -> GuiProfile:
        return GuiProfile(
            name=self.profile_name_edit.text().strip() or "Unnamed Profile",
            description=self.description_edit.text().strip(),
            base_profile=self.base_profile_combo.currentText(),
            output_directory=self.output_dir_edit.text().strip() or "./output",
            active_validation_mode=self.active_validation_mode_combo.currentText(),
            request_replay_enabled=self.request_replay_enabled_checkbox.isChecked(),
            validation_budget_per_target=self.validation_budget_spin.value(),
            target_duration_hours=self.target_duration_spin.value(),
            revisit_enabled=self.revisit_enabled_checkbox.isChecked(),
            breadth_first=self.breadth_first_checkbox.isChecked(),
            unauthenticated_only=self.unauthenticated_only_checkbox.isChecked(),
            enable_web_playbooks=self.web_playbooks_checkbox.isChecked(),
            enable_tls_playbooks=self.tls_playbooks_checkbox.isChecked(),
            enable_service_playbooks=self.service_playbooks_checkbox.isChecked(),
            enable_object_access_playbook=self.object_access_playbook_checkbox.isChecked(),
            enable_input_reflection_playbook=self.input_reflection_playbook_checkbox.isChecked(),
            enable_api_expansion_playbook=self.api_expansion_playbook_checkbox.isChecked(),
            enable_admin_debug_playbook=self.admin_debug_playbook_checkbox.isChecked(),
            enable_client_artifact_playbook=self.client_artifact_playbook_checkbox.isChecked(),
            enable_framework_component_playbook=self.framework_component_playbook_checkbox.isChecked(),
            enable_web_misconfiguration_playbook=self.web_misconfiguration_playbook_checkbox.isChecked(),
            use_default_validation_presets=self.use_default_validation_presets_checkbox.isChecked(),
            injection_preset_path=self.injection_preset_edit.text().strip(),
            xss_preset_path=self.xss_preset_edit.text().strip(),
            sqli_preset_path=self.sqli_preset_edit.text().strip(),
            auth_rate_limit_preset_path=self.auth_rate_limit_preset_edit.text().strip(),
            misconfig_preset_path=self.misconfig_preset_edit.text().strip(),
            data_exposure_preset_path=self.data_exposure_preset_edit.text().strip(),
            api_idor_preset_path=self.api_idor_preset_edit.text().strip(),
            upload_preset_path=self.upload_preset_edit.text().strip(),
            component_preset_path=self.component_preset_edit.text().strip(),
            infra_preset_path=self.infra_preset_edit.text().strip(),
            endpoint_wordlist_path=self.endpoint_wordlist_edit.text().strip(),
            parameter_wordlist_path=self.parameter_wordlist_edit.text().strip(),
            payload_wordlist_path=self.payload_wordlist_edit.text().strip(),
            concurrency=self.concurrency_spin.value(),
            cpu_cores=self.cpu_cores_spin.value(),
            adaptive_execution_enabled=self.adaptive_execution_checkbox.isChecked(),
            max_ports=self.max_ports_spin.value(),
            delay_ms_between_requests=self.delay_spin.value(),
            rate_limit_mode=self.rate_mode_combo.currentText(),
            masscan_rate=self.masscan_rate_spin.value(),
            risk_mode=self.risk_mode_combo.currentText(),
            proxy_enabled=self.proxy_enabled_checkbox.isChecked(),
            proxy_url=self.proxy_url_edit.text().strip(),
            enable_masscan=False,
            enable_nmap=self.enable_nmap.isChecked(),
            enable_web_probe=self.enable_web_probe.isChecked(),
            enable_whatweb=self.enable_whatweb.isChecked(),
            enable_nikto=self.enable_nikto.isChecked(),
            enable_nuclei=self.enable_nuclei.isChecked(),
            enable_wpscan=self.enable_wpscan.isChecked(),
            enable_sqlmap=self.enable_sqlmap.isChecked(),
            export_html_report=self.export_html.isChecked(),
            export_json_data=self.export_json.isChecked(),
        )

    def _apply_profile_to_form(self, profile: GuiProfile) -> None:
        self.profile_name_edit.setText(profile.name)
        self.description_edit.setText(profile.description)
        self.base_profile_combo.setCurrentText(profile.base_profile)
        self.output_dir_edit.setText(profile.output_directory)
        self.active_validation_mode_combo.setCurrentText(profile.active_validation_mode)
        self.request_replay_enabled_checkbox.setChecked(profile.request_replay_enabled)
        self.validation_budget_spin.setValue(profile.validation_budget_per_target)
        self.target_duration_spin.setValue(profile.target_duration_hours)
        self.revisit_enabled_checkbox.setChecked(profile.revisit_enabled)
        self.breadth_first_checkbox.setChecked(profile.breadth_first)
        self.unauthenticated_only_checkbox.setChecked(profile.unauthenticated_only)
        self.web_playbooks_checkbox.setChecked(profile.enable_web_playbooks)
        self.tls_playbooks_checkbox.setChecked(profile.enable_tls_playbooks)
        self.service_playbooks_checkbox.setChecked(profile.enable_service_playbooks)
        self.object_access_playbook_checkbox.setChecked(profile.enable_object_access_playbook)
        self.input_reflection_playbook_checkbox.setChecked(profile.enable_input_reflection_playbook)
        self.api_expansion_playbook_checkbox.setChecked(profile.enable_api_expansion_playbook)
        self.admin_debug_playbook_checkbox.setChecked(profile.enable_admin_debug_playbook)
        self.client_artifact_playbook_checkbox.setChecked(profile.enable_client_artifact_playbook)
        self.framework_component_playbook_checkbox.setChecked(profile.enable_framework_component_playbook)
        self.web_misconfiguration_playbook_checkbox.setChecked(profile.enable_web_misconfiguration_playbook)
        self.use_default_validation_presets_checkbox.setChecked(profile.use_default_validation_presets)
        self.injection_preset_edit.setText(profile.injection_preset_path)
        self.xss_preset_edit.setText(profile.xss_preset_path)
        self.sqli_preset_edit.setText(profile.sqli_preset_path)
        self.auth_rate_limit_preset_edit.setText(profile.auth_rate_limit_preset_path)
        self.misconfig_preset_edit.setText(profile.misconfig_preset_path)
        self.data_exposure_preset_edit.setText(profile.data_exposure_preset_path)
        self.api_idor_preset_edit.setText(profile.api_idor_preset_path)
        self.upload_preset_edit.setText(profile.upload_preset_path)
        self.component_preset_edit.setText(profile.component_preset_path)
        self.infra_preset_edit.setText(profile.infra_preset_path)
        self.endpoint_wordlist_edit.setText(profile.endpoint_wordlist_path)
        self.parameter_wordlist_edit.setText(profile.parameter_wordlist_path)
        self.payload_wordlist_edit.setText(profile.payload_wordlist_path)
        self.concurrency_spin.setValue(profile.concurrency)
        self.cpu_cores_spin.setValue(profile.cpu_cores)
        self.adaptive_execution_checkbox.setChecked(profile.adaptive_execution_enabled)
        self.max_ports_spin.setValue(profile.max_ports)
        self.delay_spin.setValue(profile.delay_ms_between_requests)
        self.risk_mode_combo.setCurrentText(profile.risk_mode)
        self.rate_mode_combo.setCurrentText(profile.rate_limit_mode)
        self.proxy_enabled_checkbox.setChecked(profile.proxy_enabled)
        self.proxy_url_edit.setText(profile.proxy_url)
        self.enable_nmap.setChecked(profile.enable_nmap)
        self.enable_web_probe.setChecked(profile.enable_web_probe)
        self.enable_whatweb.setChecked(profile.enable_whatweb)
        self.enable_nikto.setChecked(profile.enable_nikto)
        self.enable_nuclei.setChecked(profile.enable_nuclei)
        self.enable_wpscan.setChecked(profile.enable_wpscan)
        self.enable_sqlmap.setChecked(profile.enable_sqlmap)
        self.export_html.setChecked(profile.export_html_report)
        self.export_json.setChecked(profile.export_json_data)
        self._suspend_recipe_tracking = False
        self._active_recipe_name = ""
        self._sync_recipe_buttons()
        self._update_tool_family_cards()
        self._refresh_preset_summary()

    def sync_profile_form_width(self, width: int) -> None:
        tool_columns = 1 if width < 1100 else 2
        expert_columns = 1 if width < 980 else 2
        self._reflow_grid(self.tool_family_grid, self._tool_family_cards, tool_columns)
        self._reflow_grid(self.expert_layout, list(self._tool_checkboxes()), expert_columns)

    def _reflow_grid(self, layout: QGridLayout, widgets: list[QWidget], columns: int) -> None:
        while layout.count():
            layout.takeAt(0)
        for index, widget in enumerate(widgets):
            layout.addWidget(widget, index // columns, index % columns)
