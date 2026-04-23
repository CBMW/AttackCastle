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

TOOL_FIELDS = (
    "enable_subfinder",
    "enable_dnsx",
    "enable_dig_host",
    "enable_nmap",
    "enable_web_probe",
    "enable_openssl_tls",
    "enable_whatweb",
    "enable_nikto",
    "enable_nuclei",
    "enable_wpscan",
    "enable_sqlmap",
)

TOOL_FIELD_NAMES = {
    "enable_subfinder": "subfinder",
    "enable_dnsx": "dnsx",
    "enable_dig_host": "dig / host",
    "enable_nmap": "nmap",
    "enable_web_probe": "httpx",
    "enable_openssl_tls": "openssl",
    "enable_whatweb": "whatweb",
    "enable_nikto": "nikto",
    "enable_nuclei": "nuclei",
    "enable_wpscan": "wpscan",
    "enable_sqlmap": "sqlmap",
}


def _coverage_slug(value: str) -> str:
    normalized: list[str] = []
    previous_separator = False
    for char in str(value or "").strip().lower():
        if char.isalnum():
            normalized.append(char)
            previous_separator = False
            continue
        if not previous_separator:
            normalized.append("_")
            previous_separator = True
    return "".join(normalized).strip("_") or "item"


TOOL_COVERAGE_CATEGORIES: tuple[dict[str, object], ...] = (
    {
        "id": "subdomain_enumeration",
        "title": "Subdomain Enumeration",
        "description": "Find additional in-scope hosts, domains, and internet-facing assets.",
        "tools": (
            ("subfinder", "Passive subdomain enumeration for in-scope root domains.", "enable_subfinder"),
            ("assetfinder", "Additional passive asset discovery source.", ""),
            ("amass", "Deep OSINT and graph-based attack surface discovery.", ""),
        ),
    },
    {
        "id": "dns_resolution",
        "title": "DNS Resolution",
        "description": "Confirm discovered assets resolve and validate live host mappings.",
        "tools": (
            ("dnsx", "Bulk DNS resolution and record collection.", "enable_dnsx"),
            ("puredns", "High-volume trusted resolver validation.", ""),
            ("dig / host", "Resolver fallback for hostname and record checks.", "enable_dig_host"),
        ),
    },
    {
        "id": "port_discovery",
        "title": "Port Discovery",
        "description": "Quickly identify exposed TCP services on discovered hosts.",
        "tools": (
            ("masscan", "Very fast wide TCP port discovery.", ""),
            ("naabu", "Fast ProjectDiscovery port discovery.", ""),
            ("rustscan", "Rapid TCP port discovery front-end.", ""),
            ("nmap", "TCP port discovery and service reachability checks.", "enable_nmap"),
        ),
    },
    {
        "id": "service_detection",
        "title": "Service Detection",
        "description": "Determine what open ports are actually running and identify service versions.",
        "tools": (
            ("nmap", "Service verification, versions, and selected script checks.", "enable_nmap"),
            ("amap", "Protocol detection on unusual service ports.", ""),
            ("nc / openssl s_client", "Manual socket and TLS handshake confirmation.", "enable_openssl_tls"),
        ),
    },
    {
        "id": "http_service_discovery",
        "title": "HTTP Service Discovery",
        "description": "Identify web services, collect titles/statuses, and capture screenshots.",
        "tools": (
            ("httpx", "HTTP probing, metadata, tech hints, and built-in screenshots.", "enable_web_probe"),
            ("nmap", "HTTP service detection through service/version probes.", "enable_nmap"),
            ("aquatone", "Web screenshot inventory.", ""),
        ),
    },
    {
        "id": "web_screenshots",
        "title": "Web Screenshots",
        "description": "Capture screenshots and visual page inventory for rapid operator review.",
        "tools": (
            ("gowitness", "Web screenshot inventory.", ""),
            ("aquatone", "Web screenshot inventory.", ""),
            ("EyeWitness", "Screenshot collection and visual inventory.", ""),
        ),
    },
    {
        "id": "web_technology_fingerprinting",
        "title": "Web Technology Fingerprinting",
        "description": "Fingerprint frameworks, WAFs, CDNs, CMSs, and technology stacks.",
        "tools": (
            ("whatweb", "Technology fingerprinting for confirmed web targets.", "enable_whatweb"),
            ("wafw00f", "WAF and edge protection detection.", ""),
            ("nuclei tech-detect templates", "Template-based technology detection and framework checks.", "enable_nuclei"),
        ),
    },
    {
        "id": "directory_and_file_discovery",
        "title": "Directory and File Discovery",
        "description": "Discover hidden files, directories, admin panels, and forgotten paths.",
        "tools": (
            ("ffuf", "Directory, file, and virtual-host fuzzing.", ""),
            ("feroxbuster", "Recursive content discovery.", ""),
            ("dirsearch", "Directory and file discovery.", ""),
        ),
    },
    {
        "id": "parameter_discovery",
        "title": "Parameter Discovery",
        "description": "Identify hidden or unlinked parameters that expand attack surface.",
        "tools": (
            ("arjun", "Parameter name discovery.", ""),
            ("ffuf", "Parameter fuzzing with supplied wordlists.", ""),
            ("ParamSpider", "Archived parameter discovery.", ""),
        ),
    },
    {
        "id": "javascript_recon",
        "title": "JavaScript Recon",
        "description": "Extract endpoints, secrets, routes, and client-side attack surface from JavaScript.",
        "tools": (
            ("katana", "Crawler-assisted JavaScript and endpoint discovery.", ""),
            ("LinkFinder", "JavaScript endpoint extraction.", ""),
            ("SecretFinder", "JavaScript secret pattern detection.", ""),
        ),
    },
    {
        "id": "api_endpoint_discovery",
        "title": "API Endpoint Discovery",
        "description": "Discover API endpoints, GraphQL surfaces, and OpenAPI/Swagger exposure.",
        "tools": (
            ("katana", "API and endpoint crawling.", ""),
            ("ffuf", "API path discovery with supplied wordlists.", ""),
            ("graphql-cop / inql-style workflow", "GraphQL-specific discovery and introspection workflow.", ""),
        ),
    },
    {
        "id": "tls_and_certificate_analysis",
        "title": "TLS and Certificate Analysis",
        "description": "Review TLS posture, certificate details, protocol support, and SSL weaknesses.",
        "tools": (
            ("testssl.sh", "Detailed TLS configuration assessment.", ""),
            ("sslscan", "TLS protocol and cipher enumeration.", ""),
            ("openssl", "Certificate collection and TLS handshake checks.", "enable_openssl_tls"),
            ("nmap", "TLS service scripts and certificate checks where enabled.", "enable_nmap"),
        ),
    },
    {
        "id": "general_vulnerability_scanning",
        "title": "General Vulnerability Scanning",
        "description": "Run safe broad validation and exposure checks against identified targets.",
        "tools": (
            ("nuclei", "Template-driven exposure and vulnerability validation.", "enable_nuclei"),
            ("nikto", "Common web server exposure checks.", "enable_nikto"),
            ("nmap", "NSE-assisted exposure checks and service validation.", "enable_nmap"),
        ),
    },
    {
        "id": "cms_enumeration",
        "title": "CMS Enumeration",
        "description": "Run technology-specific enumeration for identified CMS or platform targets.",
        "tools": (
            ("wpscan", "WordPress-focused enumeration.", "enable_wpscan"),
            ("droopescan", "Drupal and SilverStripe enumeration.", ""),
            ("joomscan", "Joomla enumeration.", ""),
        ),
    },
    {
        "id": "authentication_surface_testing",
        "title": "Authentication Surface Testing",
        "description": "Focus on login surfaces, session handling, cookies, token lifetime, and auth paths.",
        "tools": (
            ("Burp Suite automation", "Proxy-driven authenticated workflow automation.", ""),
            ("ffuf", "Login and auth route discovery.", ""),
            ("custom curl/python request workflows", "Built-in replay and session-aware validation.", ""),
        ),
    },
    {
        "id": "focused_exploitation",
        "title": "Focused Exploitation",
        "description": "Run targeted higher-impact validation when a likely issue is already suspected.",
        "tools": (
            ("sqlmap", "Targeted SQL injection exploitation workflow.", "enable_sqlmap"),
            ("ghauri", "Targeted SQL injection exploitation workflow.", ""),
            ("xsstrike", "Targeted reflected XSS validation.", ""),
        ),
    },
    {
        "id": "oast_callback_detection",
        "title": "OAST / Callback Detection",
        "description": "Validate blind and out-of-band behaviours such as SSRF and blind XSS callbacks.",
        "tools": (
            ("interactsh-client", "Out-of-band callback validation.", ""),
            ("Burp Collaborator", "Out-of-band callback validation.", ""),
            ("webhook/callback workflow", "Operator-supplied callback validation workflow.", ""),
        ),
    },
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
        self.setToolTip(description)
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
        compact = bool(getattr(self, "_compact_profile_cards", False))
        card = Card(
            title,
            summary=description,
            object_name="profileCard",
            surface=surface,
            padding=12 if compact else 18,
            spacing=8 if compact else 12,
        )
        card.content_layout.addWidget(widget)
        return card

    def _profile_form(
        self,
        *,
        include_identity: bool = True,
        collapsible_sections: bool = False,
        include_posture: bool = True,
    ) -> QWidget:
        container = QWidget()
        container.setObjectName("formContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)

        self._compact_profile_cards = not include_identity
        self._track_manual_tool_overrides = not include_identity
        self._build_profile_fields()

        sections: list[tuple[str, str, QWidget, bool]] = []
        if include_identity and include_posture:
            sections.append(
                (
                    "Profile Posture",
                    "Define the operator-facing identity, baseline posture, risk mode, rate mode, and default output location.",
                    self._build_identity_posture_form(),
                    True,
                ),
            )
        elif include_posture:
            sections.append(
                (
                    "Profile Posture",
                    "Define the built-in baseline, stored risk posture, rate mode, and where run artifacts should be written.",
                    self._build_scope_form(),
                    True,
                )
            )
        sections.extend(
            [
                (
                    "Performance",
                    "Tune scan speed and resource pressure. Lower values reduce noise, higher values finish faster but increase load.",
                    self._build_performance_form(),
                    False,
                ),
            ]
        )
        sections.extend(
            [
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
        for field in (
            self.profile_name_edit,
            self.description_edit,
            self.output_dir_edit,
            self.endpoint_wordlist_edit,
            self.parameter_wordlist_edit,
            self.payload_wordlist_edit,
        ):
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.enable_masscan = QCheckBox("masscan")
        self.enable_subfinder = QCheckBox("subfinder")
        self.enable_dnsx = QCheckBox("dnsx")
        self.enable_dig_host = QCheckBox("dig / host")
        self.enable_nmap = QCheckBox("nmap")
        self.enable_web_probe = QCheckBox("web probe")
        self.enable_openssl_tls = QCheckBox("openssl")
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
                (self.endpoint_wordlist_edit, "Optional endpoint wordlist used to expand route discovery."),
                (self.parameter_wordlist_edit, "Optional parameter wordlist used during parameter discovery and replay."),
                (self.payload_wordlist_edit, "Optional payload wordlist shared by supported validation tools."),
                (self.enable_subfinder, "Enable subfinder-based passive subdomain enumeration."),
                (self.enable_dnsx, "Enable dnsx-based DNS record checks."),
                (self.enable_dig_host, "Enable dig/host fallback DNS resolution."),
                (self.enable_nmap, "Enable service verification and host profiling with nmap."),
                (self.enable_web_probe, "Enable HTTP probing, reachability checks, and screenshots."),
                (self.enable_openssl_tls, "Enable openssl-based TLS and certificate inspection."),
                (self.enable_whatweb, "Enable technology fingerprinting with whatweb."),
                (self.enable_nikto, "Enable nikto for common web exposure checks."),
                (self.enable_nuclei, "Enable nuclei template-based checks."),
                (self.enable_wpscan, "Enable WordPress-focused enumeration when supported."),
                (self.enable_sqlmap, "Enable targeted SQL injection exploitation workflows when authorized."),
                (self.export_html, "Write an HTML report at the end of the run."),
                (self.export_json, "Write structured JSON output for downstream analysis."),
            )
        )

        self._tool_category_cards: list[QFrame] = []
        self._tool_rows: list[QFrame] = []
        self._tool_rows_by_card: dict[QFrame, list[QFrame]] = {}
        self._tool_rows_by_field: dict[str, list[dict[str, object]]] = {}
        self._tool_rows_by_key: dict[str, dict[str, object]] = {}
        self._profile_tool_defaults: dict[str, bool] = {}
        self._manual_tool_overrides: dict[str, bool] = {}
        self._tool_coverage_overrides: dict[str, bool] = {}
        self._profile_tool_coverage_defaults: dict[str, bool] = {}
        self._manual_tool_coverage_overrides: dict[str, bool] = {}
        self._syncing_tool_widgets = False
        self._loading_profile_tools = False

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
            self.endpoint_wordlist_edit.textChanged,
            self.parameter_wordlist_edit.textChanged,
            self.payload_wordlist_edit.textChanged,
            self.export_html.toggled,
            self.export_json.toggled,
        ):
            signal.connect(self._profile_settings_changed)
        for field, checkbox in zip(TOOL_FIELDS, self._tool_checkboxes(), strict=True):
            checkbox.toggled.connect(lambda checked, tool_field=field: self._tool_settings_changed(tool_field, checked))

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

    def _checkbox_group(self, title: str, helper: str, checkboxes: tuple[QCheckBox, ...]) -> QWidget:
        group = QFrame()
        group.setObjectName("profileSubCard")
        compact = bool(getattr(self, "_compact_profile_cards", False))
        layout = QVBoxLayout(group)
        padding = 10 if compact else 14
        layout.setContentsMargins(padding, padding, padding, padding)
        layout.setSpacing(PAGE_CARD_SPACING)
        title_label = QLabel(title)
        title_label.setObjectName("profileGroupTitle")
        group.setToolTip(helper)
        grid_host = QWidget()
        grid_layout = QGridLayout(grid_host)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setHorizontalSpacing(PANEL_CONTENT_PADDING)
        grid_layout.setVerticalSpacing(PAGE_CARD_SPACING)
        for index, checkbox in enumerate(checkboxes):
            grid_layout.addWidget(checkbox, index // 2, index % 2)
        layout.addWidget(title_label)
        layout.addWidget(grid_host)
        return group

    def _build_tool_form(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PANEL_CONTENT_PADDING)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(PAGE_CARD_SPACING)
        header_layout.addStretch(1)
        self.hide_windows_only_checkbox = QCheckBox("Hide Windows Only")
        self.hide_windows_only_checkbox.setObjectName("hideWindowsOnlyTools")
        self.hide_windows_only_checkbox.toggled.connect(self._update_tool_family_cards)
        set_tooltip(self.hide_windows_only_checkbox, "Hide tools that are not currently available in this Windows launch workflow.")
        header_layout.addWidget(self.hide_windows_only_checkbox, 0, Qt.AlignRight)
        layout.addWidget(header)

        self.tool_family_grid = QGridLayout()
        self.tool_family_grid.setHorizontalSpacing(PANEL_CONTENT_PADDING)
        self.tool_family_grid.setVerticalSpacing(PANEL_CONTENT_PADDING)
        self._tool_category_cards = []
        self._tool_rows = []
        self._tool_rows_by_card = {}
        self._tool_rows_by_field = {}
        self._tool_rows_by_key = {}
        for idx, category in enumerate(TOOL_COVERAGE_CATEGORIES):
            card = self._build_tool_category_card(category)
            self._tool_category_cards.append(card)
            self.tool_family_grid.addWidget(card, idx // 2, idx % 2)
        layout.addLayout(self.tool_family_grid)

        # Kept as a hidden compatibility surface for callers/tests that still
        # probe the old expert-toggle API; the category rows are now the editor.
        self.expert_tool_panel = QWidget()
        self.expert_tool_panel.setObjectName("expertToolPanel")
        self.expert_tool_panel.setVisible(False)
        self.expert_toggle_button = QPushButton("Show Expert Toggles")
        self.expert_toggle_button.setCheckable(True)
        self.expert_toggle_button.setVisible(False)
        self.expert_toggle_button.toggled.connect(self._toggle_expert_tools)
        return container

    def _build_tool_category_card(self, category: dict[str, object]) -> QFrame:
        card = QFrame()
        card.setObjectName("toolCoverageCategory")
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        compact = bool(getattr(self, "_compact_profile_cards", False))
        card_layout = QVBoxLayout(card)
        padding = 10 if compact else 14
        card_layout.setContentsMargins(padding, padding, padding, padding)
        card_layout.setSpacing(PAGE_CARD_SPACING)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(PAGE_CARD_SPACING)
        title_label = QLabel(str(category.get("title", "")))
        title_label.setObjectName("profileGroupTitle")
        header_layout.addWidget(title_label, 1)

        body = QWidget()
        body.setObjectName("toolCoverageBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(PAGE_CARD_SPACING)
        category_rows: list[QFrame] = []
        category_id = str(category.get("id") or _coverage_slug(str(category.get("title", ""))))
        for tool_name, _description, field in category.get("tools", ()):
            row = self._build_tool_row(str(tool_name), str(field), category_id)
            category_rows.append(row)
            body_layout.addWidget(row)
        self._tool_rows_by_card[card] = category_rows
        card_layout.addWidget(header)
        card_layout.addWidget(body)
        return card

    def _build_tool_row(self, tool_name: str, field: str, category_id: str) -> QFrame:
        row = QFrame()
        row.setObjectName("toolCoverageRow")
        self._tool_rows.append(row)
        coverage_key = f"{category_id}.{_coverage_slug(tool_name)}"
        row.setProperty("coverage_key", coverage_key)
        available = bool(field and hasattr(self, field))
        row.setProperty("available", available)
        # In the Windows launch workflow, rows without an engine mapping are
        # treated as Windows-only visibility noise until they are wired up.
        row.setProperty("windows_only", not available)
        row_layout = QHBoxLayout(row)
        compact = bool(getattr(self, "_compact_profile_cards", False))
        padding = 6 if compact else 8
        row_layout.setContentsMargins(padding, padding, padding, padding)
        row_layout.setSpacing(PAGE_CARD_SPACING)

        checkbox = QCheckBox()
        checkbox.setObjectName("toolCoverageCheckbox")
        checkbox.setProperty("coverage_key", coverage_key)
        checkbox.setEnabled(available)
        checkbox.setFocusPolicy(Qt.StrongFocus if available else Qt.NoFocus)
        if available:
            checkbox.toggled.connect(lambda checked, key=coverage_key: self._set_tool_coverage_row(key, checked))
        row_layout.addWidget(checkbox, 0, Qt.AlignTop)

        name_label = QLabel(tool_name)
        name_label.setObjectName("toolCoverageName")
        name_label.setProperty("available", available)
        row_layout.addWidget(name_label, 1, Qt.AlignVCenter)

        if available:
            entry = {
                "checkbox": checkbox,
                "field": field,
                "tool_name": tool_name,
                "coverage_key": coverage_key,
                "category_id": category_id,
            }
            self._tool_rows_by_key[coverage_key] = entry
            rows = self._tool_rows_by_field.setdefault(field, [])
            rows.append(entry)
        else:
            checkbox.setToolTip("This tool is not currently wired into the AttackCastle scan pipeline.")
            row.setToolTip("Unavailable: no implemented AttackCastle adapter or per-scan override hook exists yet.")
        return row

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
            self.enable_subfinder,
            self.enable_dnsx,
            self.enable_dig_host,
            self.enable_nmap,
            self.enable_web_probe,
            self.enable_openssl_tls,
            self.enable_whatweb,
            self.enable_nikto,
            self.enable_nuclei,
            self.enable_wpscan,
            self.enable_sqlmap,
        )

    def _toggle_expert_tools(self, visible: bool) -> None:
        self.expert_tool_panel.setVisible(visible)

    def _profile_settings_changed(self, *_args: object) -> None:
        self._update_tool_family_cards()
        refresh = getattr(self, "_refresh_launch_summary", None)
        if callable(refresh):
            refresh()

    def _recommended_tool_state(self) -> dict[str, bool]:
        base_profile = self.base_profile_combo.currentText().strip().lower()
        if base_profile == "cautious":
            return {
                "enable_subfinder": True,
                "enable_dnsx": True,
                "enable_dig_host": True,
                "enable_nmap": True,
                "enable_web_probe": True,
                "enable_openssl_tls": True,
                "enable_whatweb": True,
                "enable_nikto": False,
                "enable_nuclei": False,
                "enable_wpscan": False,
                "enable_sqlmap": False,
            }
        if base_profile == "aggressive":
            return {
                "enable_subfinder": True,
                "enable_dnsx": True,
                "enable_dig_host": True,
                "enable_nmap": True,
                "enable_web_probe": True,
                "enable_openssl_tls": True,
                "enable_whatweb": True,
                "enable_nikto": True,
                "enable_nuclei": True,
                "enable_wpscan": True,
                "enable_sqlmap": True,
            }
        return {
            "enable_subfinder": True,
            "enable_dnsx": True,
            "enable_dig_host": True,
            "enable_nmap": True,
            "enable_web_probe": True,
            "enable_openssl_tls": True,
            "enable_whatweb": True,
            "enable_nikto": True,
            "enable_nuclei": True,
            "enable_wpscan": base_profile == "prototype",
            "enable_sqlmap": False,
        }

    def _tool_settings_changed(self, field: str, checked: bool) -> None:
        if self._syncing_tool_widgets:
            return
        # Launch overrides are stored as deltas from the selected profile so a
        # later profile change can recompute the baseline without losing intent.
        if not self._loading_profile_tools and getattr(self, "_track_manual_tool_overrides", False):
            default = self._profile_tool_defaults.get(field)
            if default is not None:
                if checked == default:
                    self._manual_tool_overrides.pop(field, None)
                else:
                    self._manual_tool_overrides[field] = checked
        self._update_tool_family_cards()
        refresh = getattr(self, "_refresh_launch_summary", None)
        if callable(refresh):
            refresh()

    def _update_tool_family_cards(self) -> None:
        self._sync_tool_rows()
        hide_windows_only = (
            hasattr(self, "hide_windows_only_checkbox")
            and self.hide_windows_only_checkbox.isChecked()
        )
        for row in getattr(self, "_tool_rows", []):
            row.setVisible(not (hide_windows_only and bool(row.property("windows_only"))))
        for card, rows in getattr(self, "_tool_rows_by_card", {}).items():
            card.setVisible(any(not row.isHidden() for row in rows))

    def _row_baseline_checked(self, entry: dict[str, object]) -> bool:
        field = str(entry.get("field") or "")
        return bool(getattr(self, field).isChecked()) if field and hasattr(self, field) else False

    def _row_checked(self, coverage_key: str) -> bool:
        entry = self._tool_rows_by_key.get(coverage_key)
        if not entry:
            return False
        if coverage_key in self._tool_coverage_overrides:
            return bool(self._tool_coverage_overrides[coverage_key])
        return self._row_baseline_checked(entry)

    def _set_tool_coverage_override(self, coverage_key: str, checked: bool) -> None:
        entry = self._tool_rows_by_key.get(coverage_key)
        if not entry:
            return
        if checked == self._row_baseline_checked(entry):
            self._tool_coverage_overrides.pop(coverage_key, None)
        else:
            self._tool_coverage_overrides[coverage_key] = checked

    def _set_tool_coverage_row(self, coverage_key: str, checked: bool) -> None:
        if self._syncing_tool_widgets:
            return
        self._set_tool_coverage_override(coverage_key, checked)
        if not self._loading_profile_tools and getattr(self, "_track_manual_tool_overrides", False):
            default = self._profile_tool_coverage_defaults.get(coverage_key)
            if default is not None:
                if checked == default:
                    self._manual_tool_coverage_overrides.pop(coverage_key, None)
                else:
                    self._manual_tool_coverage_overrides[coverage_key] = checked
        self._update_tool_family_cards()

    def _current_tool_state(self) -> dict[str, bool]:
        return {field: getattr(self, field).isChecked() for field in TOOL_FIELDS if hasattr(self, field)}

    def _current_tool_coverage_state(self) -> dict[str, bool]:
        return {
            key: self._row_checked(key)
            for key in self._tool_rows_by_key
        }

    def _current_tool_coverage_overrides(self) -> dict[str, bool]:
        overrides: dict[str, bool] = {}
        for key, entry in self._tool_rows_by_key.items():
            checked = self._row_checked(key)
            if checked != self._row_baseline_checked(entry):
                overrides[key] = checked
        return overrides

    def _enabled_tool_coverage_labels(self) -> list[str]:
        labels: list[str] = []
        for key, entry in self._tool_rows_by_key.items():
            if not self._row_checked(key):
                continue
            tool_name = str(entry.get("tool_name") or "")
            category_id = str(entry.get("category_id") or "").replace("_", " ")
            label = f"{tool_name} ({category_id.title()})" if tool_name else category_id.title()
            labels.append(label)
        return labels

    def _apply_tool_state(self, state: dict[str, bool]) -> None:
        self._loading_profile_tools = True
        try:
            for field in TOOL_FIELDS:
                if field in state and hasattr(self, field):
                    getattr(self, field).setChecked(bool(state[field]))
        finally:
            self._loading_profile_tools = False
        self._update_tool_family_cards()

    def _apply_manual_tool_overrides(self) -> None:
        if self._manual_tool_overrides:
            self._apply_tool_state(self._manual_tool_overrides)

    def _apply_manual_tool_coverage_overrides(self) -> None:
        for coverage_key, checked in self._manual_tool_coverage_overrides.items():
            self._set_tool_coverage_override(coverage_key, checked)
        self._update_tool_family_cards()

    def _sync_tool_rows(self) -> None:
        if self._syncing_tool_widgets:
            return
        self._syncing_tool_widgets = True
        try:
            for coverage_key, entry in self._tool_rows_by_key.items():
                checkbox = entry.get("checkbox")
                if isinstance(checkbox, QCheckBox):
                    checkbox.setChecked(self._row_checked(coverage_key))
        finally:
            self._syncing_tool_widgets = False

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
            endpoint_wordlist_path=self.endpoint_wordlist_edit.text().strip(),
            parameter_wordlist_path=self.parameter_wordlist_edit.text().strip(),
            payload_wordlist_path=self.payload_wordlist_edit.text().strip(),
            tool_coverage_overrides=self._current_tool_coverage_overrides(),
            concurrency=self.concurrency_spin.value(),
            cpu_cores=self.cpu_cores_spin.value(),
            adaptive_execution_enabled=self.adaptive_execution_checkbox.isChecked(),
            max_ports=self.max_ports_spin.value(),
            delay_ms_between_requests=self.delay_spin.value(),
            rate_limit_mode=self.rate_mode_combo.currentText(),
            masscan_rate=self.masscan_rate_spin.value(),
            risk_mode=self.risk_mode_combo.currentText(),
            proxy_enabled=False,
            proxy_url="",
            enable_masscan=False,
            enable_subfinder=self.enable_subfinder.isChecked(),
            enable_dnsx=self.enable_dnsx.isChecked(),
            enable_dig_host=self.enable_dig_host.isChecked(),
            enable_nmap=self.enable_nmap.isChecked(),
            enable_web_probe=self.enable_web_probe.isChecked(),
            enable_openssl_tls=self.enable_openssl_tls.isChecked(),
            enable_whatweb=self.enable_whatweb.isChecked(),
            enable_nikto=self.enable_nikto.isChecked(),
            enable_nuclei=self.enable_nuclei.isChecked(),
            enable_wpscan=self.enable_wpscan.isChecked(),
            enable_sqlmap=self.enable_sqlmap.isChecked(),
            export_html_report=self.export_html.isChecked(),
            export_json_data=self.export_json.isChecked(),
        )

    def _apply_profile_to_form(self, profile: GuiProfile, *, preserve_manual_overrides: bool = False) -> None:
        # The launch dialog preserves explicit per-scan deltas when the operator
        # changes the selected profile; the profile editor intentionally resets.
        previous_overrides = dict(self._manual_tool_overrides) if preserve_manual_overrides else {}
        previous_coverage_overrides = dict(self._manual_tool_coverage_overrides) if preserve_manual_overrides else {}
        self._loading_profile_tools = True
        self.profile_name_edit.setText(profile.name)
        self.description_edit.setText(profile.description)
        self.base_profile_combo.setCurrentText(profile.base_profile)
        self.output_dir_edit.setText(profile.output_directory)
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
        self.enable_subfinder.setChecked(profile.enable_subfinder)
        self.enable_dnsx.setChecked(profile.enable_dnsx)
        self.enable_dig_host.setChecked(profile.enable_dig_host)
        self.enable_nmap.setChecked(profile.enable_nmap)
        self.enable_web_probe.setChecked(profile.enable_web_probe)
        self.enable_openssl_tls.setChecked(profile.enable_openssl_tls)
        self.enable_whatweb.setChecked(profile.enable_whatweb)
        self.enable_nikto.setChecked(profile.enable_nikto)
        self.enable_nuclei.setChecked(profile.enable_nuclei)
        self.enable_wpscan.setChecked(profile.enable_wpscan)
        self.enable_sqlmap.setChecked(profile.enable_sqlmap)
        self._tool_coverage_overrides = dict(profile.tool_coverage_overrides)
        self.export_html.setChecked(profile.export_html_report)
        self.export_json.setChecked(profile.export_json_data)
        self._loading_profile_tools = False
        self._profile_tool_defaults = self._current_tool_state()
        self._profile_tool_coverage_defaults = self._current_tool_coverage_state()
        self._manual_tool_overrides = {
            field: value
            for field, value in previous_overrides.items()
            if field in self._profile_tool_defaults
        }
        self._manual_tool_coverage_overrides = {
            key: value
            for key, value in previous_coverage_overrides.items()
            if key in self._profile_tool_coverage_defaults
        }
        self._apply_manual_tool_overrides()
        self._apply_manual_tool_coverage_overrides()
        self._update_tool_family_cards()

    def sync_profile_form_width(self, width: int) -> None:
        tool_columns = 1 if width < 1100 else 2
        self._reflow_grid(self.tool_family_grid, self._tool_category_cards, tool_columns)

    def _reflow_grid(self, layout: QGridLayout, widgets: list[QWidget], columns: int) -> None:
        while layout.count():
            layout.takeAt(0)
        for index, widget in enumerate(widgets):
            layout.addWidget(widget, index // columns, index % columns)
