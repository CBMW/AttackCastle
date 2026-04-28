from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


BUILT_IN_PROFILE_NAMES = ("cautious", "standard", "prototype", "aggressive")
RATE_LIMIT_MODES = ("careful", "balanced", "aggressive")
RISK_MODES = ("safe-active", "aggressive", "passive")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_int(value: Any, default: int, minimum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return default
    return parsed


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    return default


def _coerce_choice(value: Any, default: str, allowed: tuple[str, ...]) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in allowed else default


@dataclass(slots=True)
class GuiProfile:
    name: str
    description: str = ""
    base_profile: str = "prototype"
    output_directory: str = "./output"
    concurrency: int = 4
    cpu_cores: int = 0
    adaptive_execution_enabled: bool = True
    max_ports: int = 1000
    delay_ms_between_requests: int = 100
    rate_limit_mode: str = "balanced"
    masscan_rate: int = 2000
    risk_mode: str = "safe-active"
    enable_masscan: bool = True
    enable_subfinder: bool = True
    enable_dnsx: bool = True
    enable_dig_host: bool = True
    enable_nmap: bool = True
    enable_web_probe: bool = True
    enable_openssl_tls: bool = True
    enable_whatweb: bool = True
    enable_nikto: bool = True
    enable_nuclei: bool = True
    enable_http_security_headers: bool = True
    enable_wpscan: bool = False
    enable_sqlmap: bool = False
    proxy_enabled: bool = False
    proxy_url: str = ""
    endpoint_wordlist_path: str = ""
    parameter_wordlist_path: str = ""
    payload_wordlist_path: str = ""
    tool_coverage_overrides: dict[str, bool] = field(default_factory=dict)
    export_html_report: bool = True
    export_json_data: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GuiProfile":
        return cls(
            name=str(payload.get("name", "Unnamed Profile")).strip() or "Unnamed Profile",
            description=str(payload.get("description", "")),
            base_profile=_coerce_choice(payload.get("base_profile"), "prototype", BUILT_IN_PROFILE_NAMES),
            output_directory=str(payload.get("output_directory", "./output")) or "./output",
            concurrency=_coerce_int(payload.get("concurrency", 4), 4, 1),
            cpu_cores=_coerce_int(payload.get("cpu_cores", 0), 0, 0),
            adaptive_execution_enabled=_coerce_bool(payload.get("adaptive_execution_enabled", True), True),
            max_ports=_coerce_int(payload.get("max_ports", 1000), 1000, 1),
            delay_ms_between_requests=_coerce_int(payload.get("delay_ms_between_requests", 100), 100, 0),
            rate_limit_mode=_coerce_choice(payload.get("rate_limit_mode"), "balanced", RATE_LIMIT_MODES),
            masscan_rate=_coerce_int(payload.get("masscan_rate", 2000), 2000, 1),
            risk_mode=_coerce_choice(payload.get("risk_mode"), "safe-active", RISK_MODES),
            enable_masscan=_coerce_bool(payload.get("enable_masscan", True), True),
            enable_subfinder=_coerce_bool(payload.get("enable_subfinder", True), True),
            enable_dnsx=_coerce_bool(payload.get("enable_dnsx", True), True),
            enable_dig_host=_coerce_bool(payload.get("enable_dig_host", True), True),
            enable_nmap=_coerce_bool(payload.get("enable_nmap", True), True),
            enable_web_probe=_coerce_bool(payload.get("enable_web_probe", True), True),
            enable_openssl_tls=_coerce_bool(payload.get("enable_openssl_tls", True), True),
            enable_whatweb=_coerce_bool(payload.get("enable_whatweb", True), True),
            enable_nikto=_coerce_bool(payload.get("enable_nikto", True), True),
            enable_nuclei=_coerce_bool(payload.get("enable_nuclei", True), True),
            enable_http_security_headers=_coerce_bool(payload.get("enable_http_security_headers", True), True),
            enable_wpscan=_coerce_bool(payload.get("enable_wpscan", False), False),
            enable_sqlmap=_coerce_bool(payload.get("enable_sqlmap", False), False),
            proxy_enabled=_coerce_bool(payload.get("proxy_enabled", False), False),
            proxy_url=str(payload.get("proxy_url", "")),
            endpoint_wordlist_path=str(payload.get("endpoint_wordlist_path", "")),
            parameter_wordlist_path=str(payload.get("parameter_wordlist_path", "")),
            payload_wordlist_path=str(payload.get("payload_wordlist_path", "")),
            tool_coverage_overrides={
                str(key): _coerce_bool(value, False)
                for key, value in (payload.get("tool_coverage_overrides") or {}).items()
            }
            if isinstance(payload.get("tool_coverage_overrides"), dict)
            else {},
            export_html_report=_coerce_bool(payload.get("export_html_report", True), True),
            export_json_data=_coerce_bool(payload.get("export_json_data", True), True),
        )


@dataclass(slots=True)
class GuiProxySettings:
    proxy_all_traffic: bool = False
    global_proxy_url: str = ""
    scanner_proxy_enabled: bool = False
    scanner_proxy_url: str = ""
    attacker_proxy_enabled: bool = False
    attacker_proxy_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GuiProxySettings":
        return cls(
            proxy_all_traffic=_coerce_bool(payload.get("proxy_all_traffic", False), False),
            global_proxy_url=str(payload.get("global_proxy_url", "")),
            scanner_proxy_enabled=_coerce_bool(payload.get("scanner_proxy_enabled", False), False),
            scanner_proxy_url=str(payload.get("scanner_proxy_url", "")),
            attacker_proxy_enabled=_coerce_bool(payload.get("attacker_proxy_enabled", False), False),
            attacker_proxy_url=str(payload.get("attacker_proxy_url", "")),
        )

    def effective_scanner_proxy_url(self) -> str:
        if self.proxy_all_traffic:
            return self.global_proxy_url.strip()
        if self.scanner_proxy_enabled:
            return self.scanner_proxy_url.strip()
        return ""

    def effective_attacker_proxy_url(self) -> str:
        if self.proxy_all_traffic:
            return self.global_proxy_url.strip()
        if self.attacker_proxy_enabled:
            return self.attacker_proxy_url.strip()
        return ""


@dataclass(slots=True)
class ScanRequest:
    scan_name: str
    target_input: str
    profile: GuiProfile
    output_directory: str
    workspace_id: str = ""
    workspace_name: str = ""
    audience: str = "consultant"
    resume_run_dir: str = ""
    launch_mode: str = "new"
    enabled_extension_ids: list[str] = field(default_factory=list)
    performance_guard: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_name": self.scan_name,
            "target_input": self.target_input,
            "profile": self.profile.to_dict(),
            "output_directory": self.output_directory,
            "workspace_id": self.workspace_id,
            "workspace_name": self.workspace_name,
            # Preserve legacy keys for older readers.
            "engagement_id": self.workspace_id,
            "engagement_name": self.workspace_name,
            "audience": self.audience,
            "resume_run_dir": self.resume_run_dir,
            "launch_mode": self.launch_mode,
            "enabled_extension_ids": list(self.enabled_extension_ids),
            "performance_guard": dict(self.performance_guard),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanRequest":
        workspace_id = str(payload.get("workspace_id") or payload.get("engagement_id") or "")
        workspace_name = str(payload.get("workspace_name") or payload.get("engagement_name") or "")
        return cls(
            scan_name=str(payload.get("scan_name", "Untitled Scan")).strip() or "Untitled Scan",
            target_input=str(payload.get("target_input", "")),
            profile=GuiProfile.from_dict(dict(payload.get("profile", {}))),
            output_directory=str(payload.get("output_directory", "./output")) or "./output",
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            audience=str(payload.get("audience", "consultant")) or "consultant",
            resume_run_dir=str(payload.get("resume_run_dir", "")),
            launch_mode=str(payload.get("launch_mode", "resume" if payload.get("resume_run_dir") else "new")) or "new",
            enabled_extension_ids=[
                str(item)
                for item in payload.get("enabled_extension_ids", [])
                if str(item).strip()
            ]
            if isinstance(payload.get("enabled_extension_ids"), list)
            else [],
            performance_guard=dict(payload.get("performance_guard", {}))
            if isinstance(payload.get("performance_guard"), dict)
            else {},
        )

    @property
    def engagement_id(self) -> str:
        return self.workspace_id

    @engagement_id.setter
    def engagement_id(self, value: str) -> None:
        self.workspace_id = value

    @property
    def engagement_name(self) -> str:
        return self.workspace_name

    @engagement_name.setter
    def engagement_name(self, value: str) -> None:
        self.workspace_name = value


@dataclass(slots=True)
class Workspace:
    workspace_id: str
    name: str
    home_dir: str = "./output"
    client_name: str = ""
    scope_summary: str = ""
    last_opened_at: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Workspace":
        current = now_iso()
        workspace_id = str(payload.get("workspace_id") or payload.get("engagement_id") or "").strip()
        return cls(
            workspace_id=workspace_id,
            name=str(payload.get("name", "Untitled Project")).strip() or "Untitled Project",
            home_dir=str(payload.get("home_dir") or payload.get("output_directory") or "./output") or "./output",
            client_name=str(payload.get("client_name", "")),
            scope_summary=str(payload.get("scope_summary", "")),
            last_opened_at=str(payload.get("last_opened_at", "")),
            created_at=str(payload.get("created_at", current)),
            updated_at=str(payload.get("updated_at", current)),
        )

    @property
    def engagement_id(self) -> str:
        return self.workspace_id

    @engagement_id.setter
    def engagement_id(self, value: str) -> None:
        self.workspace_id = value


@dataclass(slots=True)
class OverviewChecklistItem:
    item_id: str
    label: str
    completed: bool = False
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "OverviewChecklistItem":
        current = now_iso()
        return cls(
            item_id=str(payload.get("item_id", "")).strip(),
            label=str(payload.get("label", "")).strip(),
            completed=_coerce_bool(payload.get("completed", False), False),
            created_at=str(payload.get("created_at", current)),
            updated_at=str(payload.get("updated_at", current)),
        )


@dataclass(slots=True)
class WorkspaceOverviewState:
    checklist_items: list[OverviewChecklistItem] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checklist_items": [item.to_dict() for item in self.checklist_items if item.item_id and item.label],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WorkspaceOverviewState":
        if not isinstance(payload, dict):
            return cls()
        raw_items = payload.get("checklist_items", [])
        items: list[OverviewChecklistItem] = []
        if isinstance(raw_items, list):
            for raw_item in raw_items:
                if not isinstance(raw_item, dict):
                    continue
                item = OverviewChecklistItem.from_dict(raw_item)
                if not item.item_id or not item.label:
                    continue
                items.append(item)
        return cls(
            checklist_items=items,
            notes=str(payload.get("notes", "")),
        )


class Engagement(Workspace):
    def __init__(
        self,
        engagement_id: str,
        name: str,
        home_dir: str = "./output",
        client_name: str = "",
        scope_summary: str = "",
        last_opened_at: str = "",
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        super().__init__(
            workspace_id=engagement_id,
            name=name,
            home_dir=home_dir,
            client_name=client_name,
            scope_summary=scope_summary,
            last_opened_at=last_opened_at,
            created_at=created_at or now_iso(),
            updated_at=updated_at or now_iso(),
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Engagement":
        workspace = Workspace.from_dict(payload)
        return cls(
            engagement_id=workspace.workspace_id,
            name=workspace.name,
            home_dir=workspace.home_dir,
            client_name=workspace.client_name,
            scope_summary=workspace.scope_summary,
            last_opened_at=workspace.last_opened_at,
            created_at=workspace.created_at,
            updated_at=workspace.updated_at,
        )


@dataclass(slots=True)
class RunRegistryEntry:
    run_id: str
    run_dir: str
    workspace_id: str
    scan_name: str = ""
    last_known_state: str = ""
    last_seen_at: str = field(default_factory=now_iso)
    pause_requested: bool = False
    resume_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunRegistryEntry":
        return cls(
            run_id=str(payload.get("run_id", "")).strip(),
            run_dir=str(payload.get("run_dir", "")).strip(),
            workspace_id=str(payload.get("workspace_id") or payload.get("engagement_id") or "").strip(),
            scan_name=str(payload.get("scan_name", "")),
            last_known_state=str(payload.get("last_known_state", "")),
            last_seen_at=str(payload.get("last_seen_at", now_iso())),
            pause_requested=bool(payload.get("pause_requested", False)),
            resume_required=bool(payload.get("resume_required", False)),
        )


@dataclass(slots=True)
class MigrationState:
    completed: bool = False
    import_roots: list[str] = field(default_factory=list)
    last_detected_legacy_version: int = 0
    pending_run_assignments: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MigrationState":
        import_roots = payload.get("import_roots", [])
        pending = payload.get("pending_run_assignments", {})
        return cls(
            completed=bool(payload.get("completed", False)),
            import_roots=[str(item) for item in import_roots if str(item).strip()] if isinstance(import_roots, list) else [],
            last_detected_legacy_version=_coerce_int(payload.get("last_detected_legacy_version", 0), 0, 0),
            pending_run_assignments={str(key): str(value) for key, value in pending.items()} if isinstance(pending, dict) else {},
        )


@dataclass(slots=True)
class FindingState:
    finding_id: str
    status: str = "needs-validation"
    analyst_note: str = ""
    severity_override: str = ""
    include_in_report: bool = True
    report_flag_touched: bool = False
    reproduce_steps: str = ""
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FindingState":
        return cls(
            finding_id=str(payload.get("finding_id", "")).strip(),
            status=str(payload.get("status", "needs-validation")) or "needs-validation",
            analyst_note=str(payload.get("analyst_note", "")),
            severity_override=str(payload.get("severity_override", "")),
            include_in_report=bool(payload.get("include_in_report", True)),
            report_flag_touched=_coerce_bool(payload.get("report_flag_touched", False), False),
            reproduce_steps=str(payload.get("reproduce_steps", "")),
            updated_at=str(payload.get("updated_at", now_iso())),
        )


@dataclass(slots=True)
class ReportScopeItem:
    scope_type: str
    value: str = ""
    is_uat: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReportScopeItem":
        return cls(
            scope_type=str(payload.get("scope_type", "")).strip(),
            value=str(payload.get("value", "")),
            is_uat=_coerce_bool(payload.get("is_uat", False), False),
        )


@dataclass(slots=True)
class ReportsConfig:
    export_path: str = ""
    merge_tool_path: str = ""
    export_formats: list[str] = field(default_factory=lambda: ["docx"])
    report_title: str = ""
    report_types: list[str] = field(default_factory=list)
    client_name: str = ""
    report_date: str = ""
    engagement_start_date: str = ""
    engagement_end_date: str = ""
    scope_items: list[ReportScopeItem] = field(default_factory=list)
    add_all_findings: bool = True
    add_report_only_findings: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "export_path": self.export_path,
            "merge_tool_path": self.merge_tool_path,
            "export_formats": list(self.export_formats),
            "report_title": self.report_title,
            "report_types": list(self.report_types),
            "client_name": self.client_name,
            "report_date": self.report_date,
            "engagement_start_date": self.engagement_start_date,
            "engagement_end_date": self.engagement_end_date,
            "scope_items": [item.to_dict() for item in self.scope_items if item.scope_type],
            "add_all_findings": self.add_all_findings,
            "add_report_only_findings": self.add_report_only_findings,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReportsConfig":
        if not isinstance(payload, dict):
            return cls()
        raw_types = payload.get("report_types", [])
        raw_scope = payload.get("scope_items", [])
        raw_formats = payload.get("export_formats", ["docx"])
        export_formats = [
            str(item).strip().lower()
            for item in raw_formats
            if str(item).strip().lower() in {"docx", "pdf"}
        ] if isinstance(raw_formats, list) else ["docx"]
        return cls(
            export_path=str(payload.get("export_path", "")),
            merge_tool_path=str(payload.get("merge_tool_path", "")),
            export_formats=export_formats or ["docx"],
            report_title=str(payload.get("report_title", "")),
            report_types=[str(item) for item in raw_types if str(item).strip()] if isinstance(raw_types, list) else [],
            client_name=str(payload.get("client_name", "")),
            report_date=str(payload.get("report_date", "")),
            engagement_start_date=str(payload.get("engagement_start_date", "")),
            engagement_end_date=str(payload.get("engagement_end_date", "")),
            scope_items=[
                ReportScopeItem.from_dict(item)
                for item in raw_scope
                if isinstance(item, dict) and str(item.get("scope_type", "")).strip()
            ]
            if isinstance(raw_scope, list)
            else [],
            add_all_findings=_coerce_bool(payload.get("add_all_findings", True), True),
            add_report_only_findings=_coerce_bool(payload.get("add_report_only_findings", False), False),
        )


@dataclass(slots=True)
class AuditEntry:
    timestamp: str
    action: str
    summary: str
    run_id: str = ""
    workspace_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["engagement_id"] = self.workspace_id
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditEntry":
        details = payload.get("details", {})
        return cls(
            timestamp=str(payload.get("timestamp", now_iso())),
            action=str(payload.get("action", "event")),
            summary=str(payload.get("summary", "")),
            run_id=str(payload.get("run_id", "")),
            workspace_id=str(payload.get("workspace_id") or payload.get("engagement_id") or ""),
            details=details if isinstance(details, dict) else {},
        )

    @property
    def engagement_id(self) -> str:
        return self.workspace_id

    @engagement_id.setter
    def engagement_id(self, value: str) -> None:
        self.workspace_id = value


@dataclass(slots=True)
class EntityNote:
    signature: str
    entity_kind: str
    label: str = ""
    note: str = ""
    target: str = ""
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EntityNote":
        return cls(
            signature=str(payload.get("signature", "")).strip(),
            entity_kind=str(payload.get("entity_kind", "")).strip(),
            label=str(payload.get("label", "")),
            note=str(payload.get("note", "")),
            target=str(payload.get("target", "")),
            updated_at=str(payload.get("updated_at", now_iso())),
        )


@dataclass(slots=True)
class AttackTargetObject:
    target_object_id: str
    entity_kind: str
    label: str = ""
    target: str = ""
    signature: str = ""
    source_run_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    added_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackTargetObject":
        data = payload.get("data", {})
        return cls(
            target_object_id=str(payload.get("target_object_id", "")).strip(),
            entity_kind=str(payload.get("entity_kind", "")).strip(),
            label=str(payload.get("label", "")),
            target=str(payload.get("target", "")),
            signature=str(payload.get("signature", "")),
            source_run_id=str(payload.get("source_run_id", "")),
            data=data if isinstance(data, dict) else {},
            added_at=str(payload.get("added_at", now_iso())),
        )


@dataclass(slots=True)
class AttackSession:
    session_id: str
    session_type: str
    label: str = ""
    status: str = "draft"
    command: str = ""
    request: str = ""
    response: str = ""
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackSession":
        return cls(
            session_id=str(payload.get("session_id", "")).strip(),
            session_type=str(payload.get("session_type", "terminal")).strip() or "terminal",
            label=str(payload.get("label", "")),
            status=str(payload.get("status", "draft")) or "draft",
            command=str(payload.get("command", "")),
            request=str(payload.get("request", "")),
            response=str(payload.get("response", "")),
            notes=str(payload.get("notes", "")),
            metadata=dict(payload.get("metadata", {}))
            if isinstance(payload.get("metadata", {}), dict)
            else {},
            created_at=str(payload.get("created_at", now_iso())),
            updated_at=str(payload.get("updated_at", now_iso())),
        )


@dataclass(slots=True)
class AttackEvidence:
    evidence_id: str
    source: str = ""
    summary: str = ""
    raw_output: str = ""
    route_to: str = "evidence"
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackEvidence":
        return cls(
            evidence_id=str(payload.get("evidence_id", "")).strip(),
            source=str(payload.get("source", "")),
            summary=str(payload.get("summary", "")),
            raw_output=str(payload.get("raw_output", "")),
            route_to=str(payload.get("route_to", "evidence")) or "evidence",
            created_at=str(payload.get("created_at", now_iso())),
        )


@dataclass(slots=True)
class AttackWorkspace:
    attack_workspace_id: str
    name: str
    workspace_type: str = "terminal"
    status: str = "draft"
    target_objects: list[AttackTargetObject] = field(default_factory=list)
    sessions: list[AttackSession] = field(default_factory=list)
    evidence: list[AttackEvidence] = field(default_factory=list)
    notes: str = ""
    linked_findings: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_workspace_id": self.attack_workspace_id,
            "name": self.name,
            "workspace_type": self.workspace_type,
            "status": self.status,
            "target_objects": [target.to_dict() for target in self.target_objects],
            "sessions": [session.to_dict() for session in self.sessions],
            "evidence": [item.to_dict() for item in self.evidence],
            "notes": self.notes,
            "linked_findings": list(self.linked_findings),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackWorkspace":
        raw_targets = payload.get("target_objects", [])
        raw_sessions = payload.get("sessions", [])
        raw_evidence = payload.get("evidence", [])
        raw_linked = payload.get("linked_findings", [])
        return cls(
            attack_workspace_id=str(payload.get("attack_workspace_id", "")).strip(),
            name=str(payload.get("name", "Untitled Attack")).strip() or "Untitled Attack",
            workspace_type=str(payload.get("workspace_type", "terminal")).strip() or "terminal",
            status=str(payload.get("status", "draft")) or "draft",
            target_objects=[
                AttackTargetObject.from_dict(item)
                for item in raw_targets
                if isinstance(item, dict)
            ],
            sessions=[
                AttackSession.from_dict(item)
                for item in raw_sessions
                if isinstance(item, dict)
            ],
            evidence=[
                AttackEvidence.from_dict(item)
                for item in raw_evidence
                if isinstance(item, dict)
            ],
            notes=str(payload.get("notes", "")),
            linked_findings=[str(item) for item in raw_linked if str(item).strip()]
            if isinstance(raw_linked, list)
            else [],
            created_at=str(payload.get("created_at", now_iso())),
            updated_at=str(payload.get("updated_at", now_iso())),
        )


@dataclass(slots=True)
class RunSnapshot:
    run_id: str
    scan_name: str
    run_dir: str
    state: str
    elapsed_seconds: float
    eta_seconds: float | None
    current_task: str
    total_tasks: int
    completed_tasks: int
    workspace_id: str = ""
    workspace_name: str = ""
    engagement_id: str = ""
    engagement_name: str = ""
    target_input: str = ""
    profile_name: str = ""
    pause_requested: bool = False
    resume_required: bool = False
    live_process: bool = False
    tasks: list[dict[str, Any]] = field(default_factory=list)
    scope: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    web_apps: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    tls_assets: list[dict[str, Any]] = field(default_factory=list)
    site_map: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    login_surfaces: list[dict[str, Any]] = field(default_factory=list)
    replay_requests: list[dict[str, Any]] = field(default_factory=list)
    surface_signals: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    investigation_steps: list[dict[str, Any]] = field(default_factory=list)
    playbook_executions: list[dict[str, Any]] = field(default_factory=list)
    coverage_decisions: list[dict[str, Any]] = field(default_factory=list)
    validation_results: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    validation_tasks: list[dict[str, Any]] = field(default_factory=list)
    coverage_gaps: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_bundles: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    task_results: list[dict[str, Any]] = field(default_factory=list)
    tool_executions: list[dict[str, Any]] = field(default_factory=list)
    evidence_artifacts: list[dict[str, Any]] = field(default_factory=list)
    extensions: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    execution_issues: list[dict[str, Any]] = field(default_factory=list)
    execution_issues_summary: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    completeness_status: str = "healthy"

    def __post_init__(self) -> None:
        if not self.workspace_id and self.engagement_id:
            self.workspace_id = self.engagement_id
        if not self.workspace_name and self.engagement_name:
            self.workspace_name = self.engagement_name
        if not self.engagement_id and self.workspace_id:
            self.engagement_id = self.workspace_id
        if not self.engagement_name and self.workspace_name:
            self.engagement_name = self.workspace_name
