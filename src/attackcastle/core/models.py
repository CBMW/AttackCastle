from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from attackcastle.core.enums import RunState, Severity, TargetType

SCHEMA_VERSION = "2.2.0"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat()


def parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def normalize_confidence(value: float | int | None, default: float = 1.0) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed < 0.0:
        return 0.0
    if parsed > 1.0:
        return 1.0
    return parsed


@dataclass
class ScanTarget:
    target_id: str
    raw: str
    target_type: TargetType
    value: str
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    aliases: list[str] = field(default_factory=list)


@dataclass
class RunMetadata:
    run_id: str
    target_input: str
    profile: str
    output_dir: str
    started_at: datetime
    ended_at: datetime | None = None
    tool_version: str = "0.1.0"
    schema_version: str = SCHEMA_VERSION
    state: RunState = RunState.CREATED
    audience: str = "consultant"


@dataclass
class Asset:
    asset_id: str
    kind: str
    name: str
    ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    parent_asset_id: str | None = None
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None
    aliases: list[str] = field(default_factory=list)


@dataclass
class Service:
    service_id: str
    asset_id: str
    port: int
    protocol: str
    state: str
    name: str | None = None
    banner: str | None = None
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class WebApplication:
    webapp_id: str
    asset_id: str
    url: str
    service_id: str | None = None
    status_code: int | None = None
    title: str | None = None
    forms_count: int = 0
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class Technology:
    tech_id: str
    asset_id: str
    name: str
    version: str | None = None
    confidence: float = 0.5
    webapp_id: str | None = None
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class TLSAsset:
    tls_id: str
    asset_id: str
    host: str
    port: int
    service_id: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sans: list[str] = field(default_factory=list)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class Evidence:
    evidence_id: str
    source_tool: str
    kind: str
    snippet: str
    artifact_path: str | None = None
    selector: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str | None = None
    source_execution_id: str | None = None
    parser_version: str | None = None
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=now_utc)


@dataclass
class Observation:
    observation_id: str
    key: str
    value: Any
    entity_type: str
    entity_id: str
    source_tool: str
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=now_utc)
    evidence_ids: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    source_execution_id: str | None = None
    parser_version: str | None = None


@dataclass
class Assertion:
    assertion_id: str
    key: str
    value: Any
    confidence: float
    entity_refs: list[dict[str, str]]
    source_observation_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=now_utc)


@dataclass
class ToolExecution:
    execution_id: str
    tool_name: str
    command: str
    started_at: datetime
    ended_at: datetime
    exit_code: int | None
    status: str
    capability: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    transcript_path: str | None = None
    raw_artifact_paths: list[str] = field(default_factory=list)
    error_message: str | None = None
    termination_reason: str | None = None
    termination_detail: str | None = None
    timed_out: bool = False
    raw_command: str | None = None
    task_instance_key: str | None = None
    task_inputs: list[str] = field(default_factory=list)


@dataclass
class EvidenceArtifact:
    artifact_id: str
    kind: str
    path: str
    source_tool: str
    caption: str = ""
    source_task_id: str | None = None
    source_execution_id: str | None = None
    parser_version: str | None = None
    hash_sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=now_utc)


@dataclass
class NormalizedEntity:
    entity_id: str
    entity_type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    source_tool: str = "internal"
    source_task_id: str | None = None
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None
    timestamp: datetime = field(default_factory=now_utc)


@dataclass
class TaskArtifactRef:
    artifact_type: str
    path: str


@dataclass
class TaskResult:
    task_id: str
    task_type: str
    status: str
    command: str
    exit_code: int | None
    started_at: datetime
    finished_at: datetime
    transcript_path: str | None = None
    raw_artifacts: list[TaskArtifactRef] = field(default_factory=list)
    parsed_entities: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    termination_reason: str | None = None
    termination_detail: str | None = None
    timed_out: bool = False
    raw_command: str | None = None
    task_instance_key: str | None = None
    task_inputs: list[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    template_id: str
    title: str
    severity: Severity
    category: str
    description: str
    impact: str
    likelihood: str
    recommendations: list[str]
    references: list[str]
    tags: list[str]
    affected_entities: list[dict[str, str]]
    evidence_ids: list[str]
    plextrac: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    status: str = "confirmed"
    evidence_quality_score: float = 0.0
    corroboration: dict[str, Any] = field(default_factory=dict)
    quality_notes: list[str] = field(default_factory=list)


@dataclass
class Lead:
    lead_id: str
    title: str
    category: str
    priority_score: int
    priority_label: str
    confidence: float = 0.7
    status: str = "manual-review"
    why_it_matters: str = ""
    reasoning: str = ""
    suggested_next_steps: list[str] = field(default_factory=list)
    likely_finding: str | None = None
    likely_severity: str | None = None
    draft_finding_seed: str | None = None
    tags: list[str] = field(default_factory=list)
    affected_entities: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    source_observation_ids: list[str] = field(default_factory=list)
    detection_sources: list[str] = field(default_factory=list)


@dataclass
class EvidenceBundle:
    bundle_id: str
    label: str
    entity_type: str
    entity_id: str
    asset_id: str | None = None
    summary: str = ""
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    artifact_paths: list[str] = field(default_factory=list)
    screenshot_paths: list[str] = field(default_factory=list)
    raw_output_paths: list[str] = field(default_factory=list)
    source_tools: list[str] = field(default_factory=list)


@dataclass
class EntityRelationship:
    relationship_id: str
    source_entity_type: str
    source_entity_id: str
    target_entity_type: str
    target_entity_id: str
    relationship_type: str
    source_tool: str = "internal"
    source_execution_id: str | None = None
    discovered_from_entity_type: str | None = None
    discovered_from_entity_id: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Endpoint:
    endpoint_id: str
    webapp_id: str
    asset_id: str
    url: str
    path: str
    service_id: str | None = None
    method: str | None = None
    kind: str = "endpoint"
    tags: list[str] = field(default_factory=list)
    auth_hints: list[str] = field(default_factory=list)
    confidence: float = 0.7
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class Parameter:
    parameter_id: str
    webapp_id: str
    name: str
    location: str = "unknown"
    endpoint_id: str | None = None
    example_value: str | None = None
    inferred_type: str | None = None
    sensitive: bool = False
    confidence: float = 0.6
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class Form:
    form_id: str
    webapp_id: str
    action_url: str
    method: str = "GET"
    endpoint_id: str | None = None
    field_names: list[str] = field(default_factory=list)
    has_password: bool = False
    confidence: float = 0.7
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class LoginSurface:
    login_surface_id: str
    webapp_id: str
    url: str
    endpoint_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    username_fields: list[str] = field(default_factory=list)
    password_fields: list[str] = field(default_factory=list)
    auth_hints: list[str] = field(default_factory=list)
    confidence: float = 0.75
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class ReplayRequest:
    replay_request_id: str
    webapp_id: str
    asset_id: str
    url: str
    method: str = "GET"
    endpoint_id: str | None = None
    service_id: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    parameter_names: list[str] = field(default_factory=list)
    body_field_names: list[str] = field(default_factory=list)
    cookie_names: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    auth_hints: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    replay_enabled: bool = True
    confidence: float = 0.7
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class SurfaceSignal:
    surface_signal_id: str
    signal_key: str
    signal_type: str
    summary: str
    entity_type: str = ""
    entity_id: str = ""
    service_id: str | None = None
    protocol_family: str = ""
    source_category: str = ""
    webapp_id: str = ""
    replay_request_id: str | None = None
    endpoint_id: str | None = None
    parameter_name: str | None = None
    confidence: float = 0.7
    severity_hint: str = "info"
    evidence_ids: list[str] = field(default_factory=list)
    source_observation_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class InvestigationStep:
    investigation_step_id: str
    attack_path_id: str
    playbook_key: str
    step_key: str
    title: str
    protocol_family: str = ""
    transport: str = ""
    status: str = "ready"
    priority_score: int = 0
    rationale: str = ""
    expected_proof: str = ""
    evidence_goal: str = ""
    request_target: str = ""
    attempt_index: int = 0
    auto_runnable: bool = True
    entry_signal_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class ResponseDelta:
    response_delta_id: str
    replay_request_id: str
    attack_path_id: str = ""
    step_key: str = ""
    protocol_family: str = ""
    interaction_target: str = ""
    comparison_type: str = "baseline"
    summary: str = ""
    status_before: int | None = None
    status_after: int | None = None
    body_changed: bool = False
    header_changed: bool = False
    length_before: int = 0
    length_after: int = 0
    length_delta: int = 0
    timing_delta_ms: float | None = None
    similarity_score: float | None = None
    header_deltas: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class AuthorizationComparison:
    authorization_comparison_id: str
    attack_path_id: str
    replay_request_id: str
    parameter_name: str = ""
    baseline_status: int | None = None
    candidate_status: int | None = None
    baseline_length: int = 0
    candidate_length: int = 0
    similarity_score: float | None = None
    outcome: str = "not_applicable"
    reason: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class ProofOutcome:
    proof_outcome_id: str
    attack_path_id: str
    playbook_key: str
    step_key: str
    status: str
    reason: str
    strength: str = "weak"
    validation_result_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class PlaybookExecution:
    playbook_execution_id: str
    attack_path_id: str
    playbook_key: str
    status: str
    wave: str = "validation"
    attempt_count: int = 0
    last_attempted_at: datetime | None = None
    next_revisit_at: datetime | None = None
    entry_signal_ids: list[str] = field(default_factory=list)
    executed_step_ids: list[str] = field(default_factory=list)
    next_step_id: str | None = None
    proof_outcome_id: str | None = None
    summary: str = ""
    coverage_decision_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class CoverageDecision:
    coverage_decision_id: str
    attack_path_id: str
    playbook_key: str
    status: str
    reason: str
    wave: str = "validation"
    next_action: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class ValidationResult:
    validation_result_id: str
    replay_request_id: str
    webapp_id: str
    validator_key: str
    family: str
    category: str
    status: str
    title: str
    summary: str
    entity_type: str = ""
    entity_id: str = ""
    service_id: str | None = None
    protocol_family: str = ""
    severity_hint: str = "info"
    request_url: str = ""
    request_method: str = "GET"
    mutated: bool = False
    confidence: float = 0.7
    coverage_lane_id: str | None = None
    attack_path_id: str | None = None
    playbook_key: str = ""
    step_key: str = ""
    entry_signal_ids: list[str] = field(default_factory=list)
    response_delta: dict[str, Any] = field(default_factory=dict)
    stop_reason: str = ""
    proof_strength: str = "medium"
    evidence_ids: list[str] = field(default_factory=list)
    source_observation_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "internal"
    source_execution_id: str | None = None
    parser_version: str | None = None
    canonical_key: str | None = None


@dataclass
class Hypothesis:
    hypothesis_id: str
    title: str
    exploit_class: str
    confidence: float
    priority_score: int
    severity_hint: str = "info"
    status: str = "hypothesized"
    approval_class: str = "safe_auto"
    playbook: str = ""
    reasoning: str = ""
    next_validation_step: str = ""
    validation_capability: str | None = None
    task_key: str | None = None
    attack_path_id: str | None = None
    step_key: str = ""
    affected_entities: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    required_preconditions: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    evidence_goals: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source_observation_ids: list[str] = field(default_factory=list)


@dataclass
class ValidationTask:
    validation_task_id: str
    hypothesis_id: str
    title: str
    exploit_class: str
    status: str
    approval_class: str
    rationale: str = ""
    next_action: str = ""
    validation_capability: str | None = None
    task_key: str | None = None
    attack_path_id: str | None = None
    playbook_key: str = ""
    step_key: str = ""
    auto_runnable: bool = False
    command_preview: list[str] = field(default_factory=list)
    affected_entities: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    blocking_reason: str | None = None
    result: str | None = None


@dataclass
class ApprovalDecision:
    decision_id: str
    approval_class: str
    status: str
    scope_key: str
    created_at: datetime = field(default_factory=now_utc)
    task_key: str | None = None
    hypothesis_id: str | None = None
    validation_task_id: str | None = None
    decided_by: str = "system"
    reason: str = ""


@dataclass
class AttackPath:
    attack_path_id: str
    title: str
    summary: str
    risk_score: int
    entity_type: str = ""
    entity_id: str = ""
    service_id: str | None = None
    protocol_family: str = ""
    playbook_key: str = ""
    wave: str = "validation"
    status: str = "ready"
    priority_score: int = 0
    proof_status: str = "candidate"
    attempt_count: int = 0
    last_attempted_at: datetime | None = None
    next_revisit_at: datetime | None = None
    next_step_id: str | None = None
    next_action: str = ""
    entry_signal_ids: list[str] = field(default_factory=list)
    current_step_ids: list[str] = field(default_factory=list)
    affected_entities: list[dict[str, str]] = field(default_factory=list)
    step_titles: list[str] = field(default_factory=list)
    hypothesis_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    coverage_decision_id: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class CoverageGap:
    coverage_gap_id: str
    title: str
    source: str
    reason: str
    status: str = "coverage_gap"
    impact: str = ""
    suggested_action: str = ""
    url: str | None = None
    attack_path_id: str | None = None
    playbook_key: str = ""
    coverage_decision_id: str | None = None
    affected_entities: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    source_tool: str = "internal"


@dataclass
class RunData:
    metadata: RunMetadata
    scope: list[ScanTarget] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    web_apps: list[WebApplication] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    tls_assets: list[TLSAsset] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    login_surfaces: list[LoginSurface] = field(default_factory=list)
    replay_requests: list[ReplayRequest] = field(default_factory=list)
    surface_signals: list[SurfaceSignal] = field(default_factory=list)
    investigation_steps: list[InvestigationStep] = field(default_factory=list)
    response_deltas: list[ResponseDelta] = field(default_factory=list)
    authorization_comparisons: list[AuthorizationComparison] = field(default_factory=list)
    proof_outcomes: list[ProofOutcome] = field(default_factory=list)
    playbook_executions: list[PlaybookExecution] = field(default_factory=list)
    coverage_decisions: list[CoverageDecision] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    assertions: list[Assertion] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    evidence_bundles: list[EvidenceBundle] = field(default_factory=list)
    relationships: list[EntityRelationship] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    validation_tasks: list[ValidationTask] = field(default_factory=list)
    approval_decisions: list[ApprovalDecision] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    normalized_entities: list[NormalizedEntity] = field(default_factory=list)
    evidence_artifacts: list[EvidenceArtifact] = field(default_factory=list)
    task_results: list[TaskResult] = field(default_factory=list)
    tool_executions: list[ToolExecution] = field(default_factory=list)
    task_states: list[dict[str, Any]] = field(default_factory=list)
    state_history: list[dict[str, Any]] = field(default_factory=list)
    alias_map: dict[str, list[str]] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _serialize_value(value: Any) -> Any:
    if is_dataclass(value):
        return _serialize_value(asdict(value))
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    return value


def to_serializable(obj: Any) -> Any:
    return _serialize_value(obj)


def _target_from_dict(data: dict[str, Any]) -> ScanTarget:
    return ScanTarget(
        target_id=data["target_id"],
        raw=data.get("raw", data.get("value", "")),
        target_type=TargetType(data.get("target_type", "unknown")),
        value=data.get("value", ""),
        host=data.get("host"),
        port=data.get("port"),
        scheme=data.get("scheme"),
        aliases=list(data.get("aliases", [])),
    )


def _metadata_from_dict(data: dict[str, Any]) -> RunMetadata:
    state = data.get("state", RunState.CREATED.value)
    return RunMetadata(
        run_id=data["run_id"],
        target_input=data.get("target_input", ""),
        profile=data.get("profile", "cautious"),
        output_dir=data.get("output_dir", ""),
        started_at=parse_datetime(data.get("started_at")) or now_utc(),
        ended_at=parse_datetime(data.get("ended_at")),
        tool_version=data.get("tool_version", "0.1.0"),
        schema_version=data.get("schema_version", SCHEMA_VERSION),
        state=RunState(state) if isinstance(state, str) else state,
        audience=data.get("audience", "consultant"),
    )


def _asset_from_dict(data: dict[str, Any]) -> Asset:
    return Asset(
        asset_id=data["asset_id"],
        kind=data["kind"],
        name=data["name"],
        ip=data.get("ip"),
        resolved_ips=list(data.get("resolved_ips", [])),
        parent_asset_id=data.get("parent_asset_id"),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
        aliases=list(data.get("aliases", [])),
    )


def _service_from_dict(data: dict[str, Any]) -> Service:
    return Service(
        service_id=data["service_id"],
        asset_id=data["asset_id"],
        port=int(data["port"]),
        protocol=data.get("protocol", "tcp"),
        state=data.get("state", "open"),
        name=data.get("name"),
        banner=data.get("banner"),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _web_from_dict(data: dict[str, Any]) -> WebApplication:
    return WebApplication(
        webapp_id=data["webapp_id"],
        asset_id=data["asset_id"],
        url=data["url"],
        service_id=data.get("service_id"),
        status_code=data.get("status_code"),
        title=data.get("title"),
        forms_count=int(data.get("forms_count", 0)),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _tech_from_dict(data: dict[str, Any]) -> Technology:
    return Technology(
        tech_id=data["tech_id"],
        asset_id=data["asset_id"],
        name=data["name"],
        version=data.get("version"),
        confidence=normalize_confidence(data.get("confidence"), default=0.5),
        webapp_id=data.get("webapp_id"),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _tls_from_dict(data: dict[str, Any]) -> TLSAsset:
    return TLSAsset(
        tls_id=data["tls_id"],
        asset_id=data["asset_id"],
        host=data["host"],
        port=int(data["port"]),
        service_id=data.get("service_id"),
        protocol=data.get("protocol"),
        cipher=data.get("cipher"),
        subject=data.get("subject"),
        issuer=data.get("issuer"),
        not_before=data.get("not_before"),
        not_after=data.get("not_after"),
        sans=list(data.get("sans", [])),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _evidence_from_dict(data: dict[str, Any]) -> Evidence:
    return Evidence(
        evidence_id=data["evidence_id"],
        source_tool=data.get("source_tool", "internal"),
        kind=data.get("kind", "artifact"),
        snippet=data.get("snippet", ""),
        artifact_path=data.get("artifact_path"),
        selector=dict(data.get("selector", {})),
        evidence_hash=data.get("evidence_hash"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        confidence=normalize_confidence(data.get("confidence"), default=1.0),
        timestamp=parse_datetime(data.get("timestamp")) or now_utc(),
    )


def _observation_from_dict(data: dict[str, Any]) -> Observation:
    return Observation(
        observation_id=data["observation_id"],
        key=data["key"],
        value=data.get("value"),
        entity_type=data["entity_type"],
        entity_id=data["entity_id"],
        source_tool=data.get("source_tool", "internal"),
        confidence=normalize_confidence(data.get("confidence"), default=1.0),
        timestamp=parse_datetime(data.get("timestamp")) or now_utc(),
        evidence_ids=list(data.get("evidence_ids", [])),
        derived_from=list(data.get("derived_from", [])),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
    )


def _assertion_from_dict(data: dict[str, Any]) -> Assertion:
    return Assertion(
        assertion_id=data["assertion_id"],
        key=data["key"],
        value=data.get("value"),
        confidence=normalize_confidence(data.get("confidence"), default=0.8),
        entity_refs=list(data.get("entity_refs", [])),
        source_observation_ids=list(data.get("source_observation_ids", [])),
        created_at=parse_datetime(data.get("created_at")) or now_utc(),
    )


def _execution_from_dict(data: dict[str, Any]) -> ToolExecution:
    return ToolExecution(
        execution_id=data["execution_id"],
        tool_name=data.get("tool_name", "unknown"),
        command=data.get("command", ""),
        started_at=parse_datetime(data.get("started_at")) or now_utc(),
        ended_at=parse_datetime(data.get("ended_at")) or now_utc(),
        exit_code=data.get("exit_code"),
        status=data.get("status", "unknown"),
        capability=data.get("capability"),
        stdout_path=data.get("stdout_path"),
        stderr_path=data.get("stderr_path"),
        transcript_path=data.get("transcript_path"),
        raw_artifact_paths=list(data.get("raw_artifact_paths", [])),
        error_message=data.get("error_message"),
        termination_reason=data.get("termination_reason"),
        termination_detail=data.get("termination_detail"),
        timed_out=bool(data.get("timed_out", False)),
        raw_command=data.get("raw_command") or data.get("command", ""),
        task_instance_key=data.get("task_instance_key"),
        task_inputs=[str(item) for item in data.get("task_inputs", []) if str(item).strip()]
        if isinstance(data.get("task_inputs", []), list)
        else [],
    )


def _evidence_artifact_from_dict(data: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        artifact_id=data["artifact_id"],
        kind=data.get("kind", "artifact"),
        path=data.get("path", ""),
        source_tool=data.get("source_tool", "internal"),
        caption=data.get("caption", ""),
        source_task_id=data.get("source_task_id"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        hash_sha256=data.get("hash_sha256"),
        metadata=dict(data.get("metadata", {})),
        timestamp=parse_datetime(data.get("timestamp")) or now_utc(),
    )


def _normalized_entity_from_dict(data: dict[str, Any]) -> NormalizedEntity:
    return NormalizedEntity(
        entity_id=data["entity_id"],
        entity_type=data.get("entity_type", "unknown"),
        attributes=dict(data.get("attributes", {})),
        evidence_ids=list(data.get("evidence_ids", [])),
        source_tool=data.get("source_tool", "internal"),
        source_task_id=data.get("source_task_id"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
        timestamp=parse_datetime(data.get("timestamp")) or now_utc(),
    )


def _task_artifact_ref_from_dict(data: dict[str, Any]) -> TaskArtifactRef:
    return TaskArtifactRef(
        artifact_type=data.get("artifact_type", "raw"),
        path=data.get("path", ""),
    )


def _task_result_from_dict(data: dict[str, Any]) -> TaskResult:
    return TaskResult(
        task_id=data["task_id"],
        task_type=data.get("task_type", ""),
        status=data.get("status", "unknown"),
        command=data.get("command", ""),
        exit_code=data.get("exit_code"),
        started_at=parse_datetime(data.get("started_at")) or now_utc(),
        finished_at=parse_datetime(data.get("finished_at")) or now_utc(),
        transcript_path=data.get("transcript_path"),
        raw_artifacts=[_task_artifact_ref_from_dict(item) for item in data.get("raw_artifacts", [])],
        parsed_entities=list(data.get("parsed_entities", [])),
        metrics=dict(data.get("metrics", {})),
        warnings=list(data.get("warnings", [])),
        termination_reason=data.get("termination_reason"),
        termination_detail=data.get("termination_detail"),
        timed_out=bool(data.get("timed_out", False)),
        raw_command=data.get("raw_command") or data.get("command", ""),
        task_instance_key=data.get("task_instance_key"),
        task_inputs=[str(item) for item in data.get("task_inputs", []) if str(item).strip()]
        if isinstance(data.get("task_inputs", []), list)
        else [],
    )


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    severity_value = data.get("severity", Severity.INFO.value)
    severity = Severity(severity_value) if isinstance(severity_value, str) else severity_value
    return Finding(
        finding_id=data["finding_id"],
        template_id=data.get("template_id", ""),
        title=data.get("title", ""),
        severity=severity,
        category=data.get("category", "General"),
        description=data.get("description", ""),
        impact=data.get("impact", ""),
        likelihood=data.get("likelihood", ""),
        recommendations=list(data.get("recommendations", [])),
        references=list(data.get("references", [])),
        tags=list(data.get("tags", [])),
        affected_entities=list(data.get("affected_entities", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        plextrac=dict(data.get("plextrac", {})),
        fingerprint=data.get("fingerprint"),
        suppressed=bool(data.get("suppressed", False)),
        suppression_reason=data.get("suppression_reason"),
        status=data.get("status", "confirmed"),
        evidence_quality_score=float(data.get("evidence_quality_score", 0.0)),
        corroboration=dict(data.get("corroboration", {})),
        quality_notes=list(data.get("quality_notes", [])),
    )


def _lead_from_dict(data: dict[str, Any]) -> Lead:
    return Lead(
        lead_id=data["lead_id"],
        title=data.get("title", ""),
        category=data.get("category", "General"),
        priority_score=int(data.get("priority_score", 0)),
        priority_label=data.get("priority_label", "low"),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        status=data.get("status", "manual-review"),
        why_it_matters=data.get("why_it_matters", ""),
        reasoning=data.get("reasoning", ""),
        suggested_next_steps=list(data.get("suggested_next_steps", [])),
        likely_finding=data.get("likely_finding"),
        likely_severity=data.get("likely_severity"),
        draft_finding_seed=data.get("draft_finding_seed"),
        tags=list(data.get("tags", [])),
        affected_entities=list(data.get("affected_entities", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        source_observation_ids=list(data.get("source_observation_ids", [])),
        detection_sources=list(data.get("detection_sources", [])),
    )


def _evidence_bundle_from_dict(data: dict[str, Any]) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id=data["bundle_id"],
        label=data.get("label", ""),
        entity_type=data.get("entity_type", "asset"),
        entity_id=data.get("entity_id", ""),
        asset_id=data.get("asset_id"),
        summary=data.get("summary", ""),
        confidence=normalize_confidence(data.get("confidence"), default=0.0),
        evidence_ids=list(data.get("evidence_ids", [])),
        artifact_paths=list(data.get("artifact_paths", [])),
        screenshot_paths=list(data.get("screenshot_paths", [])),
        raw_output_paths=list(data.get("raw_output_paths", [])),
        source_tools=list(data.get("source_tools", [])),
    )


def _relationship_from_dict(data: dict[str, Any]) -> EntityRelationship:
    return EntityRelationship(
        relationship_id=data["relationship_id"],
        source_entity_type=data.get("source_entity_type", ""),
        source_entity_id=data.get("source_entity_id", ""),
        target_entity_type=data.get("target_entity_type", ""),
        target_entity_id=data.get("target_entity_id", ""),
        relationship_type=data.get("relationship_type", "related_to"),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        discovered_from_entity_type=data.get("discovered_from_entity_type"),
        discovered_from_entity_id=data.get("discovered_from_entity_id"),
        first_seen_at=parse_datetime(data.get("first_seen_at")),
        last_seen_at=parse_datetime(data.get("last_seen_at")),
        confidence=normalize_confidence(data.get("confidence"), default=1.0),
        metadata=dict(data.get("metadata", {})),
    )


def _endpoint_from_dict(data: dict[str, Any]) -> Endpoint:
    return Endpoint(
        endpoint_id=data["endpoint_id"],
        webapp_id=data["webapp_id"],
        asset_id=data["asset_id"],
        url=data.get("url", ""),
        path=data.get("path", "/"),
        service_id=data.get("service_id"),
        method=data.get("method"),
        kind=data.get("kind", "endpoint"),
        tags=list(data.get("tags", [])),
        auth_hints=list(data.get("auth_hints", [])),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _parameter_from_dict(data: dict[str, Any]) -> Parameter:
    return Parameter(
        parameter_id=data["parameter_id"],
        webapp_id=data["webapp_id"],
        name=data.get("name", ""),
        location=data.get("location", "unknown"),
        endpoint_id=data.get("endpoint_id"),
        example_value=data.get("example_value"),
        inferred_type=data.get("inferred_type"),
        sensitive=bool(data.get("sensitive", False)),
        confidence=normalize_confidence(data.get("confidence"), default=0.6),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _form_from_dict(data: dict[str, Any]) -> Form:
    return Form(
        form_id=data["form_id"],
        webapp_id=data["webapp_id"],
        action_url=data.get("action_url", ""),
        method=data.get("method", "GET"),
        endpoint_id=data.get("endpoint_id"),
        field_names=list(data.get("field_names", [])),
        has_password=bool(data.get("has_password", False)),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _login_surface_from_dict(data: dict[str, Any]) -> LoginSurface:
    return LoginSurface(
        login_surface_id=data["login_surface_id"],
        webapp_id=data["webapp_id"],
        url=data.get("url", ""),
        endpoint_id=data.get("endpoint_id"),
        reasons=list(data.get("reasons", [])),
        username_fields=list(data.get("username_fields", [])),
        password_fields=list(data.get("password_fields", [])),
        auth_hints=list(data.get("auth_hints", [])),
        confidence=normalize_confidence(data.get("confidence"), default=0.75),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _replay_request_from_dict(data: dict[str, Any]) -> ReplayRequest:
    return ReplayRequest(
        replay_request_id=data["replay_request_id"],
        webapp_id=data["webapp_id"],
        asset_id=data.get("asset_id", ""),
        url=data.get("url", ""),
        method=data.get("method", "GET"),
        endpoint_id=data.get("endpoint_id"),
        service_id=data.get("service_id"),
        headers=dict(data.get("headers", {})),
        parameter_names=list(data.get("parameter_names", [])),
        body_field_names=list(data.get("body_field_names", [])),
        cookie_names=list(data.get("cookie_names", [])),
        tags=list(data.get("tags", [])),
        auth_hints=list(data.get("auth_hints", [])),
        context=dict(data.get("context", {})),
        replay_enabled=bool(data.get("replay_enabled", True)),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _surface_signal_from_dict(data: dict[str, Any]) -> SurfaceSignal:
    return SurfaceSignal(
        surface_signal_id=data["surface_signal_id"],
        signal_key=data.get("signal_key", ""),
        signal_type=data.get("signal_type", "generic"),
        summary=data.get("summary", ""),
        entity_type=data.get("entity_type", ""),
        entity_id=data.get("entity_id", ""),
        service_id=data.get("service_id"),
        protocol_family=data.get("protocol_family", ""),
        source_category=data.get("source_category", ""),
        webapp_id=data.get("webapp_id", ""),
        replay_request_id=data.get("replay_request_id"),
        endpoint_id=data.get("endpoint_id"),
        parameter_name=data.get("parameter_name"),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        severity_hint=data.get("severity_hint", "info"),
        evidence_ids=list(data.get("evidence_ids", [])),
        source_observation_ids=list(data.get("source_observation_ids", [])),
        tags=list(data.get("tags", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _investigation_step_from_dict(data: dict[str, Any]) -> InvestigationStep:
    return InvestigationStep(
        investigation_step_id=data["investigation_step_id"],
        attack_path_id=data.get("attack_path_id", ""),
        playbook_key=data.get("playbook_key", ""),
        step_key=data.get("step_key", ""),
        title=data.get("title", ""),
        protocol_family=data.get("protocol_family", ""),
        transport=data.get("transport", ""),
        status=data.get("status", "ready"),
        priority_score=int(data.get("priority_score", 0)),
        rationale=data.get("rationale", ""),
        expected_proof=data.get("expected_proof", ""),
        evidence_goal=data.get("evidence_goal", ""),
        request_target=data.get("request_target", ""),
        attempt_index=int(data.get("attempt_index", 0)),
        auto_runnable=bool(data.get("auto_runnable", True)),
        entry_signal_ids=list(data.get("entry_signal_ids", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _response_delta_from_dict(data: dict[str, Any]) -> ResponseDelta:
    return ResponseDelta(
        response_delta_id=data["response_delta_id"],
        replay_request_id=data.get("replay_request_id", ""),
        attack_path_id=data.get("attack_path_id", ""),
        step_key=data.get("step_key", ""),
        protocol_family=data.get("protocol_family", ""),
        interaction_target=data.get("interaction_target", ""),
        comparison_type=data.get("comparison_type", "baseline"),
        summary=data.get("summary", ""),
        status_before=data.get("status_before"),
        status_after=data.get("status_after"),
        body_changed=bool(data.get("body_changed", False)),
        header_changed=bool(data.get("header_changed", False)),
        length_before=int(data.get("length_before", 0)),
        length_after=int(data.get("length_after", 0)),
        length_delta=int(data.get("length_delta", 0)),
        timing_delta_ms=float(data["timing_delta_ms"]) if data.get("timing_delta_ms") is not None else None,
        similarity_score=float(data["similarity_score"]) if data.get("similarity_score") is not None else None,
        header_deltas=dict(data.get("header_deltas", {})),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _authorization_comparison_from_dict(data: dict[str, Any]) -> AuthorizationComparison:
    return AuthorizationComparison(
        authorization_comparison_id=data["authorization_comparison_id"],
        attack_path_id=data.get("attack_path_id", ""),
        replay_request_id=data.get("replay_request_id", ""),
        parameter_name=data.get("parameter_name", ""),
        baseline_status=data.get("baseline_status"),
        candidate_status=data.get("candidate_status"),
        baseline_length=int(data.get("baseline_length", 0)),
        candidate_length=int(data.get("candidate_length", 0)),
        similarity_score=float(data["similarity_score"]) if data.get("similarity_score") is not None else None,
        outcome=data.get("outcome", "not_applicable"),
        reason=data.get("reason", ""),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _proof_outcome_from_dict(data: dict[str, Any]) -> ProofOutcome:
    return ProofOutcome(
        proof_outcome_id=data["proof_outcome_id"],
        attack_path_id=data.get("attack_path_id", ""),
        playbook_key=data.get("playbook_key", ""),
        step_key=data.get("step_key", ""),
        status=data.get("status", "candidate"),
        reason=data.get("reason", ""),
        strength=data.get("strength", "weak"),
        validation_result_id=data.get("validation_result_id"),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _playbook_execution_from_dict(data: dict[str, Any]) -> PlaybookExecution:
    return PlaybookExecution(
        playbook_execution_id=data["playbook_execution_id"],
        attack_path_id=data.get("attack_path_id", ""),
        playbook_key=data.get("playbook_key", ""),
        status=data.get("status", "ready"),
        wave=data.get("wave", "validation"),
        attempt_count=int(data.get("attempt_count", 0)),
        last_attempted_at=parse_datetime(data.get("last_attempted_at")),
        next_revisit_at=parse_datetime(data.get("next_revisit_at")),
        entry_signal_ids=list(data.get("entry_signal_ids", [])),
        executed_step_ids=list(data.get("executed_step_ids", [])),
        next_step_id=data.get("next_step_id"),
        proof_outcome_id=data.get("proof_outcome_id"),
        summary=data.get("summary", ""),
        coverage_decision_id=data.get("coverage_decision_id"),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _coverage_decision_from_dict(data: dict[str, Any]) -> CoverageDecision:
    return CoverageDecision(
        coverage_decision_id=data["coverage_decision_id"],
        attack_path_id=data.get("attack_path_id", ""),
        playbook_key=data.get("playbook_key", ""),
        status=data.get("status", "insufficient_signal"),
        wave=data.get("wave", "validation"),
        reason=data.get("reason", ""),
        next_action=data.get("next_action", ""),
        evidence_ids=list(data.get("evidence_ids", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _validation_result_from_dict(data: dict[str, Any]) -> ValidationResult:
    return ValidationResult(
        validation_result_id=data["validation_result_id"],
        replay_request_id=data.get("replay_request_id", ""),
        webapp_id=data.get("webapp_id", ""),
        validator_key=data.get("validator_key", ""),
        family=data.get("family", "general"),
        category=data.get("category", "validation"),
        status=data.get("status", "candidate"),
        title=data.get("title", ""),
        summary=data.get("summary", ""),
        entity_type=data.get("entity_type", ""),
        entity_id=data.get("entity_id", ""),
        service_id=data.get("service_id"),
        protocol_family=data.get("protocol_family", ""),
        severity_hint=data.get("severity_hint", "info"),
        request_url=data.get("request_url", ""),
        request_method=data.get("request_method", "GET"),
        mutated=bool(data.get("mutated", False)),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        coverage_lane_id=data.get("coverage_lane_id"),
        attack_path_id=data.get("attack_path_id"),
        playbook_key=data.get("playbook_key", ""),
        step_key=data.get("step_key", ""),
        entry_signal_ids=list(data.get("entry_signal_ids", [])),
        response_delta=dict(data.get("response_delta", {})),
        stop_reason=data.get("stop_reason", ""),
        proof_strength=data.get("proof_strength", "medium"),
        evidence_ids=list(data.get("evidence_ids", [])),
        source_observation_ids=list(data.get("source_observation_ids", [])),
        tags=list(data.get("tags", [])),
        details=dict(data.get("details", {})),
        source_tool=data.get("source_tool", "internal"),
        source_execution_id=data.get("source_execution_id"),
        parser_version=data.get("parser_version"),
        canonical_key=data.get("canonical_key"),
    )


def _hypothesis_from_dict(data: dict[str, Any]) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=data["hypothesis_id"],
        title=data.get("title", ""),
        exploit_class=data.get("exploit_class", "exposure"),
        confidence=normalize_confidence(data.get("confidence"), default=0.7),
        priority_score=int(data.get("priority_score", 0)),
        severity_hint=data.get("severity_hint", "info"),
        status=data.get("status", "hypothesized"),
        approval_class=data.get("approval_class", "safe_auto"),
        playbook=data.get("playbook", ""),
        reasoning=data.get("reasoning", ""),
        next_validation_step=data.get("next_validation_step", ""),
        validation_capability=data.get("validation_capability"),
        task_key=data.get("task_key"),
        attack_path_id=data.get("attack_path_id"),
        step_key=data.get("step_key", ""),
        affected_entities=list(data.get("affected_entities", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        required_preconditions=list(data.get("required_preconditions", [])),
        stop_conditions=list(data.get("stop_conditions", [])),
        evidence_goals=list(data.get("evidence_goals", [])),
        tags=list(data.get("tags", [])),
        source_observation_ids=list(data.get("source_observation_ids", [])),
    )


def _validation_task_from_dict(data: dict[str, Any]) -> ValidationTask:
    return ValidationTask(
        validation_task_id=data["validation_task_id"],
        hypothesis_id=data["hypothesis_id"],
        title=data.get("title", ""),
        exploit_class=data.get("exploit_class", "exposure"),
        status=data.get("status", "discovered"),
        approval_class=data.get("approval_class", "safe_auto"),
        rationale=data.get("rationale", ""),
        next_action=data.get("next_action", ""),
        validation_capability=data.get("validation_capability"),
        task_key=data.get("task_key"),
        attack_path_id=data.get("attack_path_id"),
        playbook_key=data.get("playbook_key", ""),
        step_key=data.get("step_key", ""),
        auto_runnable=bool(data.get("auto_runnable", False)),
        command_preview=list(data.get("command_preview", [])),
        affected_entities=list(data.get("affected_entities", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        related_finding_ids=list(data.get("related_finding_ids", [])),
        blocking_reason=data.get("blocking_reason"),
        result=data.get("result"),
    )


def _approval_decision_from_dict(data: dict[str, Any]) -> ApprovalDecision:
    return ApprovalDecision(
        decision_id=data["decision_id"],
        approval_class=data.get("approval_class", "safe_auto"),
        status=data.get("status", "approved"),
        scope_key=data.get("scope_key", ""),
        created_at=parse_datetime(data.get("created_at")) or now_utc(),
        task_key=data.get("task_key"),
        hypothesis_id=data.get("hypothesis_id"),
        validation_task_id=data.get("validation_task_id"),
        decided_by=data.get("decided_by", "system"),
        reason=data.get("reason", ""),
    )


def _attack_path_from_dict(data: dict[str, Any]) -> AttackPath:
    return AttackPath(
        attack_path_id=data["attack_path_id"],
        title=data.get("title", ""),
        summary=data.get("summary", ""),
        risk_score=int(data.get("risk_score", 0)),
        entity_type=data.get("entity_type", ""),
        entity_id=data.get("entity_id", ""),
        service_id=data.get("service_id"),
        protocol_family=data.get("protocol_family", ""),
        playbook_key=data.get("playbook_key", ""),
        wave=data.get("wave", "validation"),
        status=data.get("status", "ready"),
        priority_score=int(data.get("priority_score", 0)),
        proof_status=data.get("proof_status", "candidate"),
        attempt_count=int(data.get("attempt_count", 0)),
        last_attempted_at=parse_datetime(data.get("last_attempted_at")),
        next_revisit_at=parse_datetime(data.get("next_revisit_at")),
        next_step_id=data.get("next_step_id"),
        next_action=data.get("next_action", ""),
        entry_signal_ids=list(data.get("entry_signal_ids", [])),
        current_step_ids=list(data.get("current_step_ids", [])),
        affected_entities=list(data.get("affected_entities", [])),
        step_titles=list(data.get("step_titles", [])),
        hypothesis_ids=list(data.get("hypothesis_ids", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        coverage_decision_id=data.get("coverage_decision_id"),
        tags=list(data.get("tags", [])),
    )


def _coverage_gap_from_dict(data: dict[str, Any]) -> CoverageGap:
    return CoverageGap(
        coverage_gap_id=data["coverage_gap_id"],
        title=data.get("title", ""),
        source=data.get("source", ""),
        reason=data.get("reason", ""),
        status=data.get("status", "coverage_gap"),
        impact=data.get("impact", ""),
        suggested_action=data.get("suggested_action", ""),
        url=data.get("url"),
        attack_path_id=data.get("attack_path_id"),
        playbook_key=data.get("playbook_key", ""),
        coverage_decision_id=data.get("coverage_decision_id"),
        affected_entities=list(data.get("affected_entities", [])),
        evidence_ids=list(data.get("evidence_ids", [])),
        source_tool=data.get("source_tool", "internal"),
    )


def run_data_from_dict(payload: dict[str, Any]) -> RunData:
    metadata = _metadata_from_dict(payload["metadata"])
    return RunData(
        metadata=metadata,
        scope=[_target_from_dict(item) for item in payload.get("scope", [])],
        assets=[_asset_from_dict(item) for item in payload.get("assets", [])],
        services=[_service_from_dict(item) for item in payload.get("services", [])],
        web_apps=[_web_from_dict(item) for item in payload.get("web_apps", [])],
        technologies=[_tech_from_dict(item) for item in payload.get("technologies", [])],
        tls_assets=[_tls_from_dict(item) for item in payload.get("tls_assets", [])],
        endpoints=[_endpoint_from_dict(item) for item in payload.get("endpoints", [])],
        parameters=[_parameter_from_dict(item) for item in payload.get("parameters", [])],
        forms=[_form_from_dict(item) for item in payload.get("forms", [])],
        login_surfaces=[_login_surface_from_dict(item) for item in payload.get("login_surfaces", [])],
        replay_requests=[_replay_request_from_dict(item) for item in payload.get("replay_requests", [])],
        surface_signals=[_surface_signal_from_dict(item) for item in payload.get("surface_signals", [])],
        investigation_steps=[
            _investigation_step_from_dict(item) for item in payload.get("investigation_steps", [])
        ],
        response_deltas=[_response_delta_from_dict(item) for item in payload.get("response_deltas", [])],
        authorization_comparisons=[
            _authorization_comparison_from_dict(item)
            for item in payload.get("authorization_comparisons", [])
        ],
        proof_outcomes=[_proof_outcome_from_dict(item) for item in payload.get("proof_outcomes", [])],
        playbook_executions=[
            _playbook_execution_from_dict(item) for item in payload.get("playbook_executions", [])
        ],
        coverage_decisions=[
            _coverage_decision_from_dict(item) for item in payload.get("coverage_decisions", [])
        ],
        validation_results=[
            _validation_result_from_dict(item) for item in payload.get("validation_results", [])
        ],
        observations=[_observation_from_dict(item) for item in payload.get("observations", [])],
        assertions=[_assertion_from_dict(item) for item in payload.get("assertions", [])],
        evidence=[_evidence_from_dict(item) for item in payload.get("evidence", [])],
        findings=[_finding_from_dict(item) for item in payload.get("findings", [])],
        leads=[_lead_from_dict(item) for item in payload.get("leads", [])],
        evidence_bundles=[
            _evidence_bundle_from_dict(item) for item in payload.get("evidence_bundles", [])
        ],
        relationships=[
            _relationship_from_dict(item) for item in payload.get("relationships", [])
        ],
        hypotheses=[_hypothesis_from_dict(item) for item in payload.get("hypotheses", [])],
        validation_tasks=[
            _validation_task_from_dict(item) for item in payload.get("validation_tasks", [])
        ],
        approval_decisions=[
            _approval_decision_from_dict(item) for item in payload.get("approval_decisions", [])
        ],
        attack_paths=[_attack_path_from_dict(item) for item in payload.get("attack_paths", [])],
        coverage_gaps=[_coverage_gap_from_dict(item) for item in payload.get("coverage_gaps", [])],
        normalized_entities=[
            _normalized_entity_from_dict(item) for item in payload.get("normalized_entities", [])
        ],
        evidence_artifacts=[
            _evidence_artifact_from_dict(item) for item in payload.get("evidence_artifacts", [])
        ],
        task_results=[_task_result_from_dict(item) for item in payload.get("task_results", [])],
        tool_executions=[_execution_from_dict(item) for item in payload.get("tool_executions", [])],
        task_states=list(payload.get("task_states", [])),
        state_history=list(payload.get("state_history", [])),
        alias_map=dict(payload.get("alias_map", {})),
        facts=dict(payload.get("facts", {})),
        warnings=list(payload.get("warnings", [])),
        errors=list(payload.get("errors", [])),
    )
