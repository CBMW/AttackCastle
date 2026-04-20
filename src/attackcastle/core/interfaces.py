from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from attackcastle.core.models import (
    Asset,
    AuthorizationComparison,
    CoverageGap,
    CoverageDecision,
    Evidence,
    EvidenceArtifact,
    Endpoint,
    Form,
    Hypothesis,
    InvestigationStep,
    LoginSurface,
    NormalizedEntity,
    Observation,
    Parameter,
    PlaybookExecution,
    ProofOutcome,
    ReplayRequest,
    ResponseDelta,
    RunData,
    Service,
    SurfaceSignal,
    TLSAsset,
    Technology,
    TaskResult,
    ToolExecution,
    ValidationResult,
    ValidationTask,
    WebApplication,
)


@dataclass
class AdapterResult:
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
    hypotheses: list[Hypothesis] = field(default_factory=list)
    validation_tasks: list[ValidationTask] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    evidence_artifacts: list[EvidenceArtifact] = field(default_factory=list)
    normalized_entities: list[NormalizedEntity] = field(default_factory=list)
    task_results: list[TaskResult] = field(default_factory=list)
    tool_executions: list[ToolExecution] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class AdapterContext:
    profile_name: str
    config: dict[str, Any]
    profile_config: dict[str, Any]
    run_store: Any
    logger: Any
    audit: Any
    policy_engine: Any = None
    secret_resolver: Any = None
    rate_limiter: Any = None
    execution_controller: Any = None
    event_emitter: Callable[[str, dict[str, Any]], None] | None = None
    post_run_processors: list[Callable[[Any, RunData, Any], None]] = field(default_factory=list)
    task_instance_key: str | None = None
    task_inputs: list[str] = field(default_factory=list)
    cancellation_token: Any = None
    deadline_monotonic: float | None = None


class ToolAdapter(Protocol):
    name: str
    capability: str
    noise_score: int
    cost_score: int

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        ...

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        ...
