from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4


StageName = Literal["plan", "step", "step_replan", "final_answer"]
StepStatus = Literal["pending", "running", "completed", "failed", "blocked"]
SubAgentStatus = Literal["queued", "running", "completed", "failed", "blocked"]
ObservationStatus = Literal["ok", "error", "skipped"]
VerificationStatus = Literal["pending", "verified", "failed", "manual_required"]
DecisionSource = Literal["llm", "fallback"]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def make_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return {key: to_plain(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    return value


@dataclass(slots=True)
class Artifact:
    artifact_id: str
    kind: str
    name: str
    path: str = ""
    content_type: str = "text/plain"
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class ToolAction:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    decision_confidence: float = 0.0
    stop_candidate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class DecisionRecord:
    decision_id: str
    source: DecisionSource
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    hypothesis: str = ""
    rationale: str = ""
    skill_name: str = ""
    step_name: str = ""
    input_summary: str = ""
    observation_refs: list[str] = field(default_factory=list)
    verification_goal: str = ""
    decision_confidence: float = 0.0
    stop_candidate: bool = False
    progress_score: float = 0.0
    stagnation_rounds: int = 0
    duplicate_action_ratio: float = 0.0
    model: str = ""
    provider: str = ""
    fallback_reason: str = ""
    fallback_detail: str = ""
    latency_ms: int = 0
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class Observation:
    observation_id: str
    tool_name: str
    status: ObservationStatus
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    artifact_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class Lead:
    lead_id: str
    title: str
    category: str
    severity: str
    location: str
    rationale: str
    evidence: str
    next_steps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class VerificationRecord:
    verification_id: str
    lead_id: str
    method: str
    status: VerificationStatus
    summary: str
    proof: str = ""
    artifact_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class VerifiedFinding:
    finding_id: str
    title: str
    category: str
    severity: str
    location: str
    impact: str
    evidence: str
    recommendation: str
    reproduction_steps: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)
    verification_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class StepBudget:
    max_iterations: int = 4
    max_tool_calls: int = 6

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class StepSpec:
    step_id: str
    name: str
    goal: str
    skill_names: list[str]
    allowed_tools: list[str]
    depends_on: list[str] = field(default_factory=list)
    verification_policy: str = "bounded"
    budget: StepBudget = field(default_factory=StepBudget)
    category: str = "generic"

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class StepState:
    step_id: str
    status: StepStatus = "pending"
    iterations: int = 0
    tool_calls: int = 0
    hypothesis: str = ""
    decision_records: list[DecisionRecord] = field(default_factory=list)
    llm_fallback_count: int = 0
    verification_gap: str = ""
    observations: list[Observation] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    verification_records: list[VerificationRecord] = field(default_factory=list)
    verified_findings: list[VerifiedFinding] = field(default_factory=list)
    output_context: dict[str, Any] = field(default_factory=dict)
    artifact_ids: list[str] = field(default_factory=list)
    spawned_subagents: list[str] = field(default_factory=list)
    error: str = ""
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class SkillCard:
    name: str
    module: str
    category: str
    description: str
    checklist: list[str]
    recommended_tools: list[str]
    verification_requirements: list[str]
    followup_routes: list[str]
    triggers: list[str] = field(default_factory=list)
    when_to_use: str = ""
    skip_conditions: list[str] = field(default_factory=list)
    decision_prompt: str = ""
    tool_schema_subset: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    false_positive_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class ChildTaskPolicy:
    source_module: str
    task_name: str
    goal: str
    planned_tools: list[str]
    spawn_condition: str = "always"
    max_iterations: int = 6
    success_criteria: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    output_contract: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class AgentProfile:
    name: str
    role: str
    description: str
    goal: str
    skill_names: list[str]
    default_tools: list[str]
    llm_enabled: bool = False
    provider_name: str = "ollama"
    model_id: str = ""
    base_url: str = ""
    api_key_env: str = ""
    max_iterations: int = 16
    max_step_iterations: int = 4
    max_parallel_steps: int = 4
    max_parallel_subagents: int = 2
    state_bootstrap: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class AgentEvent:
    event_id: str
    stage: StageName
    kind: str
    message: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class SubAgentTask:
    task_id: str
    name: str
    goal: str
    target: str
    planned_tools: list[str]
    max_iterations: int = 6
    seed_artifact_ids: list[str] = field(default_factory=list)
    seed_step_id: str = ""
    seed_context: dict[str, Any] = field(default_factory=dict)
    success_criteria: list[str] = field(default_factory=list)
    verification_gap: str = ""
    already_attempted: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    stop_conditions: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    output_contract: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class SubAgentState:
    subagent_id: str
    task: SubAgentTask
    status: SubAgentStatus = "queued"
    iterations: int = 0
    tool_calls: int = 0
    decision_records: list[DecisionRecord] = field(default_factory=list)
    llm_fallback_count: int = 0
    done_reason: str = ""
    observations: list[Observation] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    verification_records: list[VerificationRecord] = field(default_factory=list)
    verified_findings: list[VerifiedFinding] = field(default_factory=list)
    output_context: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)
    error: str = ""
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class ScanPlan:
    target: str
    steps: list[StepSpec]
    profile_name: str
    module_bundle: str = "full"
    task_mode: str = ""
    task_mode_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class ScanState:
    scan_id: str
    target: str
    profile: AgentProfile
    stage: StageName
    plan: ScanPlan
    status: str = "ready"
    provider_status: dict[str, Any] = field(default_factory=dict)
    fallback_metrics: dict[str, int] = field(default_factory=dict)
    manual_approvals: dict[str, dict[str, Any]] = field(default_factory=dict)
    report_manifest: dict[str, Any] = field(default_factory=dict)
    step_states: dict[str, StepState] = field(default_factory=dict)
    subagents: dict[str, SubAgentState] = field(default_factory=dict)
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    verified_findings: list[VerifiedFinding] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)
