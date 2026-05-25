# AUTO-GENERATED from sailor.schema.json. DO NOT EDIT.
# Run scripts/regen_contracts.sh to regenerate.

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, EmailStr, Field, RootModel


class SailorApiContracts(RootModel[Any]):
    root: Any = Field(..., title="Sailor API Contracts")
    """
    Single source of truth for all types shared between frontend and backend.
    Generated artifacts (TypeScript, Pydantic) must NOT be hand-edited.
    See shared/contracts/README.md for the conflict resolution log.
    """


class RunStatus(StrEnum):
    """
    Run lifecycle states. See backend_spec.md §3.1.
    NOTE: 'archived' is the soft-delete terminal state from DELETE /api/runs/:id.
    """

    created = "created"
    needs_build_config = "needs_build_config"
    queued = "queued"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    archived = "archived"


class Phase1Status(StrEnum):
    """
    Phase 1 outcome per spec. See backend_spec.md §3.2.
    """

    emitted = "emitted"
    filtered_out = "filtered_out"


class Phase2Status(StrEnum):
    """
    Phase 2 spec state machine. See backend_spec.md §3.2.
    NOTE: 'errored' is the terminal failure state — was missing from frontend types.
    """

    queued = "queued"
    exploring = "exploring"
    authoring = "authoring"
    refining = "refining"
    bug_triggered = "bug_triggered"
    inconclusive = "inconclusive"
    likely_false_positive = "likely_false_positive"
    errored = "errored"


class Phase3Status(StrEnum):
    """
    Phase 3 spec state machine. See backend_spec.md §3.3.
    NOTE: 'skipped' (in old frontend types) was renamed to 'not_eligible' to match backend.
    """

    not_eligible = "not_eligible"
    queued = "queued"
    running = "running"
    confirmed = "confirmed"
    rejected = "rejected"
    errored = "errored"


class VerdictValue(StrEnum):
    """
    Phase 3 verdict (lowercase, per backend §2.1).
    Frontend rendering may upper-case for display but wire format is lowercase.
    """

    confirmed = "confirmed"
    rejected = "rejected"


class Phase2Outcome(StrEnum):
    """
    Phase 2 terminal outcome. Distinct from Phase 3 Verdict.
    """

    bug_triggered = "bug_triggered"
    inconclusive = "inconclusive"
    likely_false_positive = "likely_false_positive"
    errored = "errored"


class UserRole(StrEnum):
    """
    User role, least to most privileged. See frontend_spec.md §10.
    """

    viewer = "viewer"
    operator = "operator"
    intervener = "intervener"
    admin = "admin"


class TurnKind(StrEnum):
    """
    Turn kind in Phase 2 loop. See backend_spec.md §2.1.
    NOTE: 'klee_timeout' (frontend) is NOT a turn kind — KLEE timeout is a klee_run outcome.
    'terminal' is the final marker turn at phase2_status terminal transition.
    """

    explore = "explore"
    author = "author"
    compile_fail = "compile_fail"
    klee_run = "klee_run"
    refinement = "refinement"
    intervention = "intervention"
    terminal = "terminal"


class CompileErrorClass(StrEnum):
    """
    Classification of clang errors during Phase 2 compile_fail turns.
    Produced by the Phase 2 orchestrator (in worker), persisted on Turn payload.
    """

    incomplete_type = "incomplete_type"
    conflicting_proto = "conflicting_proto"
    redefinition = "redefinition"
    other = "other"


class KleeOutcome(StrEnum):
    """
    KLEE run outcome, parsed from KLEE stderr. See DockerRunner.run_klee().
    """

    not_reached = "not_reached"
    site_reached = "site_reached"
    bug_triggered = "bug_triggered"


class RunCounters(BaseModel):
    """
    Denormalized counters per run, maintained by the backend.
    Field names match backend_spec.md §2.1 verbatim.
    Frontend MUST use these names; legacy aliases like 'total_specs' are removed.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    specs_total: int = Field(..., ge=0)
    specs_filtered_out: int = Field(..., ge=0)
    specs_emitted: int = Field(..., ge=0)
    specs_phase2_queued: int = Field(..., ge=0)
    specs_phase2_running: int = Field(..., ge=0)
    specs_phase2_bug_triggered: int = Field(..., ge=0)
    specs_phase2_inconclusive: int = Field(..., ge=0)
    specs_phase2_likely_fp: int = Field(..., ge=0)
    specs_phase2_errored: int = Field(..., ge=0)
    specs_phase3_queued: int = Field(..., ge=0)
    specs_phase3_confirmed: int = Field(..., ge=0)
    specs_phase3_rejected: int = Field(..., ge=0)
    specs_phase3_errored: int = Field(..., ge=0)
    unique_confirmed: int = Field(..., ge=0)
    total_llm_tokens: int = Field(..., ge=0)
    total_klee_seconds: int = Field(..., ge=0)


class RunConfig(BaseModel):
    """
    Per-run configuration. See backend_spec.md §2.1 (RunConfig).
    Field names use snake_case throughout; legacy uppercase aliases (T_explore etc.) are removed.
    Keys are flat: 'phase2_t_explore' rather than nested 'phase2.t_explore', because JSON object keys with dots are ambiguous when consumed by typed languages.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    phase1_query_suite: list[str]
    """
    Query ids enabled for Phase 1. Default: all 34.
    """
    phase1_skip_files: list[str]
    """
    Regex patterns matching file paths to skip.
    """
    phase1_skip_functions: list[str]
    """
    Regex patterns matching function names to skip.
    """
    phase2_t_explore: int = Field(..., ge=0)
    phase2_t_author: int = Field(..., ge=0)
    phase2_t_max: int = Field(..., ge=1)
    phase2_t_klee_seconds: int = Field(..., ge=1)
    phase2_r_max: int = Field(..., ge=0)
    phase2_parallelism: int = Field(..., ge=1)
    phase2_llm_provider: str
    phase2_llm_model: str
    phase3_enabled: bool
    phase3_asan_options: str | None = None


class Phase1Summary(BaseModel):
    """
    Phase 1 aggregate summary embedded in Run.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    raw_findings: int = Field(..., ge=0)
    after_filter: int = Field(..., ge=0)
    specs_emitted: int = Field(..., ge=0)


class CodeqlBuildMode(StrEnum):
    autodetect = "autodetect"
    none = "none"
    custom = "custom"


class Run(BaseModel):
    """
    A single pipeline invocation. See backend_spec.md §2.1.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    run_id: str
    name: str
    project_zip_ref: str | None = None
    build_command: str
    codeql_build_mode: CodeqlBuildMode
    config: RunConfig
    status: RunStatus
    counters: RunCounters
    phase1_summary: Phase1Summary | None = None
    created_at: AwareDatetime
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    created_by: str
    """
    user id
    """
    error: str | None = None


class Spec(BaseModel):
    """
    VulnerabilitySpec record. See backend_spec.md §2.1.
    Field names match backend authoritatively.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    spec_id: str
    run_id: str
    rule_id: str
    cwe: str | None = None
    """
    Derived from rule_id, e.g. 'CWE-122'
    """
    file: str
    line: int
    func: str | None = None
    message: str
    snippet: str | None = None
    entrypoint: str | None = None
    assertion_template: str | None = None
    phase1_status: Phase1Status
    phase2_status: Phase2Status | None = None
    phase3_status: Phase3Status | None = None
    current_turn: int | None = Field(None, ge=0)
    turn_count_total: int | None = Field(None, ge=0)
    refine_count: int | None = Field(None, ge=0)
    phase2_outcome: Phase2Outcome | None = None
    phase2_error: str | None = None
    phase3_verdict: VerdictValue | None = None
    phase3_error: str | None = None
    worker_id: str | None = None
    intervention_pending: bool | None = False
    artifacts_root: str | None = None
    created_at: AwareDatetime
    last_event_at: AwareDatetime
    token_cost: int | None = Field(None, ge=0)
    """
    Cumulative LLM tokens for this spec.
    """


class Turn(BaseModel):
    """
    One iteration of the Phase 2 loop. Append-only. See backend_spec.md §2.1.
    Payload is fetched separately via GET /turns/:turn_id — the list endpoint returns Turn rows WITHOUT payload (only payload_ref).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    turn_id: str
    spec_id: str
    turn_number: int = Field(..., ge=0)
    kind: TurnKind
    started_at: AwareDatetime
    ended_at: AwareDatetime | None = None
    duration_ms: int | None = Field(None, ge=0)
    payload_ref: str | None = None
    """
    Artifact store reference to detailed payload. Fetch via GET /turns/:turn_id.
    """
    summary: str
    """
    Short string for timeline card (no large blobs).
    """
    tokens_consumed: int | None = Field(None, ge=0)
    klee_seconds: int | None = Field(None, ge=0)


class Kind(StrEnum):
    explore = "explore"
    author = "author"
    refinement = "refinement"


class ToolCall(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: str
    arguments: Any | None = None


class LLMTurnPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    prompt_tokens: int = Field(..., ge=0)
    completion_tokens: int = Field(..., ge=0)
    tool_calls: list[ToolCall] | None = None
    response_summary: str
    prompt_excerpt: str | None = None
    response_excerpt: str | None = None


class CompileFailPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["compile_fail"]
    error_class: CompileErrorClass
    raw_error: str
    suggested_fix: str | None = None
    relevant_source: str | None = None


class KleeRunPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["klee_run"]
    outcome: KleeOutcome
    paths_explored: int = Field(..., ge=0)
    functions_entered: list[str] | None = None
    functions_missed: list[str] | None = None
    ktest_paths: list[str] | None = None
    stderr_excerpt: str | None = None
    timed_out: bool | None = False
    """
    True if KLEE hit T_klee. Replaces the former 'klee_timeout' turn kind.
    """


class InterventionType(StrEnum):
    edit_harness = "edit_harness"
    force_outcome = "force_outcome"
    edit_spec = "edit_spec"


class InterventionPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["intervention"]
    intervention_type: InterventionType
    actor: str
    """
    user id
    """
    summary: str | None = None


class TerminalPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["terminal"]
    final_outcome: Phase2Outcome


class Input(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str
    value: str


class Verdict(BaseModel):
    """
    Phase 3 verdict record. See backend_spec.md §2.1.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict_id: str
    spec_id: str
    verdict: VerdictValue
    cwe: str
    asan_type: str
    """
    e.g. 'heap-buffer-overflow'
    """
    file: str
    line: int
    func: str
    inputs: list[Input] | None = None
    asan_report_ref: str | None = None
    replay_driver_ref: str | None = None
    dedup_key: str


class Artifact(StrEnum):
    """
    Logical artifact name, without '.c' extension. Frontend display may add '.c'.
    """

    driver = "driver"
    slice = "slice"
    assertions = "assertions"


class EditHarnessRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["edit_harness"]
    artifact: Artifact
    """
    Logical artifact name, without '.c' extension. Frontend display may add '.c'.
    """
    contents: str
    """
    UTF-8 file contents.
    """
    base_version: int = Field(..., ge=0)
    """
    Optimistic concurrency: the version the user was editing. 409 on conflict.
    """


class Outcome(StrEnum):
    skip_to_phase3 = "skip_to_phase3"
    mark_inconclusive = "mark_inconclusive"
    mark_likely_fp = "mark_likely_fp"


class ForceOutcomeRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["force_outcome"]
    outcome: Outcome
    witness_ktest_ref: str | None = None
    """
    Required iff outcome=skip_to_phase3.
    """


class EditSpecRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["edit_spec"]
    spec: Any
    """
    Full VulnerabilitySpec replacement. Fields match Spec, but only the user-editable subset is required.
    """


class SSEMessageKind(StrEnum):
    """
    Discriminator for SSE messages.

    Full mapping:
      run_status_changed       <- backend RunStatusChanged, RunCompleted, RunFailed, RunCancelled
      run_counters_updated     <- backend RunCountersUpdated (throttled to <=1/sec)
      spec_state_changed       <- backend SpecPhase2Started, SpecPhase2Outcome, SpecPhase3Started, SpecPhase3Verdict, SpecErrored, SpecRequeued, SpecEmitted, SpecFiltered
      spec_intervention_applied <- backend SpecInterventionAcknowledged, SpecInterventionApplied
      turn_appended            <- backend TurnAppended
      worker_heartbeat         <- backend WorkerHeartbeat (also covers Started/Finished/Died as one stream)
      log_line                 <- backend LogLine
      resync_required          <- backend resync signal when bus buffer gap exceeds 60s
      interrupt_created        <- pipeline reached a function with auto=false and is now waiting (see interactive_control_spec.md §3)
      interrupt_resolved       <- pipeline resumed past the interrupt (either via resume or skip)
      auto_config_changed      <- live toggle of an Auto checkbox during a run
    """

    run_status_changed = "run_status_changed"
    run_counters_updated = "run_counters_updated"
    spec_state_changed = "spec_state_changed"
    spec_intervention_applied = "spec_intervention_applied"
    turn_appended = "turn_appended"
    worker_heartbeat = "worker_heartbeat"
    log_line = "log_line"
    resync_required = "resync_required"
    interrupt_created = "interrupt_created"
    interrupt_resolved = "interrupt_resolved"
    auto_config_changed = "auto_config_changed"


class SSEMessageEnvelopeBase(BaseModel):
    """
    Internal: shared envelope fields. Each concrete message extends this with `kind` pinned to a const and `payload` typed to the matching variant.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime


class RunStatusChangedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    run_id: str
    status: RunStatus
    previous_status: RunStatus | None = None
    error: str | None = None


class RunCountersUpdatedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    run_id: str
    counters: RunCounters


class SpecStateChangedPayload(BaseModel):
    """
    Full snapshot of the spec after the change. NOT a partial diff.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    spec: Spec


class SpecInterventionAppliedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    spec_id: str
    intervention_type: InterventionType
    applied_at: AwareDatetime
    actor: str | None = None


class TurnAppendedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    turn: Turn


class Status(StrEnum):
    idle = "idle"
    busy = "busy"
    died = "died"


class WorkerHeartbeatPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    worker_id: str
    status: Status
    current_spec_id: str | None = None
    last_heartbeat: AwareDatetime
    throughput_specs_per_min: float | None = None
    tokens_per_min: float | None = None
    klee_seconds_per_min: float | None = None


class Level(StrEnum):
    error = "error"
    warn = "warn"
    info = "info"
    debug = "debug"


class Source(StrEnum):
    celery = "celery"
    phase1 = "phase1"
    phase2 = "phase2"
    phase3 = "phase3"
    llm = "llm"
    klee = "klee"
    clang = "clang"
    asan = "asan"
    api = "api"


class LogLinePayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    timestamp: AwareDatetime
    level: Level
    source: Source
    run_id: str | None = None
    spec_id: str | None = None
    worker_id: str | None = None
    trace_id: str | None = None
    message: str
    fields: dict[str, Any] | None = None


class Reason(StrEnum):
    buffer_overflow = "buffer_overflow"
    topic_subscription_reset = "topic_subscription_reset"
    unknown = "unknown"


class ResyncRequiredPayload(BaseModel):
    """
    Sent when the server's replay buffer (60s) cannot catch the client up.
    Client MUST drop local state for affected topic and refetch via REST.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    reason: Reason
    last_known_sequence: int | None = None


class SSETopicPattern(RootModel[str]):
    root: str = Field(
        ...,
        pattern="^runs\\.(all|[A-Za-z0-9_-]+(\\.(specs|workers|logs)(\\.[A-Za-z0-9_-]+(\\.logs)?)?)?)$",
    )
    """
    Allowed topic patterns:
      runs.all
      runs.<run_id>
      runs.<run_id>.specs
      runs.<run_id>.specs.<spec_id>
      runs.<run_id>.specs.<spec_id>.logs
      runs.<run_id>.workers
      runs.<run_id>.logs
    """


class ApiError(BaseModel):
    """
    Uniform error response shape. Returned with all non-2xx responses.
    Replaces the frontend client's ad-hoc {code, message, detail}.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    """
    Stable machine-readable code, snake_case. e.g. 'spec_not_found', 'invalid_transition', 'lease_expired'.
    """
    message: str
    """
    Human-readable summary.
    """
    detail: Any | None = None
    trace_id: str | None = None


class PaginatedSpecs(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    items: list[Spec]
    next_cursor: str | None
    prev_cursor: str | None = None
    total_estimate: int | None = Field(None, ge=0)


class Worker(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    worker_id: str
    status: Status
    current_spec_id: str | None = None
    last_heartbeat: AwareDatetime
    throughput_specs_per_min: float | None = None
    tokens_per_min: float | None = None
    klee_seconds_per_min: float | None = None


class User(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    user_id: str
    username: str
    email: EmailStr | None = None
    display_name: str | None = None
    role: UserRole
    created_at: AwareDatetime
    last_login: AwareDatetime | None = None
    disabled: bool | None = False


class Action(StrEnum):
    run_create = "run_create"
    run_pause = "run_pause"
    run_resume = "run_resume"
    run_cancel = "run_cancel"
    spec_requeue = "spec_requeue"
    spec_intervene = "spec_intervene"
    spec_skip = "spec_skip"
    settings_change = "settings_change"
    role_change = "role_change"
    login = "login"
    logout = "logout"
    interrupt_resume = "interrupt_resume"
    interrupt_skip = "interrupt_skip"
    auto_config_change = "auto_config_change"
    file_replace = "file_replace"
    user_register = "user_register"


class AuditEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: str
    actor: str
    """
    user id
    """
    action: Action
    target: str
    """
    e.g. 'run:<id>' or 'spec:<id>'
    """
    diff: dict[str, Any] | None = None
    created_at: AwareDatetime


class PipelineFunctionId(StrEnum):
    """
    Stable identifier for an interruptible pipeline function.

    Naming convention: <phase>_<function>, snake_case, NO DOTS.
    Used as the AutoConfig key, the interrupt point's `function_name`,
    and the wire-level identifier in every interrupt-related endpoint.

    Display labels (e.g. 'KLEE Execution') belong in the frontend label table,
    not here. The wire format is exactly these strings.
    """

    phase1_db_build = "phase1_db_build"
    phase1_query_execution = "phase1_query_execution"
    phase1_sarif_parsing = "phase1_sarif_parsing"
    phase1_fact_enrichment = "phase1_fact_enrichment"
    phase1_spec_generation = "phase1_spec_generation"
    phase2_spec_selection = "phase2_spec_selection"
    phase2_source_exploration = "phase2_source_exploration"
    phase2_driver_synthesis = "phase2_driver_synthesis"
    phase2_stub_synthesis = "phase2_stub_synthesis"
    phase2_compile_diagnose = "phase2_compile_diagnose"
    phase2_klee_execution = "phase2_klee_execution"
    phase3_replay_driver_generation = "phase3_replay_driver_generation"
    phase3_asan_compilation = "phase3_asan_compilation"
    phase3_result_classification = "phase3_result_classification"


class InterruptScope(StrEnum):
    """
    Whether the interrupt blocks the whole run (Phase 1 functions) or just one spec (Phase 2/3 functions).

      run-scoped:  phase1_*, phase2_spec_selection
                   One interrupt blocks Phase 2 dispatch entirely until resolved.
      spec-scoped: phase2_source_exploration through phase3_result_classification
                   Per-spec; other specs in the same run continue independently.

    Resolves interactive_control_spec.md §7.5 Open Question.
    """

    run = "run"
    spec = "spec"


class InterruptStatus(StrEnum):
    waiting = "waiting"
    resumed = "resumed"
    skipped = "skipped"


class InterruptInputFile(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str
    """
    Logical file name shown to the user, e.g. 'driver.c', 'findings.sarif'.
    """
    artifact_ref: str
    """
    Opaque artifact store reference. Fetch via GET /api/artifacts/:ref.
    """
    size_bytes: int = Field(..., ge=0)
    mime_type: str
    editable: bool
    """
    True for text formats (C, JSON, SARIF, QL). False for binary (.ktest, .bc) — view-only.
    """
    version: int | None = Field(None, ge=0)
    """
    Version counter for optimistic concurrency on subsequent edits.
    """


class ModifiedFile(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str
    artifact_ref: str
    base_version: int | None = Field(None, ge=0)
    """
    Optimistic concurrency token. Must equal the current InterruptInputFile.version; 409 on mismatch.
    """


class InterruptResumeRequest(BaseModel):
    """
    POST /api/runs/:run_id/interrupts/:interrupt_id/resume body.

    File uploads MUST be performed first via POST /api/runs/:run_id/interrupts/:interrupt_id/files (one call per file, returns artifact_ref). The resume body then references the new artifact_ref values. This avoids large base64 payloads in the resume call and keeps file validation visible as its own step.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    modified_files: list[ModifiedFile] | None = None
    """
    Files the user replaced or edited, referenced by artifact_ref returned from the upload endpoint. Each entry's `name` must match an `InterruptPoint.input_files[*].name` from this interrupt; unknown names are rejected.
    """
    option_overrides: dict[str, Any] | None = None
    """
    Per-function override values. Validated against the function's option schema; unknown keys rejected.
    """
    apply_to_all_matching: bool | None = False
    """
    Resolves interactive_control_spec.md §7.1 Open Question. When true, the same overrides are applied to all currently-waiting interrupts with the same function_name in this run (e.g., 128 KLEE Execution interrupts). modified_files MUST be empty when this is true (per-spec file edits cannot be broadcast).
    """
    re_enable_auto: bool | None = False
    """
    Toggle the AutoConfig for this function_name back to true after resuming. Saves the user one extra round-trip when they only wanted to pause once.
    """


class InterruptSkipRequest(BaseModel):
    """
    POST /api/runs/:run_id/interrupts/:interrupt_id/skip body.

    Skip means: use the default output of the function (the LLM-generated artifact, the auto-classified verdict, etc.) and proceed. Distinct from `spec.skip` which marks the whole spec as not-processed.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    reason: str | None = Field(None, max_length=500)
    apply_to_all_matching: bool | None = False


class AutoConfig(BaseModel):
    """
    Per-run Auto/Manual configuration. Keys are PipelineFunctionId values; value true=Auto, false=interrupt and wait.

    A missing key defaults to true (Auto). Implementations MUST persist only the explicit overrides, not the full set.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    phase1_db_build: bool | None = None
    phase1_query_execution: bool | None = None
    phase1_sarif_parsing: bool | None = None
    phase1_fact_enrichment: bool | None = None
    phase1_spec_generation: bool | None = None
    phase2_spec_selection: bool | None = None
    phase2_source_exploration: bool | None = None
    phase2_driver_synthesis: bool | None = None
    phase2_stub_synthesis: bool | None = None
    phase2_compile_diagnose: bool | None = None
    phase2_klee_execution: bool | None = None
    phase3_replay_driver_generation: bool | None = None
    phase3_asan_compilation: bool | None = None
    phase3_result_classification: bool | None = None


class AutoConfigPatch(BaseModel):
    """
    PATCH /api/runs/:run_id/auto-config body. Partial update; only included keys are changed.

    Wire format is the FLAT map below — NOT nested under 'phase1'/'phase2'/'phase3', and NOT using dotted keys like 'phase2.klee_execution'. Reason: dotted JSON keys round-trip badly through typed languages; nesting adds parse complexity for no benefit.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    phase1_db_build: bool | None = None
    phase1_query_execution: bool | None = None
    phase1_sarif_parsing: bool | None = None
    phase1_fact_enrichment: bool | None = None
    phase1_spec_generation: bool | None = None
    phase2_spec_selection: bool | None = None
    phase2_source_exploration: bool | None = None
    phase2_driver_synthesis: bool | None = None
    phase2_stub_synthesis: bool | None = None
    phase2_compile_diagnose: bool | None = None
    phase2_klee_execution: bool | None = None
    phase3_replay_driver_generation: bool | None = None
    phase3_asan_compilation: bool | None = None
    phase3_result_classification: bool | None = None


class FileValidationSeverity(StrEnum):
    error = "error"
    warning = "warning"
    info = "info"


class Issue(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    severity: FileValidationSeverity
    message: str
    line: int | None = Field(None, ge=1)
    column: int | None = Field(None, ge=1)
    rule: str | None = None
    """
    Validator-specific rule id, e.g. 'sarif.missing_runs', 'replay_driver.klee_call_present'.
    """


class FileValidationResult(BaseModel):
    """
    Response from POST /api/validate/file and from the implicit validation that runs when a file is uploaded to an interrupt.

    NOT an error response — even severity='error' results return HTTP 200. ApiError is only for endpoint-level failures (auth, not found, server error). Validation errors are returned in the body so the UI can render them inline.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    valid: bool
    """
    Convenience: true iff severity != 'error'. Severity is authoritative.
    """
    severity: FileValidationSeverity
    message: str
    """
    Human-readable summary.
    """
    detected_format: str
    """
    What the validator inferred the file to be, e.g. 'sarif', 'c-source', 'json-array', 'ktest', 'bitcode', 'unknown'.
    """
    issues: list[Issue] | None = None
    """
    Granular issues for inline display (e.g. clang error lines, JSON schema violations). Empty when severity='info'.
    """


class Resolution(StrEnum):
    resumed = "resumed"
    skipped = "skipped"


class InterruptResolvedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    interrupt_id: str
    run_id: str
    spec_id: str | None = None
    resolution: Resolution
    resolved_by: str | None = None


class AutoConfigChangedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    run_id: str
    auto_config: AutoConfig
    changed_by: str | None = None


class ManualHarnessMode(BaseModel):
    """
    Resolves interactive_control_spec.md §3.15 ambiguity: 'Disable LLM' is a per-spec configuration toggle, NOT a per-turn interrupt.

    When enabled, the worker treats phase2_driver_synthesis, phase2_stub_synthesis, and (where applicable) phase2_compile_diagnose as if auto=false — but ONLY for this one spec, without modifying the run-level AutoConfig. The spec stays in this mode until the user explicitly disables it via POST .../manual-harness with enabled=false. Re-queueing the spec preserves the flag.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    spec_id: str
    enabled: bool
    enabled_at: AwareDatetime | None = None


class RegisterRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    username: str = Field(..., max_length=32, min_length=3, pattern="^[A-Za-z0-9_]+$")
    email: EmailStr
    password: str = Field(..., min_length=12)
    """
    Server validates strength: ≥1 uppercase, ≥1 digit, ≥1 symbol. Specific regex documented in backend implementation.
    """
    display_name: str | None = Field(None, max_length=64)


class RegisterResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    user_id: str
    username: str
    role: UserRole
    """
    Always 'viewer' except for the very first registered user, who receives 'admin'.
    """


class Verdict1(StrEnum):
    """
    Lowercase wire format. UI may capitalize for display; backend rejects 'CONFIRMED'.
    """

    confirmed = "confirmed"
    rejected = "rejected"


class ClassifyVerdictRequest(BaseModel):
    """
    Body for the override path of the phase3_result_classification interrupt. Sent in InterruptResumeRequest.option_overrides under the key 'classification'.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Verdict1
    """
    Lowercase wire format. UI may capitalize for display; backend rejects 'CONFIRMED'.
    """
    cwe: str | None = None
    """
    Optional CWE override, e.g. 'CWE-122'.
    """
    reason: str | None = Field(None, max_length=1000)


class InterventionRequest(
    RootModel[EditHarnessRequest | ForceOutcomeRequest | EditSpecRequest]
):
    root: EditHarnessRequest | ForceOutcomeRequest | EditSpecRequest
    """
    POST /api/runs/:run_id/specs/:spec_id/intervene body. Discriminator: 'type'.
    See backend_spec.md §6.
    """


class SSEMessageRunStatusChanged(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["run_status_changed"]
    payload: RunStatusChangedPayload


class SSEMessageRunCountersUpdated(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["run_counters_updated"]
    payload: RunCountersUpdatedPayload


class SSEMessageSpecStateChanged(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["spec_state_changed"]
    payload: SpecStateChangedPayload


class SSEMessageSpecInterventionApplied(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["spec_intervention_applied"]
    payload: SpecInterventionAppliedPayload


class SSEMessageTurnAppended(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["turn_appended"]
    payload: TurnAppendedPayload


class SSEMessageWorkerHeartbeat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["worker_heartbeat"]
    payload: WorkerHeartbeatPayload


class SSEMessageLogLine(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["log_line"]
    payload: LogLinePayload


class SSEMessageResyncRequired(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["resync_required"]
    payload: ResyncRequiredPayload


class SSEMessageInterruptResolved(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["interrupt_resolved"]
    payload: InterruptResolvedPayload


class SSEMessageAutoConfigChanged(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["auto_config_changed"]
    payload: AutoConfigChangedPayload


class InterruptPoint(BaseModel):
    """
    An active or historical interrupt. Returned by GET /api/runs/:run_id/interrupts(/:interrupt_id).
    See interactive_control_spec.md §3 for UI behavior.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    interrupt_id: str
    run_id: str
    spec_id: str | None = None
    """
    Null for run-scoped interrupts (Phase 1, spec_selection). Required for spec-scoped.
    """
    function_name: PipelineFunctionId
    scope: InterruptScope
    turn: int | None = Field(None, ge=0)
    """
    Phase 2 turn number when the interrupt fired; null for Phase 1/3.
    """
    status: InterruptStatus
    created_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    resolved_by: str | None = None
    """
    User id of the intervener who resumed/skipped.
    """
    input_files: list[InterruptInputFile] | None = None
    """
    Files the user may View/Edit/Replace at this interrupt. Each entry's `artifact_ref` is an opaque reference resolvable via GET /api/artifacts/:ref (returns 302 to presigned URL).
    """
    option_overrides: dict[str, Any] | None = None
    """
    Per-function option set the user may adjust at this interrupt. Schema depends on `function_name`; documented in interactive_control_spec.md §3.4 through §3.18.
    """


class InterruptCreatedPayload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    interrupt: InterruptPoint


class TurnDetail(BaseModel):
    """
    Full Turn including inlined payload. Returned by GET /turns/:turn_id.
    The payload variant depends on kind.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    turn: Turn
    payload: (
        LLMTurnPayload
        | CompileFailPayload
        | KleeRunPayload
        | InterventionPayload
        | TerminalPayload
    )
    """
    Discriminated union of payload shapes. Discriminator: 'kind'.
    """


class SSEMessageInterruptCreated(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    timestamp: AwareDatetime
    kind: Literal["interrupt_created"]
    payload: InterruptCreatedPayload


class SSEBatch(BaseModel):
    """
    Server batches SSEMessage in 250ms windows per topic. Sent on the wire as the SSE 'data:' payload.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    topic: str
    sequence: int = Field(..., ge=0)
    """
    Sequence of the last message in batch.
    """
    batch: list[
        SSEMessageRunStatusChanged
        | SSEMessageRunCountersUpdated
        | SSEMessageSpecStateChanged
        | SSEMessageSpecInterventionApplied
        | SSEMessageTurnAppended
        | SSEMessageWorkerHeartbeat
        | SSEMessageLogLine
        | SSEMessageResyncRequired
        | SSEMessageInterruptCreated
        | SSEMessageInterruptResolved
        | SSEMessageAutoConfigChanged
    ] = Field(..., min_length=1)
