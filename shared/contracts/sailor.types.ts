/* eslint-disable */
/**
 * AUTO-GENERATED from sailor.schema.json. DO NOT EDIT.
 * Run scripts/regen_contracts.sh to regenerate.
 *
 * This file is the single source of truth for all types shared
 * between the Sailor frontend and backend. Import types from here;
 * do NOT redefine them in lib/types.ts or anywhere else.
 */

/**
 * Run lifecycle states. See backend_spec.md §3.1.
 * NOTE: 'archived' is the soft-delete terminal state from DELETE /api/runs/:id.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RunStatus".
 */
export type RunStatus =
  | 'created'
  | 'needs_build_config'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'archived';
/**
 * Phase 1 outcome per spec. See backend_spec.md §3.2.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Phase1Status".
 */
export type Phase1Status = 'emitted' | 'filtered_out';
/**
 * Phase 2 spec state machine. See backend_spec.md §3.2.
 * NOTE: 'errored' is the terminal failure state — was missing from frontend types.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Phase2Status".
 */
export type Phase2Status =
  | 'queued'
  | 'exploring'
  | 'authoring'
  | 'refining'
  | 'bug_triggered'
  | 'inconclusive'
  | 'likely_false_positive'
  | 'errored';
/**
 * Phase 3 spec state machine. See backend_spec.md §3.3.
 * NOTE: 'skipped' (in old frontend types) was renamed to 'not_eligible' to match backend.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Phase3Status".
 */
export type Phase3Status = 'not_eligible' | 'queued' | 'running' | 'confirmed' | 'rejected' | 'errored';
/**
 * Phase 3 verdict (lowercase, per backend §2.1).
 * Frontend rendering may upper-case for display but wire format is lowercase.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "VerdictValue".
 */
export type VerdictValue = 'confirmed' | 'rejected';
/**
 * Phase 2 terminal outcome. Distinct from Phase 3 Verdict.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Phase2Outcome".
 */
export type Phase2Outcome = 'bug_triggered' | 'inconclusive' | 'likely_false_positive' | 'errored';
/**
 * User role, least to most privileged. See frontend_spec.md §10.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "UserRole".
 */
export type UserRole = 'viewer' | 'operator' | 'intervener' | 'admin';
/**
 * Turn kind in Phase 2 loop. See backend_spec.md §2.1.
 * NOTE: 'klee_timeout' (frontend) is NOT a turn kind — KLEE timeout is a klee_run outcome.
 * 'terminal' is the final marker turn at phase2_status terminal transition.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "TurnKind".
 */
export type TurnKind = 'explore' | 'author' | 'compile_fail' | 'klee_run' | 'refinement' | 'intervention' | 'terminal';
/**
 * Classification of clang errors during Phase 2 compile_fail turns.
 * Produced by the Phase 2 orchestrator (in worker), persisted on Turn payload.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "CompileErrorClass".
 */
export type CompileErrorClass = 'incomplete_type' | 'conflicting_proto' | 'redefinition' | 'other';
/**
 * KLEE run outcome, parsed from KLEE stderr. See DockerRunner.run_klee().
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "KleeOutcome".
 */
export type KleeOutcome = 'not_reached' | 'site_reached' | 'bug_triggered';
/**
 * Discriminated union of payload shapes. Discriminator: 'kind'.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "TurnPayload".
 */
export type TurnPayload = LLMTurnPayload | CompileFailPayload | KleeRunPayload | InterventionPayload | TerminalPayload;
/**
 * POST /api/runs/:run_id/specs/:spec_id/intervene body. Discriminator: 'type'.
 * See backend_spec.md §6.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterventionRequest".
 */
export type InterventionRequest = EditHarnessRequest | ForceOutcomeRequest | EditSpecRequest;
/**
 * Discriminator for SSE messages.
 *
 * Full mapping:
 *   run_status_changed       <- backend RunStatusChanged, RunCompleted, RunFailed, RunCancelled
 *   run_counters_updated     <- backend RunCountersUpdated (throttled to <=1/sec)
 *   spec_state_changed       <- backend SpecPhase2Started, SpecPhase2Outcome, SpecPhase3Started, SpecPhase3Verdict, SpecErrored, SpecRequeued, SpecEmitted, SpecFiltered
 *   spec_intervention_applied <- backend SpecInterventionAcknowledged, SpecInterventionApplied
 *   turn_appended            <- backend TurnAppended
 *   worker_heartbeat         <- backend WorkerHeartbeat (also covers Started/Finished/Died as one stream)
 *   log_line                 <- backend LogLine
 *   resync_required          <- backend resync signal when bus buffer gap exceeds 60s
 *   interrupt_created        <- pipeline reached a function with auto=false and is now waiting (see interactive_control_spec.md §3)
 *   interrupt_resolved       <- pipeline resumed past the interrupt (either via resume or skip)
 *   auto_config_changed      <- live toggle of an Auto checkbox during a run
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageKind".
 */
export type SSEMessageKind =
  | 'run_status_changed'
  | 'run_counters_updated'
  | 'spec_state_changed'
  | 'spec_intervention_applied'
  | 'turn_appended'
  | 'worker_heartbeat'
  | 'log_line'
  | 'resync_required'
  | 'interrupt_created'
  | 'interrupt_resolved'
  | 'auto_config_changed';
/**
 * Single SSE message. Wire-level envelope, with `kind` as discriminator.
 *
 * UNRESOLVED CONFLICTS that this schema explicitly settles:
 *   - Field is `sequence`, not `seq`. Backend authoritative.
 *   - Payload is NOT a JSON Merge Patch — it is a full snapshot of the changed entity (or relevant subset). Frontend MUST replace, not merge. RFC 7386 was a frontend assumption with no backend support.
 *   - `kind` is mandatory on every message including batched messages.
 *   - Each `kind` is paired with exactly one payload shape (tagged union at the message level).
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessage".
 */
export type SSEMessage =
  | SSEMessageRunStatusChanged
  | SSEMessageRunCountersUpdated
  | SSEMessageSpecStateChanged
  | SSEMessageSpecInterventionApplied
  | SSEMessageTurnAppended
  | SSEMessageWorkerHeartbeat
  | SSEMessageLogLine
  | SSEMessageResyncRequired
  | SSEMessageInterruptCreated
  | SSEMessageInterruptResolved
  | SSEMessageAutoConfigChanged;
/**
 * Stable identifier for an interruptible pipeline function.
 *
 * Naming convention: <phase>_<function>, snake_case, NO DOTS.
 * Used as the AutoConfig key, the interrupt point's `function_name`,
 * and the wire-level identifier in every interrupt-related endpoint.
 *
 * Display labels (e.g. 'KLEE Execution') belong in the frontend label table,
 * not here. The wire format is exactly these strings.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "PipelineFunctionId".
 */
export type PipelineFunctionId =
  | 'phase1_db_build'
  | 'phase1_query_execution'
  | 'phase1_sarif_parsing'
  | 'phase1_fact_enrichment'
  | 'phase1_spec_generation'
  | 'phase2_spec_selection'
  | 'phase2_source_exploration'
  | 'phase2_driver_synthesis'
  | 'phase2_stub_synthesis'
  | 'phase2_compile_diagnose'
  | 'phase2_klee_execution'
  | 'phase3_replay_driver_generation'
  | 'phase3_asan_compilation'
  | 'phase3_result_classification';
/**
 * Whether the interrupt blocks the whole run (Phase 1 functions) or just one spec (Phase 2/3 functions).
 *
 *   run-scoped:  phase1_*, phase2_spec_selection
 *                One interrupt blocks Phase 2 dispatch entirely until resolved.
 *   spec-scoped: phase2_source_exploration through phase3_result_classification
 *                Per-spec; other specs in the same run continue independently.
 *
 * Resolves interactive_control_spec.md §7.5 Open Question.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptScope".
 */
export type InterruptScope = 'run' | 'spec';
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptStatus".
 */
export type InterruptStatus = 'waiting' | 'resumed' | 'skipped';
/**
 * Allowed topic patterns:
 *   runs.all
 *   runs.<run_id>
 *   runs.<run_id>.specs
 *   runs.<run_id>.specs.<spec_id>
 *   runs.<run_id>.specs.<spec_id>.logs
 *   runs.<run_id>.workers
 *   runs.<run_id>.logs
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSETopicPattern".
 */
export type SSETopicPattern = string;
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "FileValidationSeverity".
 */
export type FileValidationSeverity = 'error' | 'warning' | 'info';

/**
 * Single source of truth for all types shared between frontend and backend.
 * Generated artifacts (TypeScript, Pydantic) must NOT be hand-edited.
 * See shared/contracts/README.md for the conflict resolution log.
 */
export interface SailorAPIContracts {
  [k: string]: unknown;
}
/**
 * Denormalized counters per run, maintained by the backend.
 * Field names match backend_spec.md §2.1 verbatim.
 * Frontend MUST use these names; legacy aliases like 'total_specs' are removed.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RunCounters".
 */
export interface RunCounters {
  specs_total: number;
  specs_filtered_out: number;
  specs_emitted: number;
  specs_phase2_queued: number;
  specs_phase2_running: number;
  specs_phase2_bug_triggered: number;
  specs_phase2_inconclusive: number;
  specs_phase2_likely_fp: number;
  specs_phase2_errored: number;
  specs_phase3_queued: number;
  specs_phase3_confirmed: number;
  specs_phase3_rejected: number;
  specs_phase3_errored: number;
  unique_confirmed: number;
  total_llm_tokens: number;
  total_klee_seconds: number;
}
/**
 * Per-run configuration. See backend_spec.md §2.1 (RunConfig).
 * Field names use snake_case throughout; legacy uppercase aliases (T_explore etc.) are removed.
 * Keys are flat: 'phase2_t_explore' rather than nested 'phase2.t_explore', because JSON object keys with dots are ambiguous when consumed by typed languages.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RunConfig".
 */
export interface RunConfig {
  /**
   * Query ids enabled for Phase 1. Default: all 34.
   */
  phase1_query_suite: string[];
  /**
   * Regex patterns matching file paths to skip.
   */
  phase1_skip_files: string[];
  /**
   * Regex patterns matching function names to skip.
   */
  phase1_skip_functions: string[];
  phase2_t_explore: number;
  phase2_t_author: number;
  phase2_t_max: number;
  phase2_t_klee_seconds: number;
  phase2_r_max: number;
  phase2_parallelism: number;
  phase2_llm_provider: string;
  phase2_llm_model: string;
  phase3_enabled: boolean;
  phase3_asan_options?: string | null;
}
/**
 * Phase 1 aggregate summary embedded in Run.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Phase1Summary".
 */
export interface Phase1Summary {
  raw_findings: number;
  after_filter: number;
  specs_emitted: number;
}
/**
 * A single pipeline invocation. See backend_spec.md §2.1.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Run".
 */
export interface Run {
  run_id: string;
  name: string;
  project_zip_ref?: string | null;
  build_command: string;
  codeql_build_mode: 'autodetect' | 'none' | 'custom';
  config: RunConfig;
  status: RunStatus;
  counters: RunCounters;
  phase1_summary?: Phase1Summary | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  /**
   * user id
   */
  created_by: string;
  error?: string | null;
}
/**
 * VulnerabilitySpec record. See backend_spec.md §2.1.
 * Field names match backend authoritatively.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Spec".
 */
export interface Spec {
  spec_id: string;
  run_id: string;
  rule_id: string;
  /**
   * Derived from rule_id, e.g. 'CWE-122'
   */
  cwe?: string | null;
  file: string;
  line: number;
  func?: string | null;
  message: string;
  snippet?: string | null;
  entrypoint?: string | null;
  assertion_template?: string | null;
  phase1_status: Phase1Status;
  phase2_status?: Phase2Status | null;
  phase3_status?: Phase3Status | null;
  current_turn?: number | null;
  turn_count_total?: number | null;
  refine_count?: number | null;
  phase2_outcome?: Phase2Outcome | null;
  phase2_error?: string | null;
  phase3_verdict?: VerdictValue | null;
  phase3_error?: string | null;
  worker_id?: string | null;
  intervention_pending?: boolean;
  artifacts_root?: string | null;
  created_at: string;
  last_event_at: string;
  /**
   * Cumulative LLM tokens for this spec.
   */
  token_cost?: number | null;
}
/**
 * One iteration of the Phase 2 loop. Append-only. See backend_spec.md §2.1.
 * Payload is fetched separately via GET /turns/:turn_id — the list endpoint returns Turn rows WITHOUT payload (only payload_ref).
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Turn".
 */
export interface Turn {
  turn_id: string;
  spec_id: string;
  turn_number: number;
  kind: TurnKind;
  started_at: string;
  ended_at?: string | null;
  duration_ms?: number | null;
  /**
   * Artifact store reference to detailed payload. Fetch via GET /turns/:turn_id.
   */
  payload_ref?: string | null;
  /**
   * Short string for timeline card (no large blobs).
   */
  summary: string;
  tokens_consumed?: number | null;
  klee_seconds?: number | null;
}
/**
 * Full Turn including inlined payload. Returned by GET /turns/:turn_id.
 * The payload variant depends on kind.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "TurnDetail".
 */
export interface TurnDetail {
  turn: Turn;
  payload: TurnPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "LLMTurnPayload".
 */
export interface LLMTurnPayload {
  kind: 'explore' | 'author' | 'refinement';
  prompt_tokens: number;
  completion_tokens: number;
  tool_calls?: {
    name: string;
    arguments?: unknown;
    [k: string]: unknown;
  }[];
  response_summary: string;
  prompt_excerpt?: string | null;
  response_excerpt?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "CompileFailPayload".
 */
export interface CompileFailPayload {
  kind: 'compile_fail';
  error_class: CompileErrorClass;
  raw_error: string;
  suggested_fix?: string | null;
  relevant_source?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "KleeRunPayload".
 */
export interface KleeRunPayload {
  kind: 'klee_run';
  outcome: KleeOutcome;
  paths_explored: number;
  functions_entered?: string[];
  functions_missed?: string[];
  ktest_paths?: string[];
  stderr_excerpt?: string;
  /**
   * True if KLEE hit T_klee. Replaces the former 'klee_timeout' turn kind.
   */
  timed_out?: boolean;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterventionPayload".
 */
export interface InterventionPayload {
  kind: 'intervention';
  intervention_type: 'edit_harness' | 'force_outcome' | 'edit_spec';
  /**
   * user id
   */
  actor: string;
  summary?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "TerminalPayload".
 */
export interface TerminalPayload {
  kind: 'terminal';
  final_outcome: Phase2Outcome;
}
/**
 * Phase 3 verdict record. See backend_spec.md §2.1.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Verdict".
 */
export interface Verdict {
  verdict_id: string;
  spec_id: string;
  verdict: VerdictValue;
  cwe: string;
  /**
   * e.g. 'heap-buffer-overflow'
   */
  asan_type: string;
  file: string;
  line: number;
  func: string;
  inputs?: {
    name: string;
    value: string;
  }[];
  asan_report_ref?: string | null;
  replay_driver_ref?: string | null;
  dedup_key: string;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "EditHarnessRequest".
 */
export interface EditHarnessRequest {
  type: 'edit_harness';
  /**
   * Logical artifact name, without '.c' extension. Frontend display may add '.c'.
   */
  artifact: 'driver' | 'slice' | 'assertions';
  /**
   * UTF-8 file contents.
   */
  contents: string;
  /**
   * Optimistic concurrency: the version the user was editing. 409 on conflict.
   */
  base_version: number;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "ForceOutcomeRequest".
 */
export interface ForceOutcomeRequest {
  type: 'force_outcome';
  outcome: 'skip_to_phase3' | 'mark_inconclusive' | 'mark_likely_fp';
  /**
   * Required iff outcome=skip_to_phase3.
   */
  witness_ktest_ref?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "EditSpecRequest".
 */
export interface EditSpecRequest {
  type: 'edit_spec';
  /**
   * Full VulnerabilitySpec replacement. Fields match Spec, but only the user-editable subset is required.
   */
  spec: {
    [k: string]: unknown;
  };
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageRunStatusChanged".
 */
export interface SSEMessageRunStatusChanged {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'run_status_changed';
  payload: RunStatusChangedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RunStatusChangedPayload".
 */
export interface RunStatusChangedPayload {
  run_id: string;
  status: RunStatus;
  previous_status?: RunStatus;
  error?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageRunCountersUpdated".
 */
export interface SSEMessageRunCountersUpdated {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'run_counters_updated';
  payload: RunCountersUpdatedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RunCountersUpdatedPayload".
 */
export interface RunCountersUpdatedPayload {
  run_id: string;
  counters: RunCounters;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageSpecStateChanged".
 */
export interface SSEMessageSpecStateChanged {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'spec_state_changed';
  payload: SpecStateChangedPayload;
}
/**
 * Full snapshot of the spec after the change. NOT a partial diff.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SpecStateChangedPayload".
 */
export interface SpecStateChangedPayload {
  spec: Spec;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageSpecInterventionApplied".
 */
export interface SSEMessageSpecInterventionApplied {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'spec_intervention_applied';
  payload: SpecInterventionAppliedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SpecInterventionAppliedPayload".
 */
export interface SpecInterventionAppliedPayload {
  spec_id: string;
  intervention_type: 'edit_harness' | 'force_outcome' | 'edit_spec';
  applied_at: string;
  actor?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageTurnAppended".
 */
export interface SSEMessageTurnAppended {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'turn_appended';
  payload: TurnAppendedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "TurnAppendedPayload".
 */
export interface TurnAppendedPayload {
  turn: Turn;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageWorkerHeartbeat".
 */
export interface SSEMessageWorkerHeartbeat {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'worker_heartbeat';
  payload: WorkerHeartbeatPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "WorkerHeartbeatPayload".
 */
export interface WorkerHeartbeatPayload {
  worker_id: string;
  status: 'idle' | 'busy' | 'died';
  current_spec_id?: string | null;
  last_heartbeat: string;
  throughput_specs_per_min?: number | null;
  tokens_per_min?: number | null;
  klee_seconds_per_min?: number | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageLogLine".
 */
export interface SSEMessageLogLine {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'log_line';
  payload: LogLinePayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "LogLinePayload".
 */
export interface LogLinePayload {
  timestamp: string;
  level: 'error' | 'warn' | 'info' | 'debug';
  source: 'celery' | 'phase1' | 'phase2' | 'phase3' | 'llm' | 'klee' | 'clang' | 'asan' | 'api';
  run_id?: string | null;
  spec_id?: string | null;
  worker_id?: string | null;
  trace_id?: string | null;
  message: string;
  fields?: {
    [k: string]: unknown;
  };
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageResyncRequired".
 */
export interface SSEMessageResyncRequired {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'resync_required';
  payload: ResyncRequiredPayload;
}
/**
 * Sent when the server's replay buffer (60s) cannot catch the client up.
 * Client MUST drop local state for affected topic and refetch via REST.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "ResyncRequiredPayload".
 */
export interface ResyncRequiredPayload {
  reason: 'buffer_overflow' | 'topic_subscription_reset' | 'unknown';
  last_known_sequence?: number | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageInterruptCreated".
 */
export interface SSEMessageInterruptCreated {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'interrupt_created';
  payload: InterruptCreatedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptCreatedPayload".
 */
export interface InterruptCreatedPayload {
  interrupt: InterruptPoint;
}
/**
 * An active or historical interrupt. Returned by GET /api/runs/:run_id/interrupts(/:interrupt_id).
 * See interactive_control_spec.md §3 for UI behavior.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptPoint".
 */
export interface InterruptPoint {
  interrupt_id: string;
  run_id: string;
  /**
   * Null for run-scoped interrupts (Phase 1, spec_selection). Required for spec-scoped.
   */
  spec_id?: string | null;
  function_name: PipelineFunctionId;
  scope: InterruptScope;
  /**
   * Phase 2 turn number when the interrupt fired; null for Phase 1/3.
   */
  turn?: number | null;
  status: InterruptStatus;
  created_at: string;
  resolved_at?: string | null;
  /**
   * User id of the intervener who resumed/skipped.
   */
  resolved_by?: string | null;
  /**
   * Files the user may View/Edit/Replace at this interrupt. Each entry's `artifact_ref` is an opaque reference resolvable via GET /api/artifacts/:ref (returns 302 to presigned URL).
   */
  input_files?: InterruptInputFile[];
  /**
   * Per-function option set the user may adjust at this interrupt. Schema depends on `function_name`; documented in interactive_control_spec.md §3.4 through §3.18.
   */
  option_overrides?: {
    [k: string]: unknown;
  };
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptInputFile".
 */
export interface InterruptInputFile {
  /**
   * Logical file name shown to the user, e.g. 'driver.c', 'findings.sarif'.
   */
  name: string;
  /**
   * Opaque artifact store reference. Fetch via GET /api/artifacts/:ref.
   */
  artifact_ref: string;
  size_bytes: number;
  mime_type: string;
  /**
   * True for text formats (C, JSON, SARIF, QL). False for binary (.ktest, .bc) — view-only.
   */
  editable: boolean;
  /**
   * Version counter for optimistic concurrency on subsequent edits.
   */
  version?: number | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageInterruptResolved".
 */
export interface SSEMessageInterruptResolved {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'interrupt_resolved';
  payload: InterruptResolvedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptResolvedPayload".
 */
export interface InterruptResolvedPayload {
  interrupt_id: string;
  run_id: string;
  spec_id?: string | null;
  resolution: 'resumed' | 'skipped';
  resolved_by?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageAutoConfigChanged".
 */
export interface SSEMessageAutoConfigChanged {
  topic: string;
  sequence: number;
  timestamp: string;
  kind: 'auto_config_changed';
  payload: AutoConfigChangedPayload;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "AutoConfigChangedPayload".
 */
export interface AutoConfigChangedPayload {
  run_id: string;
  auto_config: AutoConfig;
  changed_by?: string | null;
}
/**
 * Per-run Auto/Manual configuration. Keys are PipelineFunctionId values; value true=Auto, false=interrupt and wait.
 *
 * A missing key defaults to true (Auto). Implementations MUST persist only the explicit overrides, not the full set.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "AutoConfig".
 */
export interface AutoConfig {
  phase1_db_build?: boolean;
  phase1_query_execution?: boolean;
  phase1_sarif_parsing?: boolean;
  phase1_fact_enrichment?: boolean;
  phase1_spec_generation?: boolean;
  phase2_spec_selection?: boolean;
  phase2_source_exploration?: boolean;
  phase2_driver_synthesis?: boolean;
  phase2_stub_synthesis?: boolean;
  phase2_compile_diagnose?: boolean;
  phase2_klee_execution?: boolean;
  phase3_replay_driver_generation?: boolean;
  phase3_asan_compilation?: boolean;
  phase3_result_classification?: boolean;
}
/**
 * Internal: shared envelope fields. Each concrete message extends this with `kind` pinned to a const and `payload` typed to the matching variant.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEMessageEnvelopeBase".
 */
export interface SSEMessageEnvelopeBase {
  topic: string;
  sequence: number;
  timestamp: string;
}
/**
 * Server batches SSEMessage in 250ms windows per topic. Sent on the wire as the SSE 'data:' payload.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "SSEBatch".
 */
export interface SSEBatch {
  topic: string;
  /**
   * Sequence of the last message in batch.
   */
  sequence: number;
  /**
   * @minItems 1
   */
  batch: [SSEMessage, ...SSEMessage[]];
}
/**
 * Uniform error response shape. Returned with all non-2xx responses.
 * Replaces the frontend client's ad-hoc {code, message, detail}.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "ApiError".
 */
export interface ApiError {
  /**
   * Stable machine-readable code, snake_case. e.g. 'spec_not_found', 'invalid_transition', 'lease_expired'.
   */
  code: string;
  /**
   * Human-readable summary.
   */
  message: string;
  detail?: unknown;
  trace_id?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "PaginatedSpecs".
 */
export interface PaginatedSpecs {
  items: Spec[];
  next_cursor: string | null;
  prev_cursor?: string | null;
  total_estimate?: number | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "Worker".
 */
export interface Worker {
  worker_id: string;
  status: 'idle' | 'busy' | 'died';
  current_spec_id?: string | null;
  last_heartbeat: string;
  throughput_specs_per_min?: number | null;
  tokens_per_min?: number | null;
  klee_seconds_per_min?: number | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "User".
 */
export interface User {
  user_id: string;
  username: string;
  email?: string | null;
  display_name?: string | null;
  role: UserRole;
  created_at: string;
  last_login?: string | null;
  disabled?: boolean;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "AuditEvent".
 */
export interface AuditEvent {
  event_id: string;
  /**
   * user id
   */
  actor: string;
  action:
    | 'run_create'
    | 'run_pause'
    | 'run_resume'
    | 'run_cancel'
    | 'spec_requeue'
    | 'spec_intervene'
    | 'spec_skip'
    | 'settings_change'
    | 'role_change'
    | 'login'
    | 'logout'
    | 'interrupt_resume'
    | 'interrupt_skip'
    | 'auto_config_change'
    | 'file_replace'
    | 'user_register';
  /**
   * e.g. 'run:<id>' or 'spec:<id>'
   */
  target: string;
  diff?: {
    [k: string]: unknown;
  } | null;
  created_at: string;
}
/**
 * POST /api/runs/:run_id/interrupts/:interrupt_id/resume body.
 *
 * File uploads MUST be performed first via POST /api/runs/:run_id/interrupts/:interrupt_id/files (one call per file, returns artifact_ref). The resume body then references the new artifact_ref values. This avoids large base64 payloads in the resume call and keeps file validation visible as its own step.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptResumeRequest".
 */
export interface InterruptResumeRequest {
  /**
   * Files the user replaced or edited, referenced by artifact_ref returned from the upload endpoint. Each entry's `name` must match an `InterruptPoint.input_files[*].name` from this interrupt; unknown names are rejected.
   */
  modified_files?: {
    name: string;
    artifact_ref: string;
    /**
     * Optimistic concurrency token. Must equal the current InterruptInputFile.version; 409 on mismatch.
     */
    base_version?: number | null;
  }[];
  /**
   * Per-function override values. Validated against the function's option schema; unknown keys rejected.
   */
  option_overrides?: {
    [k: string]: unknown;
  };
  /**
   * Resolves interactive_control_spec.md §7.1 Open Question. When true, the same overrides are applied to all currently-waiting interrupts with the same function_name in this run (e.g., 128 KLEE Execution interrupts). modified_files MUST be empty when this is true (per-spec file edits cannot be broadcast).
   */
  apply_to_all_matching?: boolean;
  /**
   * Toggle the AutoConfig for this function_name back to true after resuming. Saves the user one extra round-trip when they only wanted to pause once.
   */
  re_enable_auto?: boolean;
}
/**
 * POST /api/runs/:run_id/interrupts/:interrupt_id/skip body.
 *
 * Skip means: use the default output of the function (the LLM-generated artifact, the auto-classified verdict, etc.) and proceed. Distinct from `spec.skip` which marks the whole spec as not-processed.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "InterruptSkipRequest".
 */
export interface InterruptSkipRequest {
  reason?: string | null;
  apply_to_all_matching?: boolean;
}
/**
 * PATCH /api/runs/:run_id/auto-config body. Partial update; only included keys are changed.
 *
 * Wire format is the FLAT map below — NOT nested under 'phase1'/'phase2'/'phase3', and NOT using dotted keys like 'phase2.klee_execution'. Reason: dotted JSON keys round-trip badly through typed languages; nesting adds parse complexity for no benefit.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "AutoConfigPatch".
 */
export interface AutoConfigPatch {
  phase1_db_build?: boolean;
  phase1_query_execution?: boolean;
  phase1_sarif_parsing?: boolean;
  phase1_fact_enrichment?: boolean;
  phase1_spec_generation?: boolean;
  phase2_spec_selection?: boolean;
  phase2_source_exploration?: boolean;
  phase2_driver_synthesis?: boolean;
  phase2_stub_synthesis?: boolean;
  phase2_compile_diagnose?: boolean;
  phase2_klee_execution?: boolean;
  phase3_replay_driver_generation?: boolean;
  phase3_asan_compilation?: boolean;
  phase3_result_classification?: boolean;
}
/**
 * Response from POST /api/validate/file and from the implicit validation that runs when a file is uploaded to an interrupt.
 *
 * NOT an error response — even severity='error' results return HTTP 200. ApiError is only for endpoint-level failures (auth, not found, server error). Validation errors are returned in the body so the UI can render them inline.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "FileValidationResult".
 */
export interface FileValidationResult {
  /**
   * Convenience: true iff severity != 'error'. Severity is authoritative.
   */
  valid: boolean;
  severity: FileValidationSeverity;
  /**
   * Human-readable summary.
   */
  message: string;
  /**
   * What the validator inferred the file to be, e.g. 'sarif', 'c-source', 'json-array', 'ktest', 'bitcode', 'unknown'.
   */
  detected_format: string;
  /**
   * Granular issues for inline display (e.g. clang error lines, JSON schema violations). Empty when severity='info'.
   */
  issues?: {
    severity: FileValidationSeverity;
    message: string;
    line?: number | null;
    column?: number | null;
    /**
     * Validator-specific rule id, e.g. 'sarif.missing_runs', 'replay_driver.klee_call_present'.
     */
    rule?: string | null;
  }[];
}
/**
 * Resolves interactive_control_spec.md §3.15 ambiguity: 'Disable LLM' is a per-spec configuration toggle, NOT a per-turn interrupt.
 *
 * When enabled, the worker treats phase2_driver_synthesis, phase2_stub_synthesis, and (where applicable) phase2_compile_diagnose as if auto=false — but ONLY for this one spec, without modifying the run-level AutoConfig. The spec stays in this mode until the user explicitly disables it via POST .../manual-harness with enabled=false. Re-queueing the spec preserves the flag.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "ManualHarnessMode".
 */
export interface ManualHarnessMode {
  spec_id: string;
  enabled: boolean;
  enabled_at?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RegisterRequest".
 */
export interface RegisterRequest {
  username: string;
  email: string;
  /**
   * Server validates strength: ≥1 uppercase, ≥1 digit, ≥1 symbol. Specific regex documented in backend implementation.
   */
  password: string;
  display_name?: string | null;
}
/**
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "RegisterResponse".
 */
export interface RegisterResponse {
  user_id: string;
  username: string;
  /**
   * User role, least to most privileged. See frontend_spec.md §10.
   */
  role: 'viewer' | 'operator' | 'intervener' | 'admin';
}
/**
 * Body for the override path of the phase3_result_classification interrupt. Sent in InterruptResumeRequest.option_overrides under the key 'classification'.
 *
 * This interface was referenced by `SailorAPIContracts`'s JSON-Schema
 * via the `definition` "ClassifyVerdictRequest".
 */
export interface ClassifyVerdictRequest {
  /**
   * Lowercase wire format. UI may capitalize for display; backend rejects 'CONFIRMED'.
   */
  verdict: 'confirmed' | 'rejected';
  /**
   * Optional CWE override, e.g. 'CWE-122'.
   */
  cwe?: string | null;
  reason?: string | null;
}
