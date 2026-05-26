export type RunStatus =
  | "queued" | "running" | "paused" | "completed" | "failed" | "cancelled"
  | "needs_build_config";

export type Phase2Status =
  | "queued" | "exploring" | "authoring" | "refining"
  | "bug_triggered" | "inconclusive" | "likely_false_positive";

export type Phase3Status =
  | "queued" | "running" | "confirmed" | "rejected" | "skipped";

export type Verdict =
  | "CONFIRMED" | "inconclusive" | "likely_false_positive" | "rejected" | null;

export type TurnKind =
  | "explore" | "author" | "compile_fail" | "klee_run" | "refinement"
  | "intervention" | "klee_timeout";

export interface Run {
  id: string;
  name: string;
  status: RunStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  project_ref: string;
  config: RunConfig;
  counters: RunCounters;
}

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
  unique_confirmed: number;
  total_llm_tokens: number;
  total_klee_seconds: number;
}

export interface RunConfig {
  build_command: string | null;
  codeql_build_mode: "autodetect" | "none" | "custom";
  query_ids: string[];
  T_explore: number;
  T_author: number;
  T_max: number;
  T_klee: number;
  R_max: number;
  parallelism: number;
  llm_provider: string;
  llm_model: string;
  run_phase3: boolean;
}

export interface Spec {
  id: string;
  run_id: string;
  rule_id: string;
  cwe: string;
  file: string;
  line: number;
  func: string;
  message: string;
  snippet: string;
  phase1_status: "emitted" | "filtered";
  phase2_status: Phase2Status | null;
  phase3_status: Phase3Status | null;
  verdict: Verdict;
  current_turn: number | null;
  error_class: string | null;
  token_cost: number;
  last_updated: string;
}

export interface Turn {
  id: string;
  spec_id: string;
  turn_number: number;
  kind: TurnKind;
  started_at: string;
  duration_ms: number;
  payload: TurnPayload | null;
}

export type TurnPayload =
  | LLMTurnPayload
  | CompileFailPayload
  | KleeRunPayload
  | ArtifactWritePayload;

export interface LLMTurnPayload {
  kind: "explore" | "author" | "refinement";
  prompt_tokens: number;
  completion_tokens: number;
  tool_calls: ToolCall[];
  response_summary: string;
}

export interface CompileFailPayload {
  kind: "compile_fail";
  error_class: "incomplete_type" | "conflicting_proto" | "redefinition" | "other";
  raw_error: string;
  suggested_fix: string;
  relevant_source?: string;
}

export interface KleeRunPayload {
  kind: "klee_run";
  outcome: "not_reached" | "site_reached" | "bug_triggered";
  paths_explored: number;
  functions_entered: string[];
  functions_missed: string[];
  ktest_paths: string[];
  stderr_excerpt: string;
}

export interface ArtifactWritePayload {
  kind: "intervention";
  files_written: string[];
  diff?: string;
}

export interface ToolCall {
  name: string;
  input: Record<string, unknown>;
  output?: string;
}

export interface ArtifactNode {
  name: string;
  path: string;
  type: "file" | "directory";
  size?: number;
  children?: ArtifactNode[];
}

export interface WorkerInfo {
  id: string;
  hostname: string;
  status: "active" | "idle" | "failed";
  current_spec_id: string | null;
  current_turn: number | null;
  started_at: string;
  specs_completed: number;
}

export interface WorkerStats {
  total: number;
  active: number;
  idle: number;
  failed: number;
  specs_per_min: number;
  avg_spec_duration_min: number;
  p95_spec_duration_min: number;
  tokens_per_min: number;
  klee_seconds_per_min: number;
  queue_depth: number;
  workers: WorkerInfo[];
}

export interface LogLine {
  id: string;
  timestamp: string;
  level: "error" | "warn" | "info" | "debug";
  source: "celery" | "phase1" | "phase2" | "phase3" | "llm" | "klee" | "clang" | "asan";
  spec_id: string | null;
  worker_id: string | null;
  message: string;
}

export interface VerifiedBug {
  spec_id: string;
  cwe: string;
  asan_type: string;
  file: string;
  line: number;
  func: string;
  witness_summary: string;
  first_seen: string;
  replay_still_crashes: boolean;
}

export interface SSEDiff {
  seq: number;
  topic: string;
  diffs: Array<{ id: string; patch: Partial<Spec | Run> }>;
}

export interface ApiError {
  code: string;
  message: string;
  detail?: unknown;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  cursor: string | null;
  has_more: boolean;
}

export interface DashboardMetrics {
  total_runs: number;
  confirmed_bugs: number;
  avg_tokens_per_bug: number;
  avg_phase2_latency_min: number;
  worker_utilization: number;
}
