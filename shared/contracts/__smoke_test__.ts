/**
 * Smoke test for generated TS types.
 * This file must compile under strict mode.
 */
import type {
  Run,
  RunStatus,
  Spec,
  SSEMessage,
  EditHarnessRequest,
  Verdict,
  RunCounters,
} from './sailor.types';

// Test 1: A valid Run literal must satisfy the type
const validRun: Run = {
  run_id: 'r_001',
  name: 'binutils-test',
  status: 'running',
  build_command: 'make',
  codeql_build_mode: 'autodetect',
  config: {
    phase1_query_suite: ['q1', 'q2'],
    phase1_skip_files: [],
    phase1_skip_functions: [],
    phase2_t_explore: 8,
    phase2_t_author: 12,
    phase2_t_max: 60,
    phase2_t_klee_seconds: 300,
    phase2_r_max: 15,
    phase2_parallelism: 128,
    phase2_llm_provider: 'gemini',
    phase2_llm_model: 'gemini-2.5-pro',
    phase3_enabled: true,
  },
  counters: {
    specs_total: 100,
    specs_filtered_out: 5,
    specs_emitted: 95,
    specs_phase2_queued: 50,
    specs_phase2_running: 10,
    specs_phase2_bug_triggered: 5,
    specs_phase2_inconclusive: 10,
    specs_phase2_likely_fp: 5,
    specs_phase2_errored: 2,
    specs_phase3_queued: 3,
    specs_phase3_confirmed: 1,
    specs_phase3_rejected: 1,
    specs_phase3_errored: 0,
    unique_confirmed: 1,
    total_llm_tokens: 1000000,
    total_klee_seconds: 3600,
  },
  created_at: '2026-05-25T00:00:00Z',
  created_by: 'u_alice',
};

// Test 2: Exhaustive switch on RunStatus must not require a default
function statusLabel(s: RunStatus): string {
  switch (s) {
    case 'created':
      return 'Created';
    case 'needs_build_config':
      return 'Needs build config';
    case 'queued':
      return 'Queued';
    case 'running':
      return 'Running';
    case 'paused':
      return 'Paused';
    case 'completed':
      return 'Completed';
    case 'failed':
      return 'Failed';
    case 'cancelled':
      return 'Cancelled';
    case 'archived':
      return 'Archived';
  }
}

// Test 3: SSE message discriminated union narrowing works
function describeMessage(m: SSEMessage): string {
  switch (m.kind) {
    case 'run_status_changed':
      return `run ${m.payload.run_id} -> ${m.payload.status}`;
    case 'run_counters_updated':
      return `counters for ${m.payload.run_id}`;
    case 'spec_state_changed':
      return `spec ${m.payload.spec.spec_id} state changed`;
    case 'spec_intervention_applied':
      return `intervention on ${m.payload.spec_id}`;
    case 'turn_appended':
      return `turn ${m.payload.turn.turn_number} on ${m.payload.turn.spec_id}`;
    case 'worker_heartbeat':
      return `worker ${m.payload.worker_id}: ${m.payload.status}`;
    case 'log_line':
      return `[${m.payload.level}] ${m.payload.message}`;
    case 'resync_required':
      return `resync: ${m.payload.reason}`;
  }
}

// Test 4: EditHarnessRequest type literal narrowing
const ehr: EditHarnessRequest = {
  type: 'edit_harness',
  artifact: 'driver',
  contents: 'int main(){}',
  base_version: 3,
};

// Test 5: A Verdict literal
const v: Verdict = {
  verdict_id: 'v_001',
  spec_id: 's_001',
  verdict: 'confirmed',
  cwe: 'CWE-122',
  asan_type: 'heap-buffer-overflow',
  file: 'elfxx-x86.c',
  line: 2286,
  func: 'elf_x86_link_hash_table',
  dedup_key: 'sha256:abc',
};

// Test 6: All RunCounters fields exist (regression test against old names)
const counters: RunCounters = validRun.counters;
const _total: number = counters.specs_total;
const _uniqueConfirmed: number = counters.unique_confirmed;
const _tokens: number = counters.total_llm_tokens;

// Smoke-export so unused-var warnings don't fire
export const _testExports = { validRun, statusLabel, describeMessage, ehr, v, counters };

// Negative test (must NOT compile if uncommented):
// const badRun: Run = { ...validRun, status: 'NOT_A_REAL_STATUS' };  // <-- type error
// const badCounters: RunCounters = { ...counters, total_specs: 100 }; // <-- type error (old name)
