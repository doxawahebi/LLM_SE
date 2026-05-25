/**
 * Example integration of shared contracts on the frontend side.
 * This file shows how the existing frontend code (described in
 * CLAUDE_frontend.md) is rewritten to import from the shared contracts.
 *
 * Copy into frontend/src/hooks/useSSE.ts when bootstrapping the project.
 */

import type {
  SSEMessage,
  SSEBatch,
  Spec,
  Run,
  RunCounters,
  ApiError,
} from '@/shared/contracts/sailor.types';

// ─── State store interface (frontend-only) ─────────────────────────────

interface SpecStore {
  upsertSpec(spec: Spec): void;
  removeSpec(specId: string): void;
  resyncFromRest(runId: string): Promise<void>;
}

interface RunStore {
  setStatus(runId: string, status: Run['status']): void;
  setCounters(runId: string, counters: RunCounters): void;
  resyncFromRest(runId: string): Promise<void>;
}

interface LogStore {
  append(line: { timestamp: string; level: string; source: string; message: string }): void;
}

interface WorkerStore {
  upsertWorker(w: {
    worker_id: string;
    status: 'idle' | 'busy' | 'died';
    current_spec_id: string | null;
    last_heartbeat: string;
  }): void;
}

// ─── Message dispatcher ────────────────────────────────────────────────

/**
 * Dispatch a single SSE message to the appropriate stores.
 * TypeScript narrows `m.payload` based on `m.kind` — every case is checked.
 */
function dispatchMessage(
  m: SSEMessage,
  stores: { spec: SpecStore; run: RunStore; log: LogStore; worker: WorkerStore },
): void {
  switch (m.kind) {
    case 'run_status_changed':
      stores.run.setStatus(m.payload.run_id, m.payload.status);
      return;

    case 'run_counters_updated':
      stores.run.setCounters(m.payload.run_id, m.payload.counters);
      return;

    case 'spec_state_changed':
      // payload.spec is a full Spec snapshot — replace, do NOT merge
      stores.spec.upsertSpec(m.payload.spec);
      return;

    case 'spec_intervention_applied':
      // The state change is reflected via a subsequent spec_state_changed;
      // here we may just trigger a UI toast.
      console.log(
        `Intervention ${m.payload.intervention_type} applied to ${m.payload.spec_id}`,
      );
      return;

    case 'turn_appended':
      // Timeline component subscribes separately; for now, only log
      console.log(`Turn ${m.payload.turn.turn_number} on ${m.payload.turn.spec_id}`);
      return;

    case 'worker_heartbeat':
      stores.worker.upsertWorker({
        worker_id: m.payload.worker_id,
        status: m.payload.status,
        current_spec_id: m.payload.current_spec_id ?? null,
        last_heartbeat: m.payload.last_heartbeat,
      });
      return;

    case 'log_line':
      stores.log.append({
        timestamp: m.payload.timestamp,
        level: m.payload.level,
        source: m.payload.source,
        message: m.payload.message,
      });
      return;

    case 'resync_required':
      // Drop local state; refetch authoritative state via REST.
      // The topic on the SSE envelope tells us which scope to resync.
      console.warn(`Resync required: ${m.payload.reason}`);
      // Resync logic delegated to caller via store.resyncFromRest()
      return;

    case 'interrupt_created':
      // Pipeline paused waiting for user input. Show a toast and let the
      // user navigate to the interrupt panel.
      console.log(
        `Interrupt ${m.payload.interrupt.interrupt_id} at ${m.payload.interrupt.function_name}`,
      );
      return;

    case 'interrupt_resolved':
      // User resumed or skipped — the interrupt panel can close.
      console.log(`Interrupt ${m.payload.interrupt_id} ${m.payload.resolution}`);
      return;

    case 'auto_config_changed':
      // Another user toggled an Auto checkbox; reflect in the sidebar.
      console.log(`Auto-config changed on run ${m.payload.run_id}`);
      return;
  }
  // If TypeScript ever complains about this point being reachable,
  // a new `kind` was added to the schema without a handler. Add one.
}

// ─── EventSource wrapper ───────────────────────────────────────────────

interface UseSSEOptions {
  topics: string[]; // e.g. ["runs.r_001", "runs.r_001.specs"]
  token: string;
  stores: { spec: SpecStore; run: RunStore; log: LogStore; worker: WorkerStore };
  onResync?: (topic: string) => void;
}

export function startSSE(opts: UseSSEOptions): () => void {
  const url = new URL('/api/events', window.location.origin);
  url.searchParams.set('topics', opts.topics.join(','));
  url.searchParams.set('token', opts.token);

  const es = new EventSource(url.toString());

  es.onmessage = (e) => {
    const data: unknown = JSON.parse(e.data);

    // The server sends either a single message or a batch.
    // We distinguish by presence of `batch`.
    if (isBatch(data)) {
      for (const msg of data.batch) {
        dispatchMessage(msg, opts.stores);
      }
    } else if (isMessage(data)) {
      dispatchMessage(data, opts.stores);
    } else {
      console.error('Malformed SSE payload (does not match SSEMessage or SSEBatch):', data);
    }
  };

  es.onerror = (e) => {
    console.warn('SSE connection error; browser will auto-reconnect', e);
    // Native EventSource handles reconnect with Last-Event-ID automatically.
  };

  return () => es.close();
}

// ─── Runtime guards (because JSON has no types at runtime) ─────────────

function isMessage(d: unknown): d is SSEMessage {
  return (
    typeof d === 'object' &&
    d !== null &&
    'kind' in d &&
    'topic' in d &&
    'sequence' in d &&
    'payload' in d
  );
}

function isBatch(d: unknown): d is SSEBatch {
  return (
    typeof d === 'object' &&
    d !== null &&
    'batch' in d &&
    Array.isArray((d as { batch: unknown }).batch)
  );
}

// ─── API client error normalization ────────────────────────────────────

export async function handleApiError(response: Response): Promise<never> {
  const body: unknown = await response.json().catch(() => null);
  if (isApiError(body)) {
    // Throw a typed error the rest of the app can branch on by `code`.
    throw Object.assign(new Error(body.message), {
      code: body.code,
      detail: body.detail,
      trace_id: body.trace_id ?? null,
      status: response.status,
    });
  }
  throw new Error(`HTTP ${response.status}: ${response.statusText}`);
}

function isApiError(d: unknown): d is ApiError {
  return (
    typeof d === 'object' &&
    d !== null &&
    'code' in d &&
    'message' in d &&
    typeof (d as { code: unknown }).code === 'string' &&
    typeof (d as { message: unknown }).message === 'string'
  );
}
