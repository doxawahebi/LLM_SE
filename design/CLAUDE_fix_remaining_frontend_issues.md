# CLAUDE_fix_remaining_frontend_issues.md
# Fix: Pipeline Never Starts + Live Progress Never Shows

> Session goal: fix three critical bugs that cause the pipeline to appear
> broken end-to-end even after the SSE reconnect-loop fix from the previous
> session.

---

## Root Cause Summary

| # | Symptom | Root cause | File |
|---|---------|-----------|------|
| 1 | Pipeline never starts after "Start Run" | `# TODO: enqueue phase1_task(run.run_id)` — task never dispatched | `backend/api/runs.py:52` |
| 2 | Live progress never shows even when SSE stays open | Frontend parses `SSEDiff {seq, topic, diffs}` but backend sends `[{topic, sequence, kind, payload}]` — completely different shape | `frontend/src/hooks/useSSE.ts:69` |
| 3 | Missed events never replayed on reconnect | Frontend sends `?since=N` but backend expects `?Last-Event-ID=N` | `frontend/src/hooks/useSSE.ts:57` |
| 4 | 403 Forbidden shown as generic error | Interceptor handles 401/422/5xx but not 403; "Insufficient role" leaks to user unformatted | `frontend/src/api/client.ts` |
| 5 | Run created with no zip stays stuck in "created" forever | No task dispatched for runs without a zip; user sees no progress or guidance | `frontend/src/pages/NewRun.tsx` |

---

## Fix 1 — Dispatch Phase 1 Task (backend/api/runs.py)

**Where:** `backend/api/runs.py`, `create_run_endpoint` and `set_build_config`

**Change:** Replace both `# TODO: enqueue phase1_task(run.run_id)` comments with
actual task dispatch calls.

```python
# add import at top of file
from tasks.phase1 import phase1_task

# in create_run_endpoint, after transition_run to "queued":
phase1_task.delay(run.run_id)

# in set_build_config, after transition_run to "queued":
phase1_task.delay(run_id)
```

`phase1_task.delay()` is the standard Celery async dispatch — it returns
immediately and sends the task to the `phase1` queue. The Celery worker picks
it up and calls `_run_phase1(run_id)`, which transitions the run to `running`,
spins up a DockerRunner, and executes `Phase1Pipeline`.

---

## Fix 2 — SSE Event Parsing (frontend/src/hooks/useSSE.ts)

**Where:** `useSSE.ts`, the `es.onmessage` handler and named event listeners

**Actual backend wire format** (from `push_service._fan_out`):
```json
data: [
  {"topic": "runs.abc", "sequence": 5, "kind": "run_update", "payload": {...run...}},
  {"topic": "runs.abc", "sequence": 6, "kind": "counter_diff", "payload": {"counters": {...}}}
]
```

The backend sends one `data:` line containing a **JSON array** of event
objects. There is no `event:` prefix, so named event listeners
(`addEventListener("run_update", ...)`) never fire. All events arrive via
`es.onmessage`.

**Correct parsing logic:**
```typescript
es.onmessage = (event: MessageEvent) => {
  try {
    const items = JSON.parse(event.data as string) as Array<{
      topic: string;
      sequence: number;
      kind: string;
      payload: unknown;
    }>;
    for (const item of items) {
      if (item.sequence > lastSeqRef.current) {
        lastSeqRef.current = item.sequence;
      }
      if (item.kind === "run_update") {
        setRun(item.payload as Run);
      } else if (item.kind === "spec_update") {
        setSpec(item.payload as Spec);
      } else if (item.kind === "counter_diff") {
        const cp = item.payload as { counters: Run["counters"] };
        const runId = item.topic.replace(/^runs\./, "").split(".")[0];
        applyRunDiff(runId, { counters: cp.counters });
      } else if (item.kind === "interrupt_created") {
        onInterruptRef.current?.(item.payload as InterruptCreatedEvent);
      } else if (item.kind === "resync_required") {
        lastSeqRef.current = 0;
        es.close();
        esRef.current = null;
        onDisconnectRef.current?.();
        scheduleReconnectRef.current();
        return;
      }
    }
  } catch { /* ignore parse errors */ }
};
```

Remove all four `es.addEventListener(...)` calls — they are dead code.

---

## Fix 3 — SSE Reconnect Query Param (frontend/src/hooks/useSSE.ts)

**Where:** `useSSE.ts`, inside `connect()`, the `params.set("since", ...)` line

**Change:**
```typescript
// WRONG:
if (lastSeqRef.current > 0) params.set("since", String(lastSeqRef.current));

// CORRECT (matches backend Query alias):
if (lastSeqRef.current > 0) params.set("Last-Event-ID", String(lastSeqRef.current));
```

The backend endpoint declares:
```python
last_event_id: str | None = Query(None, alias="Last-Event-ID")
```

Without the correct param name, `event_service.get_replay_buffer()` is never
called and any events missed during a reconnect gap are permanently lost.

---

## Fix 4 — 403 Role Error (frontend/src/api/client.ts + NewRun.tsx)

### 4A — Global interceptor (client.ts)

Add 403 handling alongside the existing 401/422/5xx handlers:

```typescript
} else if (status === 403) {
  showError("Permission denied — you need Operator role or higher to perform this action.")
}
```

### 4B — NewRun form (NewRun.tsx)

Detect "Insufficient role" in the catch block and show a helpful message with
a link to the Users settings page:

```typescript
} catch (err: unknown) {
  const apiErr = err as { message?: string; code?: string };
  if (apiErr.code === "403" || apiErr.message?.toLowerCase().includes("role")) {
    setError(
      "You need Operator role to create runs. Ask an admin to update your role at Settings → Users."
    );
  } else {
    setError(apiErr.message ?? "Failed to create run");
  }
}
```

Move the `{error && ...}` block to **above** the first `<Section>` (immediately
after the `<h1>`) so the error is always visible without scrolling.

---

## Fix 5 — Require Zip with Clear Message (NewRun.tsx)

Without a project zip, the backend creates a run in `created` status and
never dispatches a task. The user sees the run page with no activity, no error,
no guidance.

Add validation at the top of `handleSubmit`:

```typescript
if (!file) {
  setError(
    "A project .zip file is required to start the pipeline. " +
    "Drag and drop your source archive or click 'or browse'."
  );
  return;
}
```

---

## Error Detection Layer (already partially done)

The following error-detection infrastructure is now in place:

| Mechanism | Status | What it covers |
|-----------|--------|----------------|
| Global `ErrorToastContainer` | Done (prev session) | All 422/5xx/network errors via Axios interceptor |
| `console.error("[API]", ...)` | Done (prev session) | Every failed request logged with URL + status |
| SSE `onDisconnect` callback | Done (prev session) | `SSEStatusIndicator` turns yellow when SSE drops |
| Interrupt toast | Done (prev session) | Pipeline pause notification with "Go to spec" link |

**New additions this session:**
- 403 role error → informative toast + inline form message
- Zip requirement missing → inline form message before any network call

---

## Execution Steps

### Step 1 — Backend: dispatch task

Edit `backend/api/runs.py`:
- Add `from tasks.phase1 import phase1_task` import
- Replace both `# TODO: enqueue phase1_task(...)` comments with `phase1_task.delay(run_id)`

### Step 2 — Frontend: fix SSE parsing + reconnect param

Edit `frontend/src/hooks/useSSE.ts`:
- Rewrite `es.onmessage` to parse the array format
- Remove all four `es.addEventListener(...)` calls
- Change `params.set("since", ...)` to `params.set("Last-Event-ID", ...)`

### Step 3 — Frontend: 403 handling

Edit `frontend/src/api/client.ts`:
- Add `else if (status === 403)` branch in the response interceptor

### Step 4 — Frontend: NewRun improvements

Edit `frontend/src/pages/NewRun.tsx`:
- Move `{error && ...}` to top of form (below `<h1>`)
- Add zip-required validation in `handleSubmit`
- Add role-specific error detection in the catch block

### Step 5 — Rebuild and verify

```bash
docker compose build frontend backend
docker compose up -d
# Verify:
# 1. POST /api/runs → navigates to run detail, status transitions to "running"
# 2. SSE indicator shows green "Live"
# 3. Spec table populates as phase 1 runs
# 4. Viewer role → "You need Operator role..." message on submit
# 5. No zip → error above form before submission
```
