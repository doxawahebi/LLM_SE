# CLAUDE_frontend.md — Sailor Frontend Implementation Prompt

> Claude Code reads this file during Session: Frontend Implementation.
> Stack: React 18 + Vite + TypeScript + Tailwind CSS.
> All Absolute Rules in CLAUDE.md apply.
> Never implement backend logic here — only API consumption.

---

> **Type definitions are NOT in this file.**
> Every shared type lives in `shared/contracts/sailor.types.ts`,
> generated from `shared/contracts/sailor.schema.json`. Import; do not
> redefine. If you see a discrepancy between this file and the schema,
> the schema wins — open an issue and fix this file.

## Spec Evaluation: What Is Missing or Needs Clarification

The uploaded `frontend_spec.md` is comprehensive. The following gaps
must be resolved before or during implementation.

### Gap 1: State Management Strategy (not specified)

The spec has 30K+ rows with live SSE updates and normalized diffs.
This requires a deliberate choice:

```
Decision: use Zustand for global state + TanStack Query for server state

Rationale:
  - Zustand: lightweight, works well with SSE diff merging
  - TanStack Query: handles REST pagination, caching, background refresh
  - Do NOT use Redux — too heavy for this read-heavy UI
  - Do NOT use React Context for the spec table — re-render cost is too high

State shape:
  useRunStore    → current run metadata, controls
  useSpecStore   → normalized spec map { spec_id: SpecState }
  useSSEStore    → SSE connection per topic, reconnect logic
```

### Gap 2: Virtualized Table Library (not specified)

```
Decision: TanStack Virtual (aka react-virtual v3)

Rationale:
  - Handles 30K+ rows at 60fps
  - Works with dynamic row heights (spec rows expand on selection)
  - Same ecosystem as TanStack Query

Alternative considered: AG Grid Community — rejected (bundle size)
```

### Gap 3: Code Editor for Intervention Panel (not specified)

```
Decision: CodeMirror 6 (via @uiw/react-codemirror)

Used in:
  - Intervention Panel §4d (harness editor)
  - Spec JSON editor (Mode C)
  - Source viewer §7b (read-only, with gutter annotations)

Rationale: lightweight, extensible, handles 100K-line files with
           progressive syntax highlighting
```

### Gap 4: SSE Client Implementation

Wire format is defined by `shared/contracts/sailor.schema.json`
(`SSEMessage`, `SSEBatch`). Frontend MUST NOT diverge.

```
Decision: custom useSSE() hook on top of native EventSource

Connection:
  - URL: `/api/events?topics=<comma-separated>&token=<jwt>`
    (browser EventSource cannot send Authorization headers — token
    must be a query parameter. Backend validates the same as a header.)
  - Topics format: see `SSETopicPattern` in the schema.

Reconnect:
  - Native EventSource handles reconnect; on each reconnect it sends
    the `Last-Event-ID` HTTP header automatically. The server uses
    this to replay from the 60-second buffer.
  - If the server sends `{kind: "resync_required"}`, the client drops
    its local store for that topic and refetches via REST.

Payload handling:
  - Each `SSEMessage` carries a full snapshot in `payload` — NOT a
    JSON Merge Patch. Frontend replaces by `spec_id`/`run_id`, not
    merges. Anything still using RFC 7386 is wrong; delete it.
  - Batches (`SSEBatch`) wrap multiple messages within a 250ms window.
    Process them in order; the batch's `sequence` is the last message's
    sequence (not a separate counter).

Dispatch:
  - Use a `switch (msg.kind)` exhaustively. TypeScript's discriminated
    union will warn if a case is missing.
```

### Gap 5: Open Questions Resolution (§14 of spec)

These must be decided before building the affected components:

```
§14.1 Artifact storage
  Decision for UI: UI always fetches artifacts via API proxy.
  Direct S3 URLs are NOT exposed to the browser (avoids CORS + auth issues).
  The API returns presigned URLs valid for 5 minutes.
  UI implementation: simple <a href={presignedUrl} download> links.

§14.2 Harness edit semantics
  Decision: edit consumes 1 turn from T_max (as spec §4d states).
  UI shows: "Editing will consume 1 of your remaining N turns."
  No alternative counting for now.

§14.3 Source viewer scope
  Decision: only files referenced by specs (lighter implementation).
  Full project source browser is a post-MVP feature.
  UI shows a "Browse full project" button (disabled, "coming soon").

§14.4 Multi-run comparison fuzziness
  Decision: exact match (file, func, line) for MVP.
  Fuzzy match (CWE + function) is a filter toggle, post-MVP.

§14.5 LLM transcript redaction
  Decision: per-project "redact source" flag in settings.
  UI shows [REDACTED] in transcript viewer when flag is on.
  Export downloads a redacted version.

§14.6 Live KLEE integration
  Decision: not in MVP. UI shows "X paths explored" only when
  KLEE writes structured progress (future backend work needed).
```

### Gap 6: Loading States and Skeleton UI (not specified)

```
Every data-dependent component must have:
  - Skeleton loader (same shape as content)
  - Empty state (no data yet)
  - Error state (API failed)
  - Stale indicator (SSE disconnected, data may be old)

Use @tanstack/react-query's isLoading/isError/isFetching states.
```

### Gap 7: URL State Synchronization (not specified)

```
Filter state in the spec table must be URL-encoded so:
  - Sharing a filtered view works
  - Browser back/forward navigates filter history

Use: nuqs (URL search param state management for React)
Encode: phase, status, cwe, verdict, search, preset name
```

---

## `frontend/Dockerfile`

Multi-stage build: development 모드와 production 모드 모두 지원.
`docker-compose.yml`의 `FRONTEND_TARGET` 환경변수로 선택.

```dockerfile
# Stage 1: development (Vite dev server with HMR)
FROM node:20-alpine AS development
WORKDIR /app
COPY package*.json ./
RUN npm install --frozen-lockfile || npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

# Stage 2: build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --frozen-lockfile || npm install
COPY . .
RUN npm run build          # outputs to /app/dist

# Stage 3: production (nginx)
FROM nginx:alpine AS production
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

> Note: `npm install --frozen-lockfile || npm install` is used instead of `npm ci`
> to handle missing lock-file edge cases during local development.

```nginx
# frontend/nginx.conf
server {
    listen 80;

    # Proxy API calls to backend
    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;

        # SSE support (disable buffering)
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
    }

    # SPA fallback — all other routes serve index.html
    location / {
        root  /usr/share/nginx/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
}
```

The API base URL is injected as an environment variable. Fixed at Vite build time:

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        // 'http://localhost:8000' for local dev (outside Docker)
        // VITE_API_URL=http://backend:8000 inside Docker network
        target: process.env.VITE_API_URL ?? 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
```

---

## Component Architecture

```
frontend/src/
├── main.tsx
├── App.tsx                       ← routes (react-router-dom v6)
│
├── api/
│   ├── client.ts                 ← axios instance, auth headers, error handling
│   ├── runs.ts                   ← all /api/runs/* endpoints
│   ├── specs.ts                  ← all /api/runs/:id/specs/* endpoints
│   ├── artifacts.ts              ← artifact download helpers
│   └── settings.ts
│
├── hooks/
│   ├── useSSE.ts                 ← SSE connection + reconnect + diff merge
│   ├── useSpecStore.ts           ← Zustand store for 30K spec state
│   ├── useRunStore.ts            ← Zustand store for run metadata
│   └── useAuth.ts                ← role-based permission checks
│
├── pages/
│   ├── Dashboard.tsx             ← /
│   ├── NewRun.tsx                ← /runs/new
│   ├── RunDetail.tsx             ← /runs/:run_id
│   │   ├── RunHeader.tsx         ← live progress + controls
│   │   ├── SpecTable.tsx         ← virtualized 30K-row table
│   │   ├── ChartsStrip.tsx       ← live aggregate charts
│   │   └── RunResultsTab.tsx     ← §7 Results Browser
│   ├── SpecDetail.tsx            ← /runs/:run_id/specs/:i
│   │   ├── SpecHeader.tsx
│   │   ├── Timeline.tsx          ← vertical event timeline
│   │   ├── ArtifactTree.tsx      ← file tree + viewer
│   │   └── InterventionPanel.tsx ← §4d modes A/B/C
│   ├── WorkerView.tsx            ← /runs/:run_id/workers
│   ├── LogsView.tsx              ← /runs/:run_id/logs
│   ├── Settings.tsx              ← /settings
│   ├── Register.tsx              ← /register  (spec §2.2)
│   └── UserManagement.tsx        ← /settings/users  (spec §2.4, admin only)
│
├── components/
│   ├── ui/                       ← shadcn/ui base components
│   ├── StatusBadge.tsx           ← phase/status color chips
│   ├── ProgressBar.tsx           ← phase progress bars
│   ├── RunTile.tsx               ← dashboard run tile
│   ├── SpecRow.tsx               ← virtualized table row
│   ├── TurnCard.tsx              ← timeline event card
│   ├── HarnessEditor.tsx         ← CodeMirror C editor
│   ├── SpecJsonEditor.tsx        ← CodeMirror JSON editor
│   ├── SourceViewer.tsx          ← CodeMirror read-only + gutter annotations
│   ├── ArtifactDownloadButton.tsx
│   ├── ConfirmModal.tsx          ← intervention confirmation
│   │
│   ├── AutoCheckbox.tsx          ← Auto/Manual toggle per pipeline function
│   ├── PipelineControlsSidebar.tsx ← collapsible sidebar with all Auto checkboxes
│   │
│   ├── interrupt/
│   │   ├── InterruptPanel.tsx         ← base panel (common elements per spec §3.3)
│   │   ├── InterruptFileRow.tsx       ← single file row (view/edit/replace)
│   │   ├── FileValidationBanner.tsx   ← ERROR/WARNING/INFO banner
│   │   │
│   │   ├── phase1/
│   │   │   ├── DBBuildInterrupt.tsx         ← §3.4
│   │   │   ├── QuerySelectorInterrupt.tsx   ← §3.5 (checklist + .ql viewer)
│   │   │   ├── SARIFParseInterrupt.tsx      ← §3.6
│   │   │   ├── FactEnrichInterrupt.tsx      ← §3.7
│   │   │   └── SpecGenInterrupt.tsx         ← §3.8
│   │   │
│   │   ├── phase2/
│   │   │   ├── SourceExploreInterrupt.tsx   ← §3.9
│   │   │   ├── SpecSelectorInterrupt.tsx    ← §3.10 (checklist + cost estimate)
│   │   │   ├── DriverSynthInterrupt.tsx     ← §3.11
│   │   │   ├── StubSynthInterrupt.tsx       ← §3.12 (CWE-416 warning)
│   │   │   ├── CompileDiagInterrupt.tsx     ← §3.13
│   │   │   ├── KLEEExecInterrupt.tsx        ← §3.14
│   │   │   └── ManualHarnessEditor.tsx      ← §3.15 (LLM Disable mode)
│   │   │
│   │   └── phase3/
│   │       ├── ReplayDriverInterrupt.tsx    ← §3.16 (klee_* blocking)
│   │       ├── ASanCompileInterrupt.tsx     ← §3.17 (stub-file blocking)
│   │       └── ResultClassifyInterrupt.tsx  ← §3.18 (verdict override)
│   │
│   └── downloads/
│       ├── PhaseDownloadButton.tsx    ← single file download (presigned redirect)
│       ├── PhaseDownloadGroup.tsx     ← "Download all Phase N outputs"
│       └── EvidencePackageButton.tsx  ← cross-phase evidence tarball
│
└── lib/
    ├── types.ts                  ← all TypeScript interfaces (mirrors API schema)
    ├── statusColors.ts           ← phase/status → Tailwind color mapping
    ├── jsonPatch.ts              ← JSON Merge Patch applier (RFC 7386)
    └── formatters.ts             ← duration, token count, timestamp formatters
```

---

## TypeScript Types — DO NOT REDEFINE HERE

All types that cross the API boundary live in `shared/contracts/sailor.types.ts`,
generated from `shared/contracts/sailor.schema.json`. Frontend code MUST
import from there:

```ts
import type {
  Run, Spec, Turn, TurnDetail, Verdict,
  RunStatus, Phase2Status, Phase3Status,
  RunConfig, RunCounters,
  SSEMessage, SSEBatch, SSEMessageKind,
  InterventionRequest, EditHarnessRequest, ForceOutcomeRequest, EditSpecRequest,
  ApiError, PaginatedSpecs,
} from "@/shared/contracts/sailor.types";
```

There must be no `lib/types.ts` redefining these. If you find yourself
typing `export type RunStatus =` anywhere in the `frontend/` tree, stop
and import instead.

The contracts directory's `README.md` documents every contract decision
that was previously ambiguous (SSE envelope, RunCounters field names,
RunConfig naming, Verdict casing, intervention discriminators). Read it
before disagreeing with any field name.

### Frontend-only types

Some types are **purely UI state** and never cross the API. Those may
live in `frontend/src/lib/ui-types.ts`:

```ts
// frontend/src/lib/ui-types.ts
export type FilterPreset = { name: string; filters: SpecFilters };
export type SpecFilters = {
  phase?: 1 | 2 | 3;
  status?: string;
  cwe?: string;
  fileGlob?: string;
  verdict?: string;
  search?: string;
};
export type ToastSeverity = "info" | "success" | "warning" | "error";
```

These never appear in network payloads.

---

## New Component Implementation Details

```
AutoCheckbox.tsx
  Props: functionName, runId, defaultChecked
  On toggle: PATCH /api/runs/:runId/auto-config {[functionName]: checked}
  Optimistic update: update local state, revert on API error.

InterruptPanel.tsx (base)
  Triggered by SSE event: {kind: "interrupt_created", interrupt_id}
  Displays as full-screen overlay (desktop) or bottom drawer (mobile).
  Common elements (spec §3.3):
    - Header: function name, spec_id, phase, turn/T_max
    - File list with InterruptFileRow per input file
    - FileValidationBanner (shown after file replacement/edit)
    - Resume button: POST /api/runs/:id/interrupts/:iid/resume
    - Skip button:  POST /api/runs/:id/interrupts/:iid/skip
    - "☑ Auto (re-enable)" checkbox

InterruptFileRow.tsx
  Props: filename, size, contentType, artifactUrl, interruptId
  [View]:    fetch content, display in modal (CodeMirror read-only)
  [Edit]:    open CodeMirror editor, on save → validate then include
             in resume payload as modified_files entry
  [Replace]: file input → POST /api/validate/file first
             Show FileValidationBanner with result before confirming

FileValidationBanner.tsx
  Props: severity ("error"|"warning"|"info"), message, detectedFormat
  ERROR:   red, blocks Resume button
  WARNING: yellow, Resume allowed with "Proceed anyway" confirmation
  INFO:    blue, informational only

QuerySelectorInterrupt.tsx (spec §3.5)
  Scrollable checklist of all 34 queries.
  Each row: [☑] query_id | CWE | [▼ expand]
  Expand: CodeMirror read-only .ql viewer.
  Edit button → editable CodeMirror. Edited queries sent as modified_files.
  Validation: POST /api/validate/file for each modified .ql.

SpecSelectorInterrupt.tsx (spec §3.10)
  Scrollable checklist of all VulnerabilitySpecs.
  Each row: [☑] CWE · file:line | function | [▼ expand]
  Expand: CodeMirror JSON viewer; [Edit] → editable, validated on change.
  Cost estimate: updates live as checkboxes toggled.
    formula: selectedCount × AVG_TOKENS_PER_SPEC × providerPrice

ManualHarnessEditor.tsx (spec §3.15)
  Three-tab CodeMirror editor: [driver.c] [slice.c] [assertions.c]
  "Submit manual harness" → validates all three compile, then resume.
  "Re-enable LLM" → PATCH auto-config to restore LLM for this spec.

PhaseDownloadButton.tsx
  Props: runId, specId?, phase, filename, label
  On click: GET endpoint → follows 302 redirect → browser download.
  Shows spinner while redirect resolves.

PhaseDownloadGroup.tsx
  Collapsible section per phase in the Artifacts pane.
  "Download all Phase N outputs" → .tar.gz endpoint.
  Individual file rows: filename, size, [↓] button.

Interrupt Notification System (SSE → toast):
  When interrupt fires on a spec the user is NOT currently viewing:
    → Toast (bottom-right): "⏸ Spec X paused at Phase 2 · KLEE Execution"
    → [Go to spec →] click navigates to spec detail, InterruptPanel opens.
  When user IS on the interrupted spec's page:
    → InterruptPanel opens as overlay immediately (no toast).
  SSE event kind: "interrupt_created" on topic: runs.{run_id}.

PipelineControlsSidebar.tsx
  Collapsible panel on Run Detail page.
  Groups AutoCheckbox components by phase: Phase 1 / Phase 2 / Phase 3.
  "Reset all to Auto" button resets all to checked.
```

---

## Claude Code Implementation Prompt

```
Read CLAUDE.md, then read CLAUDE_frontend.md in full.

Your goal: implement the Sailor frontend as a React 18 + Vite +
TypeScript + Tailwind CSS application.

Stack decisions (do not override):
  State:         Zustand + TanStack Query
  Table:         TanStack Virtual (react-virtual v3)
  Code editor:   CodeMirror 6 via @uiw/react-codemirror
  Router:        react-router-dom v6
  UI components: shadcn/ui (Tailwind-based)
  Charts:        Recharts
  URL state:     nuqs
  HTTP:          axios

Reference files:
  frontend_spec.md  ← full product specification (source of truth)
  CLAUDE_frontend.md ← architectural decisions + gap resolutions

---

IMPLEMENTATION ORDER:

Phase A — Foundation (do first, everything depends on this)

  Step A1. Project setup.
           → Vite + React + TypeScript template
           → Install all dependencies listed above
           → Install additional dependencies:
               zxcvbn            ← password strength meter (/register page)
               @codemirror/lang-c    ← C syntax highlighting (interrupt editors)
               react-dropzone    ← file drag-and-drop (interrupt file replace)
           → Configure Tailwind + shadcn/ui
           → Set up react-router-dom with all routes from §Top-Level Routes
               including: /register, /settings/users

  Step A2. Implement lib/types.ts in full.
           → All interfaces defined in CLAUDE_frontend.md TypeScript section
           → No placeholder types

  Step A3. Implement api/client.ts.
           → axios instance with baseURL from VITE_API_URL env var
           → Auth token injection: Authorization: Bearer <jwt>
             (from localStorage), on every request EXCEPT EventSource —
             see Gap 4 for SSE auth.
           → On every POST/PATCH/DELETE: inject
             `Idempotency-Key: <uuid-v4>` (generate one per logical
             intent; on user retry of the same intent, reuse the same
             key so the backend short-circuits).
           → 401 → redirect to /login
           → Non-2xx responses are typed as `ApiError`
             (from `shared/contracts/sailor.types`). Do not redefine.

  Step A4. Implement hooks/useSSE.ts.
           → Subscribes to SSE topics: runs.all, runs.{id}, etc.
           → Reconnect with exponential backoff (1s, 2s, 4s, max 30s)
           → On reconnect: fetch ?since={last_seq} to catch up
           → Applies JSON Merge Patch diffs to Zustand stores
           → Unsubscribes on unmount

  Step A5. Implement hooks/useSpecStore.ts and hooks/useRunStore.ts.
           → useSpecStore: Map<spec_id, Spec> with applyDiff() action
           → useRunStore: current Run + applyDiff() + control actions

---

Phase B — Core Views (implement in this order)

  Step B1. Dashboard (/).
           → RunTile component with progress bars (§2)
           → Cross-run metrics row
           → Runs table: sortable, filterable by status
           → Subscribes to runs.all SSE topic

  Step B2. New Run (/runs/new).
           → All form inputs from §1 (upload, config, budgets, etc.)
           → Zip upload with drag-and-drop
           → Validation: show needs_build_config state if autodetect fails
           → "Clone this run" pre-fills from existing run config

  Step B3. Run Detail — Header (/runs/:run_id).
           → Live progress bars per phase (§3a)
           → Pause / Resume / Cancel / Re-run failed controls
           → Subscribes to runs.{run_id} SSE topic

  Step B4. Spec Table (core of §3b).
           → TanStack Virtual — must handle 30K rows at 60fps
           → All columns: #, CWE, File, Func, Phase, Status, Last, Turn, Verdict
           → Row click → navigate to spec detail
           → Right-click context menu: re-queue, skip, copy spec JSON
           → Multi-select with checkboxes
           → Filter bar: phase, status, CWE, file glob, verdict, free-text
           → URL-encode filter state via nuqs
           → Saved filter presets
           → Subscribes to runs.{run_id}.specs SSE topic

  Step B5. Charts Strip (§3c).
           → Phase 2 outcomes stacked area chart (Recharts)
           → Turn distribution histogram
           → Compile error class breakdown
           → Token consumption rate

---

Phase C — Spec Detail (/runs/:run_id/specs/:i)

  Step C1. Spec Header (§4a).
           → Spec JSON pretty-printed, collapsible, copyable
           → Phase/status chips, current turn, elapsed time, token cost

  Step C2. Timeline (§4b).
           → Vertical event list, oldest at top
           → Each event: icon by kind, timestamp, summary
           → Click to expand: full LLM prompt/response, compiler stderr,
             KLEE output, ASan report
           → Lazy-load payloads (fetch on click, not on mount)
           → Subscribes to runs.{run_id}.specs.{spec_id} SSE topic

  Step C3. Artifact Tree (§4c).
           → File tree matching the directory structure in §4c
           → Click file → open in SourceViewer (CodeMirror read-only)
           → "Download" button per file
           → "Download all as tarball" button

  Step C4. Intervention Panel (§4d).
           → Only visible when: paused | errored | "Take control" clicked
           → Mode A: harness editor (CodeMirror C) + "Apply & resume" button
           → Mode B: force outcome selector + witness upload
           → Mode C: spec JSON editor + "Re-run from Phase 2" button
           → All modes: confirmation modal showing exact diff/effect
           → "Editing will consume 1 of your remaining N turns" warning

  Step C5. Interrupt system (spec §3).
           → InterruptPanel.tsx (base) + all 15 function-specific variants
               (see New Component Implementation Details above)
           → InterruptFileRow.tsx + FileValidationBanner.tsx
           → Interrupt notification: SSE event → toast → navigate.
             The interrupt event kind is NOT yet defined in
             shared/contracts/sailor.schema.json. Until the interrupt
             contract is added there, this UI is deferred — see the
             contracts README "What is NOT in this schema (yet)".
             Do not invent an `interrupt_created` event name; that
             string has no backend support.
           → PipelineControlsSidebar.tsx with AutoCheckbox per function
               (add to Run Detail page as collapsible panel)

---

Phase D — Supporting Views

  Step D1. Worker View (/runs/:run_id/workers) — §5.
           → Worker grid visualization (colored cells, hover tooltip)
           → Throughput metrics
           → Per-worker drill-down

  Step D2. Logs View (/runs/:run_id/logs) — §6.
           → Virtualized log list (must handle >100 lines/sec)
           → Filter: level, source, spec_id, worker, time range
           → Tail mode (auto-scroll) / Frozen mode
           → Subscribes to runs.{run_id}.specs.{spec_id}.logs SSE topic

  Step D3. Results Browser (/runs/:run_id → Results tab) — §7.
           → Confirmed vulnerabilities table (§7a)
           → Source viewer with gutter annotations (§7b)
           → Evidence package download (§7c)
           → Comparison view for same project, multiple runs (§7d)

  Step D4. Settings (/settings) — §8.
           → LLM providers (write-only keys, last-4 display)
           → Default budgets
           → Query suite catalog (enable/disable, upload .ql)
           → Notifications, retention, user roles

  Step D5. Phase-end downloads (spec §4).
           → PhaseDownloadButton.tsx + PhaseDownloadGroup.tsx
           → EvidencePackageButton.tsx
           → Add download buttons to Timeline event cards:
               Phase 1 completion → [↓ Download Phase 1 outputs]
               Phase 2 bug_triggered → [↓ Download .ktest witness]
               Phase 3 confirmed → [↓ Download Phase 3 outputs]
                                   [↓ Download evidence package]
           → Add "Download all Phase N" to Artifacts pane per phase.
           → "Export all confirmed bugs" button on Results tab.

---

Phase E — Auth, Error Handling, Polish

  Step E1. Authentication + Registration.
           → Login page (JWT or session)
           → Role-based rendering: hide intervention controls for viewer/operator
           → useAuth() hook with role check helpers
           → /register page (spec §2.2):
               Form: username, email, password, confirm, display_name
               Password strength meter (zxcvbn, block submit until "Good")
               On success: redirect to /login with "Account created" toast
               If response.role === "admin": show "You are the first user" banner
           → /settings/users page (spec §2.4):
               Admin-only guard (redirect to / if not admin)
               Table: username, email, role, registered, last_login, actions
               [Edit role] dropdown, [Disable], [Reset password], [Delete]
               Role change: optimistic update + revert on error

  Step E2. Error handling (§9).
           → Every API error maps to one of the error classes in §9
           → Red badge on spec row with error class name
           → Persistent banner for systemic errors
           → "Open in intervention panel" button when remediation is possible

  Step E3. Loading states.
           → Skeleton UI for every data-dependent component
           → Empty states
           → Stale indicator when SSE is disconnected

---

PERFORMANCE CONSTRAINTS (non-negotiable):
  - Spec table: 30K rows at 60fps. Use TanStack Virtual. No exceptions.
  - Timeline: lazy-load payloads on click. Never fetch all on mount.
  - Logs: virtualize. Never render >500 lines in DOM simultaneously.
  - Source viewer: CodeMirror handles 100K lines; enable progressive highlight.
  - Initial load: run detail interactive within 2s for 10K-spec run.
    Achieve this by: loading run metadata first, lazy-loading spec list.

OPEN QUESTIONS RESOLVED (do not re-open these):
  - Artifacts via API proxy (presigned URL), not direct S3.
  - Edit consumes 1 turn from T_max.
  - Source viewer: only files referenced by specs (MVP scope).
  - Comparison: exact match (file, func, line) for MVP.
  - Redaction: per-project flag, shows [REDACTED] in viewer.
  - Live KLEE: not in MVP.

After completing each Phase (A through E):
  → Run: npm run build (must succeed with zero TypeScript errors)
  → Run: npm run lint (zero ESLint errors)
  → Verify the completed phase in browser before moving on.
```
