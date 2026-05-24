# CLAUDE_sync_design_from_spec.md
# One-shot prompt: sync all design files to match current spec files.
#
# Trigger: "Read CLAUDE.md, then execute CLAUDE_sync_design_from_spec.md"
#
# Purpose:
#   spec/ files are the source of truth (what to build).
#   design/ files are implementation guides (how to build).
#   When spec/ changes, design/ must be updated to reflect it.
#   This prompt brings all design/ files up to date in one session.

---

## What Changed in spec/ (Summary for Claude Code)

Three spec files now define features that are missing from design/:

```
spec/interactive_control_spec.md   ← NEW (entire file)
  §2  User Registration & Role Management
  §3  Auto/Manual Mode + 15 per-function Interrupt Points
  §4  Phase-End Download
  §5  Backend API Additions (new endpoints)
  §6  Interrupt State Persistence (new DB table)

spec/frontend_spec.md              ← UPDATED
  §4d  Now references interactive_control_spec.md (no longer self-contained)
  §10  User registration added (/register route, first-user=admin rule)
  §13  New API endpoints referenced

spec/backend_spec.md               ← check for gaps against §5 of
                                     interactive_control_spec.md
```

Design files that need updating:

```
design/CLAUDE_backend.md    ← missing: auto_config, interrupt_points,
                               validate/file, register endpoints,
                               interrupt_points DB table, phase downloads
design/CLAUDE_frontend.md   ← missing: Auto checkbox components,
                               InterruptPanel per function,
                               file validation UI, register page,
                               phase download buttons
design/CLAUDE_Sessions_prompt.md  ← Session 9/10 steps need updating
```

---

## Step 0. Read all relevant files

```
Read in this order:
  1. CLAUDE.md                              (rules)
  2. spec/interactive_control_spec.md       (new features — full read)
  3. spec/frontend_spec.md §4d, §10, §13   (changed sections)
  4. spec/backend_spec.md                   (existing contracts)
  5. design/CLAUDE_backend.md               (current backend design)
  6. design/CLAUDE_frontend.md              (current frontend design)
  7. design/CLAUDE_Sessions_prompt.md       (current session steps)
```

Do NOT modify any file yet. After reading all files, proceed to Step 1.

---

## Step 1. Gap Analysis (report only, no changes)

For each design file, identify what is missing or outdated by comparing
against spec/interactive_control_spec.md.

Output a report in this format:

```
[MISSING] design/CLAUDE_backend.md
  - No auto_config endpoints (spec §5.1)
  - No interrupt_points table in DB schema (spec §6)
  - No /api/auth/register endpoint (spec §5.4)
  - No /api/validate/file endpoint (spec §5.3)
  - No phase-level download endpoints (spec §4.6)
  - No interrupt_points Celery task integration (spec §6)

[MISSING] design/CLAUDE_frontend.md
  - No AutoCheckbox component
  - No InterruptPanel component (15 variants)
  - No file validation UI (warning/error display)
  - No /register page
  - No phase-end download buttons on timeline
  - No VulnerabilitySpec selection panel (spec §3.10)
  - No LLM Disable Mode UI (spec §3.15)

[OUTDATED] design/CLAUDE_Sessions_prompt.md
  - Session 9 missing: interrupt endpoints, register endpoint,
    validate/file endpoint, interrupt_points table
  - Session 10 missing: AutoCheckbox, InterruptPanel, register page,
    download buttons
```

Wait for no confirmation needed — proceed immediately to Step 2.

---

## Step 2. Update `design/CLAUDE_backend.md`

Add the following sections. Insert each at the most logical location
in the existing file (after the section it extends).

### 2a. Add to Database Schema (Gap 2 section)

Add these tables to the existing table list:

```
interrupt_points    → interrupt state per function per spec (spec §6)
  interrupt_id      UUID PK
  run_id            FK → runs
  spec_id           FK → specs (nullable — Phase 1 interrupts are run-level)
  function_name     str  e.g. "phase2.klee_execution"
  phase             int  (1 | 2 | 3)
  turn              int  (nullable)
  status            enum "waiting" | "resumed" | "skipped"
  created_at        timestamp
  resumed_at        timestamp (nullable)
  modified_files    JSONB  [{name, artifact_path}]
  option_overrides  JSONB  {klee_timeout, asan_options, ...}

auto_config         → per-run Auto/Manual settings
  run_id            FK → runs (PK)
  config            JSONB  {"phase1.query_execution": true,
                            "phase2.klee_execution": false, ...}
  updated_at        timestamp
```

### 2b. Add to API Endpoints (Phase B section)

Add after existing B5:

```
B6. Auto/Manual mode (api/auto_config.py)
    → GET  /api/runs/:id/auto-config
         Returns per-function Auto flags.
    → PATCH /api/runs/:id/auto-config
         Body: {"phase2.klee_execution": false}
         Effect: takes effect at next occurrence.
         Requires: operator role.

B7. Interrupt panel state (api/interrupts.py)
    → GET  /api/runs/:id/interrupts
         Returns list of active interrupts (status="waiting").
    → GET  /api/runs/:id/interrupts/:interrupt_id
         Returns function name, input files (presigned URLs), status.
    → POST /api/runs/:id/interrupts/:interrupt_id/resume
         Body: {modified_files: [{name, content_base64}],
                option_overrides: {...}}
         Requires: intervener role.
    → POST /api/runs/:id/interrupts/:interrupt_id/skip
         Requires: intervener role.

B8. File validation (api/validate.py)
    → POST /api/validate/file
         Body: {filename: str, content_base64: str}
         Returns: {valid: bool, severity: "error"|"warning"|"info",
                   message: str, detected_format: str}
         Public endpoint — no auth required (stateless).

B9. User registration (api/auth.py — extend existing)
    → POST /api/auth/register
         Body: {username, email, password, display_name?}
         Returns: {user_id, username, role: "viewer"}
         Public. First user receives admin role.
    → GET  /api/users                  [admin]
    → POST /api/users/:id/role         [admin]
    → DELETE /api/users/:id            [admin]

B10. Phase-level downloads (api/phase_downloads.py)
    → GET /api/runs/:id/phase1/artifacts          (list)
    → GET /api/runs/:id/phase1/artifacts/:filename (presigned redirect)
    → GET /api/runs/:id/phase1/artifacts.tar.gz
    → GET /api/runs/:id/specs/:sid/phase2/artifacts
    → GET /api/runs/:id/specs/:sid/phase2/artifacts/:filename
    → GET /api/runs/:id/specs/:sid/phase2/artifacts.tar.gz
    → GET /api/runs/:id/specs/:sid/phase3/artifacts
    → GET /api/runs/:id/specs/:sid/phase3/artifacts/:filename
    → GET /api/runs/:id/specs/:sid/phase3/artifacts.tar.gz
    → GET /api/runs/:id/specs/:sid/evidence.tar.gz
    → GET /api/runs/:id/results/evidence-all.tar.gz
    All return HTTP 302 presigned redirect (300s TTL).
```

### 2c. Add to Celery Tasks (Phase D section)

Add interrupt check to phase2_task description:

```
Interrupt check in phase2_task:
  At every function boundary where auto_config[function] = false:
    1. Write interrupt_points row with status="waiting"
    2. Publish SSE event: {kind: "interrupt_created", ...}
    3. Pause task (poll interrupt_points every 5s)
    4. On status="resumed": apply modified_files + option_overrides
    5. On status="skipped": use default outputs, continue
    6. On run cancel: set status="skipped", continue teardown

  Function boundaries that support interrupt:
    Phase 1: db_build, query_execution, sarif_parsing,
             fact_enrichment, spec_generation
    Phase 2: source_exploration, spec_selection, driver_synthesis,
             stub_synthesis, compile_diagnose, klee_execution,
             harness_refinement
    Phase 3: replay_driver_gen, asan_compilation, result_classification
```

### 2d. Add to File Validation Service

```
New service: services/validation_service.py

ValidatorService.validate(filename, content_bytes) -> ValidationResult:

  Dispatch by file type:
    *.sarif, *.json with "runs" key → SARIFValidator
    findings.json                   → FindingsValidator
    fact_packs.json                 → FactPacksValidator
    specifications.json / spec.json → SpecValidator
    *.c                             → CSourceValidator (clang --syntax-only)
    *.ql                            → CodeQLValidator (codeql query compile)
    *.ktest                         → KTestValidator (magic bytes check)
    *.bc                            → BitcodeValidator (magic bytes check)

  SARIFValidator rules (from spec §3.19):
    ERROR:   not valid JSON
    ERROR:   missing "runs" array
    WARNING: results count = 0
    WARNING: type mismatch (e.g. PDF magic bytes in .sarif file)
             → detected_format = "pdf" | "elf" | "zip" | "unknown"

  CSourceValidator rules:
    Run inside container: clang --syntax-only -x c <file>
    ERROR:   compile errors present
    WARNING: klee_* symbols in replay_driver.c context

  Returns:
    ValidationResult(valid, severity, message, detected_format)
```

### 2e. Add to Constraints section

```
8. Auto/Manual mode must not be enforced inside sailor/ pipeline code.
   sailor/ always runs to completion when called.
   Interrupt logic lives entirely in backend Celery tasks.
   sailor/ pipeline code has no knowledge of interrupt_points.

9. File validation runs server-side only.
   The /api/validate/file endpoint is the single validation point.
   Frontend never validates file structure locally.

10. Phase-level downloads return presigned redirects (HTTP 302).
    Never stream artifact bytes through the FastAPI process.
    Always redirect to MinIO/S3 presigned URLs (300s TTL).
```

---

## Step 3. Update `design/CLAUDE_frontend.md`

Add the following sections and components.

### 3a. Add to Component Architecture

Add to the components/ list:

```
├── components/
│   ├── ...existing components...
│   │
│   ├── AutoCheckbox.tsx          ← Auto/Manual toggle per pipeline function
│   ├── PipelineControlsSidebar.tsx ← collapsible sidebar with all Auto checkboxes
│   │
│   ├── interrupt/
│   │   ├── InterruptPanel.tsx         ← base panel (common elements)
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
│   │   │   ├── SpecSelectorInterrupt.tsx    ← §3.10 (checklist + cost)
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
│   ├── downloads/
│   │   ├── PhaseDownloadButton.tsx    ← single file download (presigned)
│   │   ├── PhaseDownloadGroup.tsx     ← "Download all Phase N outputs"
│   │   └── EvidencePackageButton.tsx  ← cross-phase evidence tarball
```

### 3b. Add to Pages

Add to the pages/ list:

```
├── pages/
│   ├── ...existing pages...
│   ├── Register.tsx          ← /register  (spec §2.2)
│   └── UserManagement.tsx    ← /settings/users  (spec §2.4, admin only)
```

### 3c. Add Implementation Details for New Components

```
AutoCheckbox.tsx
  Props: functionName, runId, defaultChecked
  On toggle: PATCH /api/runs/:runId/auto-config {[functionName]: checked}
  Optimistic update: update local state, revert on API error.

InterruptPanel.tsx (base)
  Triggered by SSE event: {kind: "interrupt_created", interrupt_id}
  Displays as full-screen overlay (desktop) or bottom drawer (mobile).
  Common elements per spec §3.3:
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
  [Replace]: file input → upload → POST /api/validate/file first
             Show FileValidationBanner with result before confirming

FileValidationBanner.tsx
  Props: severity ("error"|"warning"|"info"), message, detectedFormat
  ERROR:   red, blocks Resume button
  WARNING: yellow, Resume allowed with "Proceed anyway" confirmation
  INFO:    blue, informational only

QuerySelectorInterrupt.tsx (spec §3.5)
  Renders scrollable checklist of all 34 queries.
  Each row: [☑] query_id | CWE | [▼ expand]
  Expand: CodeMirror read-only viewer of .ql content
  Edit button: switches to CodeMirror editable mode
  Edited queries sent as modified_files in resume payload.
  Validation: POST /api/validate/file for each modified .ql

SpecSelectorInterrupt.tsx (spec §3.10)
  Renders scrollable checklist of all VulnerabilitySpecs.
  Each row: [☑] CWE · file:line | function | [▼ expand]
  Expand: CodeMirror JSON viewer of spec content
  Edit button: editable CodeMirror JSON, validated on change
  Cost estimate: updates live as checkboxes toggled
    formula: selectedCount × AVG_TOKENS_PER_SPEC × providerPrice

ManualHarnessEditor.tsx (spec §3.15)
  Three-tab CodeMirror editor: [driver.c] [slice.c] [assertions.c]
  "Submit manual harness" → validates all three compile, then resume
  "Re-enable LLM" → PATCH auto-config to restore LLM for this spec

PhaseDownloadButton.tsx
  Props: runId, specId?, phase, filename, label
  On click: GET /api/runs/:id/phase<N>/artifacts/:filename
            → follows 302 redirect → browser download
  Shows spinner while redirect resolves.

PhaseDownloadGroup.tsx
  Renders a collapsible section per phase in the Artifacts pane.
  "Download all Phase N outputs" → .tar.gz endpoint
  Individual file rows: filename, size, [↓] button
```

### 3d. Add to Phase A — Foundation

Add to Step A1:

```
Install additional dependencies:
  zxcvbn            ← password strength meter
  @codemirror/lang-json  ← JSON syntax highlighting (already via @uiw/react-codemirror)
  @codemirror/lang-c    ← C syntax highlighting
  react-dropzone    ← file upload drag-and-drop (already likely present)
```

### 3e. Add to Phase E — Auth, Error Handling, Polish

Add to Step E1:

```
E1 additions:
  → /register page (spec §2.2):
      Form: username, email, password, confirm, display_name
      Password strength meter (zxcvbn, block submit until "Good")
      On success: redirect to /login with "Account created" toast
      First-user flow: if response.role === "admin", show
        "You are the first user and have admin access." banner

  → /settings/users page (spec §2.4):
      Admin-only guard (redirect to / if not admin)
      Table: username, email, role, registered, last_login, actions
      [Edit role] dropdown, [Disable], [Reset password], [Delete]
      Role change optimistic update + revert on error

  → PipelineControlsSidebar:
      Collapsible panel on Run Detail page
      Groups checkboxes by phase: Phase 1 / Phase 2 / Phase 3
      Each checkbox calls AutoCheckbox.tsx
      "Reset all to Auto" button
```

### 3f. Add Interrupt Notification System

```
When an interrupt fires on a spec the user is NOT currently viewing:
  → Toast notification (bottom-right):
       "⏸ Spec elfxx-x86.c:2699 paused at Phase 2 · KLEE Execution"
       [Go to spec →]
  → Clicking navigates to spec detail, InterruptPanel opens automatically

When user IS on the interrupted spec's detail page:
  → InterruptPanel opens as overlay immediately (no toast needed)

SSE subscription for interrupt notifications:
  Topic: runs.{run_id}  (already subscribed on Run Detail page)
  Event kind: "interrupt_created"
  Payload: {interrupt_id, spec_id, function_name, phase}
```

---

## Step 4. Update `design/CLAUDE_Sessions_prompt.md`

### 4a. Update Session 9 (Backend) — add new steps

Find Session 9 Step 3 (Phase A) and add:

```
  A2 addition — add to Database models:
      → interrupt_points table (spec §6)
      → auto_config table (spec §5.1)
      → Add to Alembic migration

  A5 addition — extend auth:
      → POST /api/auth/register (public, first-user=admin rule)
      → Verify: first registration gets admin, second gets viewer
```

Find Session 9 Step 4 (Phase B) and add:

```
  After B5, implement:
  B6. Auto/Manual config endpoints (api/auto_config.py)
  B7. Interrupt panel endpoints (api/interrupts.py)
      → Interrupt pause/resume polling logic in Celery tasks
      → SSE event: interrupt_created published on pause
  B8. File validation endpoint (api/validate.py + services/validation_service.py)
      → ValidatorService with all file type validators
      → CSourceValidator runs clang inside DockerRunner
  B9. User management endpoints (extend api/auth.py)
  B10. Phase-level download endpoints (api/phase_downloads.py)
```

Find Session 9 Step 6 (Phase D) and add:

```
  D2 addition — phase2_task interrupt logic:
      → At each function boundary: check auto_config
      → If false: write interrupt_points row, publish SSE, poll
      → On resume: apply modified_files + option_overrides
      → Apply same pattern to phase1_task and phase3_task
```

Find Session 9 Step 8 (tests) and add:

```
  Additional tests:
  → pytest backend/tests/test_interrupts.py
     Test: interrupt created, resume with modified file, skip
     Test: file validation rejects PDF-as-SARIF
     Test: first-user registration gets admin role
  → pytest backend/tests/test_phase_downloads.py
     Test: presigned redirect for each phase artifact type
```

### 4b. Update Session 10 (Frontend) — add new steps

Find Session 10 Step 3 (Phase A) and add to A1:

```
  A1 addition:
    → Install: zxcvbn
    → Configure routes: /register, /settings/users
```

Find Session 10 Step 5 (Phase C) and add:

```
  After C4, implement:
  C5. Interrupt system:
      → InterruptPanel.tsx (base) + all 15 function-specific variants
          (see design/CLAUDE_frontend.md interrupt/ component list)
      → InterruptFileRow.tsx + FileValidationBanner.tsx
      → Interrupt notification: SSE event → toast → navigate
      → PipelineControlsSidebar.tsx with AutoCheckbox per function
```

Find Session 10 Step 6 (Phase D) and add:

```
  After D4, implement:
  D5. Phase-end downloads:
      → PhaseDownloadButton.tsx + PhaseDownloadGroup.tsx
      → EvidencePackageButton.tsx
      → Add download buttons to timeline event cards (Phase 1/2/3 completion)
      → Add "Download all Phase N" to Artifacts pane
```

Find Session 10 Step 7 (Phase E) and add:

```
  E1 addition:
      → /register page (password strength meter, first-user banner)
      → /settings/users page (admin only, role management table)
```

---

## Step 5. Verify Consistency (Sync Check)

After making all changes in Steps 2–4, run this verification:

```
For each new feature in spec/interactive_control_spec.md:

  §2  User Registration
      □ CLAUDE_backend.md: POST /api/auth/register documented
      □ CLAUDE_backend.md: first-user=admin rule documented
      □ CLAUDE_frontend.md: /register page component listed
      □ CLAUDE_frontend.md: /settings/users component listed
      □ Session 9: registration endpoint in implementation steps
      □ Session 10: register page in implementation steps

  §3  Auto/Manual + Interrupts
      □ CLAUDE_backend.md: interrupt_points table documented
      □ CLAUDE_backend.md: auto_config table documented
      □ CLAUDE_backend.md: /api/runs/:id/auto-config endpoints documented
      □ CLAUDE_backend.md: /api/runs/:id/interrupts/* endpoints documented
      □ CLAUDE_backend.md: interrupt check in phase2_task documented
      □ CLAUDE_frontend.md: AutoCheckbox component listed
      □ CLAUDE_frontend.md: all 15 InterruptPanel variants listed
      □ CLAUDE_frontend.md: interrupt notification system documented
      □ Session 9: interrupt endpoints in Phase B steps
      □ Session 10: interrupt components in Phase C steps

  §3.5  Query Selector
      □ CLAUDE_frontend.md: QuerySelectorInterrupt.tsx listed
      □ CLAUDE_frontend.md: .ql edit + validation described

  §3.10  VulnerabilitySpec Selector
      □ CLAUDE_frontend.md: SpecSelectorInterrupt.tsx with cost estimate

  §3.15  LLM Disable Mode
      □ CLAUDE_frontend.md: ManualHarnessEditor.tsx described

  §3.19  File Validation
      □ CLAUDE_backend.md: validation_service.py with all validators
      □ CLAUDE_backend.md: /api/validate/file endpoint
      □ CLAUDE_frontend.md: FileValidationBanner component

  §4    Phase Downloads
      □ CLAUDE_backend.md: all 10 phase download endpoints
      □ CLAUDE_backend.md: presigned redirect constraint documented
      □ CLAUDE_frontend.md: PhaseDownloadButton/Group/Evidence components
      □ CLAUDE_frontend.md: download buttons on timeline event cards
      □ Session 9: download endpoints in Phase B steps
      □ Session 10: download components in Phase D steps
```

Report any unchecked items as:
```
[MISSING] <file>: <item> — not added
```

---

## Step 6. Run Standard Last Step

Append to CLAUDE_feedback.md per the Standard Last Step defined in
design/CLAUDE_Sessions_prompt.md.
