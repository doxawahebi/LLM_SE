# spec/interactive_control_spec.md
# Sailor — Interactive Control, User Registration & Download Specification
#
# Cross-reference:
#   spec/frontend_spec.md     ← base UI spec (this file extends it)
#   spec/backend_spec.md      ← API contracts
#   paper/paper_phase1.md     ← Phase 1 algorithm
#   paper/paper_phase2.md     ← Phase 2 algorithm (Algorithm 1)
#   paper/paper_phase3.md     ← Phase 3 algorithm

---

## 1. Scope

This document specifies three features added on top of `frontend_spec.md`:

```
§2  User Registration & Role Management
§3  Auto/Manual Mode + Per-Function Interrupt System
§4  Phase-End Download
```

Where this document conflicts with `frontend_spec.md`, this document
takes precedence for the features described here.

---

## 2. User Registration & Role Management

### 2.1 Registration Flow

```
Public endpoint:  POST /api/auth/register
                  (accessible without authentication)

Fields:
  username        string, 3–32 chars, alphanumeric + underscore
  email           valid email address
  password        min 12 chars, at least 1 uppercase + 1 digit + 1 symbol
  display_name    optional free-text label

On success:
  → Account created with role = "viewer" (least-privilege default)
  → Confirmation email sent (if email service configured)
  → Redirect to /login

On failure:
  → 400 with field-level errors (username taken, weak password, etc.)
  → Never reveal whether an email already exists (anti-enumeration)
```

### 2.2 Registration UI (`/register`)

```
┌──────────────────────────────────────────┐
│  Create a Sailor account                 │
│                                          │
│  Username       [________________]       │
│  Email          [________________]       │
│  Password       [________________]       │
│  Confirm        [________________]       │
│  Display name   [________________]       │
│                                          │
│  Password strength: ████████░░  Good     │
│                                          │
│  [ Create account ]                      │
│                                          │
│  Already have an account? Sign in →      │
└──────────────────────────────────────────┘
```

Password strength meter:
- Shows bar + label (Weak / Fair / Good / Strong)
- Blocks submission until strength ≥ "Good"
- Powered by zxcvbn or equivalent client-side library

Email confirmation:
- If SMTP is configured: user receives a link, must click before login
- If SMTP is not configured (dev mode): account is immediately active

### 2.3 Roles

Inherited from `frontend_spec.md §10`, extended here:

| Role       | Registration | Run | Intervene | Settings | Admin |
|------------|-------------|-----|-----------|----------|-------|
| viewer     | self-register | read | —       | —        | —     |
| operator   | admin grants  | start/cancel | — | —   | —     |
| intervener | admin grants  | start/cancel | ✓ | —  | —     |
| admin      | first user or admin grants | ✓ | ✓ | ✓ | ✓ |

First registered user automatically receives `admin` role.
All subsequent registrations default to `viewer`.
Admins promote users at `/settings/users`.

### 2.4 User Management UI (`/settings/users`)

Admin-only. Tabular list of all users:

```
Columns: username, email, role, registered, last login, actions
Actions: [Edit role ▼]  [Disable]  [Reset password]  [Delete]
```

Role change takes effect on next request (JWT invalidated on downgrade).

---

## 3. Auto/Manual Mode + Per-Function Interrupt System

### 3.1 Core Concept

Every pipeline function that can be interrupted has an **Auto checkbox**.

```
Auto = ON  (default):
  Function runs automatically without user interaction.
  This is the standard Sailor pipeline behavior.

Auto = OFF:
  Pipeline pauses before the function executes.
  User sees an Interrupt Panel for that function.
  User inspects/modifies inputs, then clicks "Resume" to proceed.
  Pipeline stays paused until Resume is clicked or Auto is re-enabled.
```

Auto state is **per-run-config** (set when creating or editing a run)
and **per-function** (each function has its own checkbox).

Auto state can also be toggled live on the Run Detail page while a run
is active. Changes take effect at the next occurrence of that function.

### 3.2 Auto Checkbox Placement

Auto checkboxes appear in two places:

**A. Run Configuration (`/runs/new` and "Edit run config")**

```
Phase 1
  ☑ Auto  CodeQL DB Build
  ☑ Auto  Query Execution
  ☑ Auto  SARIF Parsing
  ☑ Auto  Fact Enrichment
  ☑ Auto  Spec Generation

Phase 2 (per-spec; applies to all specs in the run)
  ☑ Auto  Source Exploration
  ☑ Auto  Driver Synthesis
  ☑ Auto  Stub Synthesis
  ☑ Auto  Assertion Instantiation
  ☑ Auto  Compile & Diagnose
  ☑ Auto  KLEE Execution
  ☑ Auto  Harness Refinement
  ☑ Auto  LLM Generation  [Disable LLM →]

Phase 3 (per-spec)
  ☑ Auto  Replay Driver Generation
  ☑ Auto  ASan Compilation
  ☑ Auto  Concrete Execution
  ☑ Auto  Result Classification
```

**B. Run Detail page (`/runs/:run_id`)**

Compact version in a collapsible sidebar panel titled "Pipeline Controls".
Same checkboxes, same effect. Live toggle.

### 3.3 Interrupt Panel

When Auto = OFF and pipeline reaches that function, a full-screen
overlay (or side drawer) appears for that function.

Common elements in every Interrupt Panel:

```
┌─────────────────────────────────────────────────────────────────┐
│  ⏸  Interrupted: <Function Name>                                │
│  Spec: <spec_id>  |  Phase: <N>  |  Turn: <t>/<T_max>          │
├─────────────────────────────────────────────────────────────────┤
│  INPUT FILES                  [Validate] [Replace file ↑]       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  📄 <filename>   <size>   <type>   [View] [Edit] [Replace] │  │
│  │  📄 ...                                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  <Function-specific controls — see §3.4 through §3.15>          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  [  Resume with current inputs  ]    [  Skip this function  ]   │
│  [ ☑ Auto (re-enable for future) ]                              │
└─────────────────────────────────────────────────────────────────┘
```

**File replacement rules:**

- Any input file can be replaced by uploading a new file.
- On replacement, the server runs structural validation before accepting.
- If validation fails, a warning banner appears (see §3.16).
- Non-binary files (JSON, C, SARIF, QL) can be viewed and edited inline.
- Binary files (.ktest, .bc) are view-only with a hex dump option.

### 3.4 Phase 1 — CodeQL DB Build Interrupt

```
Interrupt point: before codeql database create is invoked.

Inputs shown:
  build_command   (editable text field)
  project_root    (read-only path)

Controls:
  Build command   [_____________________________]
  CodeQL DB path  [_____________________________]
  ☑ Use existing DB  [Browse...]

User can:
  - Edit the build command before execution.
  - Point to an existing pre-built CodeQL DB to skip the build step.
    (Useful when the user already has a DB from a previous run.)

Validation on Resume:
  - If "Use existing DB": verify the path contains a valid QL DB
    (check for db-cpp/ or similar marker directory).
  - If build command is empty and no existing DB: block Resume,
    show error "Build command required."
```

### 3.5 Phase 1 — Query Execution Interrupt (Query Selector)

```
Interrupt point: before codeql database analyze is invoked.

This is the CodeQL Query Selector. It shows all 34 queries in a
scrollable checklist. The user selects which queries to run.

┌─────────────────────────────────────────────────────────────────┐
│  Select CodeQL Queries to Execute                               │
│  ☑ Select all   ☐ Deselect all   [Search queries...]           │
├──────┬──────────────────────────────────────┬──────────┬───────┤
│  ☑   │  local/cpp/cwe-120-overflow           │  CWE-120 │  [▼]  │
│  ☑   │  local/cpp/cwe-122-heap-overflow      │  CWE-122 │  [▼]  │
│  ☑   │  local/cpp/cwe-416-uaf               │  CWE-416 │  [▼]  │
│  ☐   │  local/cpp/cwe-674-recursion         │  CWE-674 │  [▼]  │
│  ...  (scrollable, all 34 queries listed)                       │
├─────────────────────────────────────────────────────────────────┤
│  Enabled: 33 / 34   Estimated runtime: ~8 min                   │
└─────────────────────────────────────────────────────────────────┘

[▼] expand row → shows full query source (.ql content) in a
    syntax-highlighted, read-only CodeMirror panel.
    "Edit" button opens the query in an editable CodeMirror panel.
    User can modify query content before execution.
    Modified query is used only for this run (not saved globally).

Validation on Resume:
  - At least 1 query must be selected.
  - Any modified query must be valid QL syntax
    (server-side: codeql query compile --check-only).
```

### 3.6 Phase 1 — SARIF Parsing Interrupt

```
Interrupt point: after codeql analyze returns, before _parse_sarif().

Input shown:
  findings.sarif   (raw SARIF output from CodeQL)

Controls:
  [View SARIF]     opens JSON viewer (collapsible tree, searchable)
  [Replace SARIF]  upload a custom SARIF file instead
  Summary:
    Runs: <N>    Total findings: <M>

Validation on Resume (applied to whichever SARIF is active):
  - Must be valid JSON.
  - Must contain "runs" array (SARIF 2.1.0 schema).
  - "results" array must be present (may be empty).
  - Each result must have "locations[0].physicalLocation.artifactLocation.uri"
    and "locations[0].physicalLocation.region.startLine".
  Warning (non-blocking) if findings count = 0.
```

### 3.7 Phase 1 — Fact Enrichment Interrupt

```
Interrupt point: before FactEnricher.enrich() is called for each finding.

Input shown:
  findings.json   (parsed SARIFFinding list — editable JSON)

Controls:
  [View / Edit findings.json]   CodeMirror JSON editor
  [Replace findings.json]       upload replacement

User can:
  - Remove specific findings (delete entries from the JSON array).
  - Edit finding fields (description, location, trace).
  - Add findings manually.

Validation on Resume:
  - Must be valid JSON array.
  - Each element must have: finding_id, rule_id, cwe, location.file,
    location.line, description (schema from design/CLAUDE_phase1.md).
  Warning if any finding has an empty suspect_calls after enrichment
  (non-blocking).
```

### 3.8 Phase 1 — Spec Generation Interrupt

```
Interrupt point: after FactEnricher runs, before SpecificationGenerator.

Input shown:
  fact_packs.json   (FactPack list — editable JSON)

Controls:
  [View / Edit fact_packs.json]   CodeMirror JSON editor
  Filter preview:
    "X of Y fact packs will pass the current filter rules."
    [View skip patterns]  [Edit skip patterns]

User can:
  - Edit any FactPack field (suspect_calls, bounds_hints, etc.).
  - Override the FILE_SKIP_PATTERNS and FUNCTION_SKIP_PATTERNS
    for this run (changes shown as a diff from defaults).

Validation on Resume:
  - fact_packs.json must be valid JSON array.
  - Each FactPack must have: finding.rule_id, finding.location,
    build_context.include_paths.
```

### 3.9 Phase 2 — Source Exploration Interrupt

```
Interrupt point: before LLMOrchestrator enters the exploration phase
                 (t < T_explore).

Input shown:
  spec.json   (VulnerabilitySpec — editable JSON)

Controls:
  [View / Edit spec.json]   CodeMirror JSON editor
  Turn budget:
    T_explore [___]   T_author [___]   T_max [___]   R_max [___]
    (editable; changes apply to this spec only)

User can:
  - Edit entrypoint, assertion_template, suspect_calls, bounds_hints.
  - Adjust T_explore budget before exploration starts.

Validation on Resume:
  - spec.json must satisfy VulnerabilitySpec schema.
  - assertion_template must be non-empty.
  - T_explore + T_author ≤ T_max.
```

### 3.10 Phase 2 — VulnerabilitySpec Selection Panel

```
Interrupt point: after Phase 1 completes, before Phase 2 dispatch begins.
This panel applies at the Run level (not per-spec).

A scrollable checklist of all VulnerabilitySpecs from Phase 1.

┌─────────────────────────────────────────────────────────────────┐
│  Select VulnerabilitySpecs to process in Phase 2                │
│  ☑ Select all   ☐ Deselect all   [Filter...]                   │
├──────┬──────────────────────────────────────┬──────────┬───────┤
│  ☑   │  CWE-120 · elfxx-x86.c:2699          │  memcpy  │  [▼]  │
│  ☑   │  CWE-416 · bfd.c:1140                │  free    │  [▼]  │
│  ☐   │  CWE-476 · dwarf2.c:889              │  deref   │  [▼]  │
│  ... (scrollable, all N specs)                                  │
├─────────────────────────────────────────────────────────────────┤
│  Selected: 1,258 / 1,260   Est. cost: ~$12.40 (Gemini Flash)   │
└─────────────────────────────────────────────────────────────────┘

[▼] expand row → shows full VulnerabilitySpec JSON in a
    syntax-highlighted panel.
    [Edit] opens the spec in an editable CodeMirror JSON panel.
    Edits apply only to this run.

Estimated cost display:
  Based on avg 5K tokens/spec × price per 1M tokens of active provider.
  Updates live as checkboxes are toggled.

Validation on Resume:
  - At least 1 spec must be selected.
  - Any edited spec must satisfy VulnerabilitySpec schema.
```

### 3.11 Phase 2 — Driver Synthesis Interrupt

```
Interrupt point: after LLM produces the initial driver draft
                 (first time driver.c is written).

Input shown:
  driver.c   (LLM-generated; editable)
  spec.json  (read-only reference)

Controls:
  [View / Edit driver.c]   CodeMirror C editor (full syntax highlighting)
  [Replace driver.c]       upload a handwritten driver

User can:
  - Edit the driver before it is compiled.
  - Replace with a fully custom driver (bypasses LLM for this turn).

Validation on Resume:
  - driver.c must compile without errors in the container:
      clang -O0 -g -emit-llvm -c <include_flags> driver.c
    Server runs this check; shows clang stderr if it fails.
    User can fix and retry validation inline without leaving the panel.
```

### 3.12 Phase 2 — Stub Synthesis Interrupt

```
Interrupt point: after StubSynthesizer produces the code slice draft.

Input shown:
  slice.c    (LLM-generated; editable)
  stubs list (summary of which functions were stubbed, at what granularity)

Controls:
  [View / Edit slice.c]    CodeMirror C editor
  Stub summary table:
    Function          Granularity    Return value
    bfd_get_32()      function       symbolic
    bfd_put_32()      function       0
    ...

User can:
  - Edit slice.c directly.
  - Change stub return type from "symbolic" to "concrete value" inline.

CWE-416 enforcement warning:
  If any free() call is present and its stub does NOT call real free(),
  a red warning banner appears:
    "⚠ free() stub must call real free() for CWE-416 (paper §4.2).
     Fix before resuming."
  This warning blocks Resume until resolved.

Validation on Resume:
  - slice.c must compile (same check as §3.11).
```

### 3.13 Phase 2 — Compile & Diagnose Interrupt

```
Interrupt point: every time CompileDiagnose(H, P) returns a failure.

Input shown:
  Compiler output (clang/llvm-link stderr)
  Error class badge: incomplete_type | conflicting_proto | redefinition | other
  Suggested fix (auto-generated by CompileDiagnoser)
  Relevant source snippet (if found)

Controls:
  [Apply suggested fix]    one-click applies the auto-fix to the affected file
  [View / Edit driver.c]   CodeMirror C
  [View / Edit slice.c]    CodeMirror C
  [View / Edit stubs.c]    CodeMirror C

User can:
  - Apply the auto-fix as-is.
  - Edit any harness file manually.
  - Combine: apply fix, then manually adjust.

Validation on Resume:
  - Re-runs clang compilation check before accepting.
  - If still failing: shows error inline; user must fix before Resume.
```

### 3.14 Phase 2 — KLEE Execution Interrupt

```
Interrupt point: before each klee invocation (every turn ≥ T_author).

Input shown:
  harness.bc   (linked bitcode; binary — hex dump only)
  KLEE options currently configured:
    search strategy, timeout, depth limit

Controls:
  KLEE options:
    Search strategy  [random-path ▼] + [dfs ▼]  (multi-select)
    Timeout          [300] s
    Depth limit      [1000]
  [View last KLEE output]   (if any previous run exists)
  Coverage probes summary:
    Entered: [func1, func2]    Missed: [func3]

User can:
  - Adjust KLEE options before this run.
  - View previous KLEE output for diagnostic context.
  Note: harness.bc itself cannot be edited here (it's binary).
        To change harness: use §3.11 / §3.12 interrupt first.

Validation on Resume:
  - Timeout must be > 0 and ≤ 3600s.
  - At least 1 search strategy selected.
```

### 3.15 Phase 2 — LLM Disable Mode (Manual Harness Generation)

```
Available when:
  The "Disable LLM" button is pressed (distinct from Auto checkbox).
  This disables LLM generation entirely for this spec.

Effect:
  Turn counter still increments.
  At each turn where LLM would normally act, pipeline pauses instead.
  User manually writes/edits driver.c, slice.c, assertions.c.
  Then clicks "Submit manual harness" to proceed to compile + KLEE.

UI:
  Interrupt Panel shows a manual editor with three tabs:
    [driver.c]  [slice.c]  [assertions.c]
  Each tab is a full CodeMirror C editor.
  "Submit manual harness" = equivalent to "Resume" in auto mode.

This mode is intended for expert users who want full control over
harness construction without LLM assistance.

Re-enable LLM:
  "Re-enable LLM" button restores auto generation for subsequent turns.
  Previously submitted manual files are kept as the starting point.

Validation on Submit:
  - All three files must compile (same as §3.11).
```

### 3.16 Phase 3 — Replay Driver Generation Interrupt

```
Interrupt point: after ReplayDriverGenerator produces replay_driver.c.

Input shown:
  replay_driver.c   (editable)
  witness_values:   (from .ktest — shown as human-readable table)
    Variable      Type      Value (interpreted)
    copy_size     size_t    17
    dst_bytes     u8[16]    0x00 × 16
    src_bytes     u8[512]   0x00 × 512

Controls:
  [View / Edit replay_driver.c]   CodeMirror C editor

Critical validation (blocking):
  - klee_make_symbolic, klee_assume, klee_assert, klee_warning_once
    must NOT appear in replay_driver.c.
  - Regular assignments (e.g., ndo->ndo_vflag = 3) must be present.
  If the validator finds klee_* calls: red error with exact line numbers.
  Resume blocked until fixed.

Validation on Resume:
  - replay_driver.c must compile with clang -fsanitize=address.
```

### 3.17 Phase 3 — ASan Compilation Interrupt

```
Interrupt point: before the project is recompiled with -fsanitize=address.

Input shown:
  ASan build command (derived from run config)
  ASAN_OPTIONS (editable)

Controls:
  ASan build command  [___________________________________]
  ASAN_OPTIONS        [halt_on_error=1:print_stacktrace=1]
  ☑ Confirm unmodified project source is used
    (checked by server: no LLM-generated files in compilation)

User can:
  - Adjust ASan build flags.
  - Set ASAN_OPTIONS.

Critical validation (blocking):
  - The compilation must NOT include any LLM-generated stub files.
  - Server checks that only project source files from the repository
    are in the compile command.
  If a stub file is detected: red error.
  Resume blocked until fixed.
```

### 3.18 Phase 3 — Result Classification Interrupt

```
Interrupt point: after ConcreteExecutor returns the ASan output,
                 before ResultClassifier assigns verdict.

Input shown:
  ASan output (full stderr — read-only, syntax-highlighted)
  Stack trace parsed by ResultClassifier:
    Frame  File               Function    Project source?
    #0     elfxx-x86.c:2286   _bfd_...    ✅ YES
    #1     replay_driver.c    main        ❌ NO (harness)

Controls:
  Proposed verdict:  [CONFIRMED ▼]  (editable dropdown)
    Options: CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE
  Reason (optional free text):  [_____________________________]
  Override CWE:  [CWE-122 ▼]

User can:
  - Accept the auto-classified verdict.
  - Override the verdict manually with a reason.
  - Override the CWE refinement.

Validation on Resume:
  - A verdict must be selected.
  - If verdict = CONFIRMED but no project source frame in stack trace:
    yellow warning (non-blocking):
    "No project source frame detected. Confirm override intentional."
```

### 3.19 Input File Validation & Warning System

Applies across ALL interrupt panels when a file is replaced or edited.

```
Structural validation rules by file type:

  *.sarif / *.json with "runs" key:
    → Must be valid JSON
    → Must match SARIF 2.1.0 schema ("$schema" key or "runs" array)
    → Warning if type mismatch: "Expected SARIF structure but got
      { detected_format }. Proceeding may cause parser errors."

  findings.json:
    → Must be JSON array of SARIFFinding objects
    → Each element: finding_id, rule_id, cwe, location.file,
      location.line, description

  fact_packs.json:
    → Must be JSON array of FactPack objects
    → Each element: finding (nested SARIFFinding), build_context

  specifications.json / spec.json:
    → Must satisfy VulnerabilitySpec schema
    → assertion_template must be non-empty
    → entrypoint must be non-empty string

  *.c (driver, slice, stubs, replay_driver):
    → Must be valid UTF-8 text
    → Server-side: clang --syntax-only check
    → Warning if klee_* symbols appear in replay_driver.c

  *.ql:
    → Server-side: codeql query compile --check-only
    → Warning if query produces no results on the current DB

  *.ktest:
    → Must be binary file starting with "KTEST" magic bytes
    → Warning if file is empty

  *.bc (LLVM bitcode):
    → Must start with "BC" magic bytes (0x42 0x43)
    → View-only; cannot be replaced in interrupt panel

Warning severity levels:
  ERROR   (red, blocks Resume):
    Structural validation failed. File will cause pipeline failure.
  WARNING (yellow, non-blocking):
    File is valid but may produce unexpected results.
  INFO    (blue, non-blocking):
    File replaced successfully. Original archived.

Archive behavior:
  When a file is replaced, the original is archived at:
    <artifact_path>.replaced.<timestamp>.<original_extension>
  This ensures the original is always recoverable.
```

---

## 4. Phase-End Download

Downloads are available at two moments:
- **After a phase completes** (phase status = completed or confirmed).
- **At an Interrupt Panel** when Auto = OFF (before the phase runs or
  after the phase has generated the file but before the next step).

### 4.1 Download UI Placement

**A. Timeline event cards** (§4b of `frontend_spec.md`):
Each phase completion event has a download button inline:

```
✓ 14:02:11   Phase 1 complete — 1,260 specs
              [↓ Download Phase 1 outputs]

⚑ 14:09:42   Turn 24: bug_triggered
              [↓ Download .ktest witness]

✓ 14:11:23   CONFIRMED: heap-buffer-overflow
              [↓ Download Phase 3 outputs]  [↓ Download evidence package]
```

**B. Artifacts pane** (§4c of `frontend_spec.md`):
Individual file download buttons, plus phase-level "Download all" buttons.

**C. Interrupt Panel** (§3 above):
Each input file row has an individual [↓ Download] button.
A "Download all phase inputs" button at panel level.

### 4.2 Phase 1 Downloads

Available after Phase 1 completes or at Fact Enrichment / Spec
Generation interrupt points.

| File | Description | Format |
|------|-------------|--------|
| `findings.sarif` | Raw CodeQL output | SARIF JSON |
| `findings.json` | Parsed SARIFFinding list | JSON array |
| `fact_packs.json` | Enriched FactPack list | JSON array |
| `specifications.json` | Final VulnerabilitySpec list | JSON array |
| `phase1_summary.json` | Statistics (counts, reduction rate, by CWE) | JSON |
| `phase1_outputs.tar.gz` | All of the above in one archive | tarball |

### 4.3 Phase 2 Downloads

Available per-spec after Phase 2 completes (outcome = bug_triggered)
or at KLEE Execution interrupt point.

| File | Description | Format |
|------|-------------|--------|
| `klee-out/test*.ktest` | KLEE witness inputs | Binary (.ktest) |
| `klee-out/messages.txt` | KLEE log output | Text |
| `klee-out/test*.kquery` | Path constraint SMT queries | Text |
| `driver.vN.c` | Final driver harness | C source |
| `slice.vN.c` | Final code slice | C source |
| `harness.bc` | Linked LLVM bitcode | Binary |
| `outcome.json` | Phase 2 verdict + statistics | JSON |
| `phase2_spec.tar.gz` | All Phase 2 artifacts for this spec | tarball |

Note: `.ktest` files are binary. The Interrupt Panel shows witness
values as a human-readable table (see §3.14) but the download
is the raw binary.

### 4.4 Phase 3 Downloads

Available per-spec after Phase 3 completes or at Result Classification
interrupt point.

| File | Description | Format |
|------|-------------|--------|
| `replay_driver.c` | Concrete replay driver (klee_* stripped) | C source |
| `asan_report.txt` | Full AddressSanitizer crash report | Text |
| `verified_bug.json` | Final verdict + CWE + ASan type + inputs | JSON |
| `phase3_spec.tar.gz` | All Phase 3 artifacts for this spec | tarball |

### 4.5 Evidence Package (cross-phase)

Available after Phase 3 CONFIRMED. Contains one artifact per phase:

```
evidence_<spec_id>/
  README.md               (auto-generated reproduction instructions)
  phase1/
    spec.json             (VulnerabilitySpec)
  phase2/
    driver.c              (final harness driver)
    slice.c               (final code slice)
    witness.ktest         (KLEE witness)
    path_constraints.txt  (human-readable constraint summary)
  phase3/
    replay_driver.c
    asan_report.txt
    verified_bug.json
```

Download buttons:
- Per-spec: "Download evidence package" in timeline and results table.
- Bulk: "Export all confirmed bugs" on the Results tab.

### 4.6 Download API Endpoints

```
# Phase 1 (run-level)
GET  /api/runs/:run_id/phase1/artifacts
GET  /api/runs/:run_id/phase1/artifacts/:filename
GET  /api/runs/:run_id/phase1/artifacts.tar.gz

# Phase 2 (spec-level)
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts/:filename
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts.tar.gz

# Phase 3 (spec-level)
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts/:filename
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts.tar.gz

# Evidence package
GET  /api/runs/:run_id/specs/:spec_id/evidence.tar.gz
GET  /api/runs/:run_id/results/evidence-all.tar.gz

All file responses:
  - Return presigned redirect (HTTP 302) to artifact store URL.
  - Presigned URL valid for 300 seconds.
  - Content-Disposition: attachment; filename="<original_filename>"
```

---

## 5. Backend API Additions

These endpoints are required by §3 and §4 but are not in
`spec/backend_spec.md`. Add them there.

### 5.1 Auto Mode Control

```
GET   /api/runs/:run_id/auto-config
      Returns: { phase1: {...}, phase2: {...}, phase3: {...} }
      Each function → boolean (auto=true/false)

PATCH /api/runs/:run_id/auto-config
      Body: { "phase2.klee_execution": false }
      Effect: takes effect at next occurrence of that function.
      Requires: operator role.
```

### 5.2 Interrupt Panel State

```
GET   /api/runs/:run_id/interrupts
      Returns list of active interrupt points waiting for user action.

GET   /api/runs/:run_id/interrupts/:interrupt_id
      Returns: function name, input files (with presigned URLs), status.

POST  /api/runs/:run_id/interrupts/:interrupt_id/resume
      Body: { modified_files: [{name, content_base64}],
              option_overrides: {...} }
      Effect: pipeline resumes with provided inputs.
      Requires: intervener role.

POST  /api/runs/:run_id/interrupts/:interrupt_id/skip
      Effect: skips the function, uses default/previous outputs.
      Requires: intervener role.
```

### 5.3 File Validation

```
POST  /api/validate/file
      Body: { filename: str, content_base64: str }
      Returns: { valid: bool, severity: "error"|"warning"|"info",
                 message: str, detected_format: str }
      Used by Interrupt Panel before allowing Resume.
      Public endpoint (no auth required — validation is stateless).
```

### 5.4 User Registration

```
POST  /api/auth/register
      Body: { username, email, password, display_name? }
      Returns: { user_id, username, role: "viewer" }
      Public endpoint.

GET   /api/users                    [admin]
POST  /api/users/:user_id/role      [admin]
      Body: { role: "viewer"|"operator"|"intervener"|"admin" }
DELETE /api/users/:user_id          [admin]
```

---

## 6. Interrupt State Persistence

Interrupt state must survive backend restarts and browser refreshes.

```
Storage:
  Interrupt points stored in PostgreSQL interrupt_points table.
  Schema:
    interrupt_id    UUID
    run_id          FK → runs
    spec_id         FK → specs (nullable for run-level interrupts)
    function_name   str (e.g. "phase2.klee_execution")
    phase           int (1|2|3)
    turn            int (nullable)
    status          "waiting" | "resumed" | "skipped"
    created_at      timestamp
    resumed_at      timestamp (nullable)
    modified_files  JSONB (list of {name, artifact_path})
    option_overrides JSONB

SSE push event on interrupt:
  {kind: "interrupt_created",
   interrupt_id: ...,
   run_id: ...,
   spec_id: ...,
   function_name: ...}

Browser notification:
  If the user is not on the relevant spec page:
    → Toast notification: "⏸ Spec X paused at Phase 2 KLEE Execution"
    → Clicking navigates to the spec detail page, Interrupt Panel open.
```

---

## 7. Open Questions

```
1. Concurrent interrupts.
   If 128 specs reach a KLEE Execution interrupt simultaneously,
   the user faces 128 open interrupt panels.
   Mitigation options:
     a) Queue interrupts; user works through them one at a time.
     b) "Apply to all matching" — bulk resume with same options.
     c) Auto-skip after timeout (configurable per function).
   Decision needed before implementation.

2. Interrupt on re-run.
   If Auto = OFF was set, and the spec is re-queued,
   does the interrupt fire again?
   Proposed: yes — re-queue resets interrupt state for that spec.

3. Query editor persistence.
   Modified queries live for one run. Should they be saveable
   as named query variants in the query catalog?

4. Mobile / narrow viewport.
   Interrupt Panel is a full-screen overlay on desktop.
   On mobile (< 768px), the code editors may be unusable.
   Proposed: interrupt panels are desktop-only; mobile shows
   read-only view with "Resume" and "Skip" buttons only.

5. Interrupt panel for Phase 1 at run level.
   Phase 1 runs once per run (not per spec). The interrupt panel
   for Phase 1 functions blocks the entire run, not just one spec.
   This is more disruptive than Phase 2/3 spec-level interrupts.
   Consider a separate "Run-level interrupt" UI vs "Spec-level interrupt".
```
