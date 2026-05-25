# `spec/interactive_control_spec.md`
# Sailor — Interactive Control, User Registration & Download Specification

> **Version**: 2 (rewritten on top of `shared/contracts/sailor.schema.json`).
> Every type referenced here — `PipelineFunctionId`, `InterruptPoint`,
> `FileValidationResult`, `AutoConfig`, the SSE message variants — lives in
> the shared schema. Do not redefine them in this document or in frontend/
> backend code. If you find yourself wanting to invent a new type while
> implementing this spec, add it to the schema first.

Cross-references:
- `shared/contracts/sailor.schema.json` — single source of truth for all wire types
- `shared/contracts/README.md` — conflict resolution log, naming rules
- `spec/frontend_spec.md` — base UI spec (this document extends it)
- `spec/backend_spec.md` — base API contract (this document extends §4 and §5)
- `paper/paper_phase1.md`, `paper_phase2.md`, `paper_phase3.md` — algorithms

---

## 1. Scope and precedence

This document specifies three features on top of `frontend_spec.md` and
`backend_spec.md`:

```
§3   User Registration & Role Management
§4   Auto/Manual Mode + Per-Function Interrupt System
§5   Phase-End Download
```

Precedence rules (changed from v1):

1. Wire-level types: `shared/contracts/sailor.schema.json` is authoritative.
2. API contracts: `backend_spec.md` is authoritative; this file may only
   *add* endpoints, never redefine existing ones.
3. UI behavior: this document is authoritative for the three features
   above. `frontend_spec.md` covers the rest.
4. Where this document and either spec contradict, **fix the contradiction
   in code review** — do not let drift accumulate.

---

## 2. Glossary (resolves prior naming drift)

| Term used in this document | Schema type / value                              | Notes                                                                     |
| -------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------- |
| "function name"            | `PipelineFunctionId` (enum string)               | snake_case, no dots, no display labels. e.g. `phase2_klee_execution`.     |
| "Auto checkbox"            | `AutoConfig[function_name]` (boolean)            | true = run normally. false = pause and wait.                              |
| "Interrupt panel"          | UI for an `InterruptPoint` with `status=waiting` | Backend state lives in `InterruptPoint`; UI renders it.                   |
| "Resume"                   | `InterruptResumeRequest` → status `resumed`      | Pipeline continues with the user's edits.                                 |
| "Skip"                     | `InterruptSkipRequest` → status `skipped`        | Pipeline continues with the default outputs of the skipped function.     |
| "Verdict"                  | `VerdictValue` (`confirmed` / `rejected`)        | Lowercase on the wire. UI may capitalize for display.                     |
| "Validation result"        | `FileValidationResult`                           | Returned with HTTP 200 even when severity=`error`. Distinct from `ApiError`. |

UI display labels (e.g. "KLEE Execution", "Driver Synthesis") are defined
in **one place only**: `frontend/src/lib/pipelineLabels.ts`. They are a
map from `PipelineFunctionId` → human-readable string. Backend code never
sees these labels.

---

## 3. User Registration & Role Management

### 3.1 Registration endpoint

```
POST /api/auth/register              [public, no auth]

Body:    RegisterRequest    (from shared/contracts)
Response 201: RegisterResponse
Response 400: ApiError with code ∈ { "username_taken",
                                     "weak_password",
                                     "invalid_email",
                                     "username_format" }
```

`RegisterRequest` (schema, abbreviated):

```
username      3–32 chars, [A-Za-z0-9_]+
email         RFC 5322
password      ≥ 12 chars; ≥1 uppercase, ≥1 digit, ≥1 symbol
display_name  optional, ≤ 64 chars
```

Server-side rules:

- **Anti-enumeration**: the response NEVER reveals whether the email is
  already registered. If the email is taken, the server still returns
  201 with a freshly generated `user_id` but **does not create the
  account**, and triggers the "already registered" email flow out of
  band (when SMTP is configured). UI cannot distinguish success from
  email-already-exists.
- **First user is admin**: the very first row in the `users` table gets
  `role="admin"`. All subsequent registrations get `role="viewer"`.
  This is the only way to bootstrap; admins promote later users from
  `/settings/users`.
- **Password strength**: the server enforces the rules above. The UI
  also runs a client-side meter (zxcvbn) but the meter is advisory; the
  server's regex check is authoritative. The meter MUST NOT block
  submission solely on its own assessment — only the server's 400 with
  `code="weak_password"` blocks.

Email confirmation:

- If `SMTP_ENABLED=true` in settings: registration creates an account
  in `disabled=true` state; the user must click the confirmation link
  to flip `disabled=false`. Logins to disabled accounts return 403 with
  `code="account_disabled"`.
- If `SMTP_ENABLED=false` (dev mode): accounts are immediately enabled.

### 3.2 Registration UI (`/register`)

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
│  Password strength: ████████░░  Good     │  ← zxcvbn, advisory only
│                                          │
│  [ Create account ]                      │
│                                          │
│  Already have an account? Sign in →      │
└──────────────────────────────────────────┘
```

On 201 response:
- If `role === "admin"`: show banner "You are the first user — you have
  been granted admin role."
- Redirect to `/login` with a flash message "Account created."

On 400 response:
- Render field-level errors keyed by `ApiError.detail.field` (e.g.
  `detail: { field: "username" }`). The UI maps `code` to a localized
  message; the raw `message` is a fallback.

### 3.3 Roles

Inherited from `frontend_spec.md §10`. The schema enum `UserRole` has
four values:

| Role         | Self-register | Run                 | Intervene | Settings | Admin |
| ------------ | ------------- | ------------------- | --------- | -------- | ----- |
| `viewer`     | ✓ (default)   | read                | —         | —        | —     |
| `operator`   | promoted      | start/cancel        | —         | —        | —     |
| `intervener` | promoted      | start/cancel        | ✓         | —        | —     |
| `admin`      | first user only, otherwise promoted | ✓ | ✓ | ✓ | ✓ |

JWT behavior on role change:
- **Downgrade** (e.g. `intervener` → `viewer`): existing access tokens
  are added to a Redis blacklist; subsequent requests get 401.
- **Upgrade**: takes effect at next token refresh. The user may need to
  sign out and back in for the new role to apply UI-side (the UI's
  current role is derived from the token).

### 3.4 User management (`/settings/users`)

Admin-only.

```
Endpoints:
  GET    /api/users                    [admin]   → list of User
  POST   /api/users/:user_id/role      [admin]   → body: { role: UserRole }
  POST   /api/users/:user_id/disable   [admin]
  POST   /api/users/:user_id/enable    [admin]
  POST   /api/users/:user_id/reset-password [admin]
  DELETE /api/users/:user_id           [admin]   → soft delete (sets disabled=true,
                                                   anonymizes email/display_name,
                                                   preserves audit log link)
```

UI: standard CRUD table. Role changes write an `AuditEvent` with
`action="role_change"`.

Restrictions:
- An admin cannot demote themselves if they are the only admin (server
  returns 409 `code="last_admin"`).
- An admin cannot delete themselves; must be deleted by another admin.

---

## 4. Auto/Manual Mode + Per-Function Interrupt System

### 4.1 Core concept

The pipeline has **14 interruptible functions**, enumerated by
`PipelineFunctionId` in the schema. For each function, the run carries
an `AutoConfig` flag:

```
AutoConfig[function_name] = true   (default)
  → function runs automatically. Standard Sailor behavior.

AutoConfig[function_name] = false
  → pipeline pauses immediately before the function executes.
    An InterruptPoint with status="waiting" is created and persisted.
    An SSE message of kind="interrupt_created" is published.
    The function does not run until the user resumes or skips.
```

`AutoConfig` is **per-run**: set at run creation, may be edited mid-run.
There is no global default; missing keys are treated as `true`.

### 4.2 Run-scope vs spec-scope interrupts (resolves v1 OQ-5)

Each `PipelineFunctionId` has a fixed `InterruptScope`:

| `PipelineFunctionId`               | Scope  | When it fires                                            |
| ---------------------------------- | ------ | -------------------------------------------------------- |
| `phase1_db_build`                  | `run`  | Once per run, before CodeQL DB creation.                |
| `phase1_query_execution`           | `run`  | Once per run, before `codeql database analyze`.         |
| `phase1_sarif_parsing`             | `run`  | Once per run, after CodeQL produces SARIF.              |
| `phase1_fact_enrichment`           | `run`  | Once per run, before `FactEnricher.enrich()`.           |
| `phase1_spec_generation`           | `run`  | Once per run, before `SpecificationGenerator`.          |
| `phase2_spec_selection`            | `run`  | Once per run, after Phase 1 completes, before Phase 2 dispatch. |
| `phase2_source_exploration`        | `spec` | Per spec, before exploration phase starts.              |
| `phase2_driver_synthesis`          | `spec` | Per spec, after first `driver.c` draft.                 |
| `phase2_stub_synthesis`            | `spec` | Per spec, after first `slice.c` draft.                  |
| `phase2_compile_diagnose`          | `spec` | Per spec, on every compile failure.                      |
| `phase2_klee_execution`            | `spec` | Per spec, before each KLEE run.                          |
| `phase3_replay_driver_generation`  | `spec` | Per spec (bug_triggered only).                          |
| `phase3_asan_compilation`          | `spec` | Per spec (bug_triggered only).                          |
| `phase3_result_classification`     | `spec` | Per spec (bug_triggered only).                          |

`scope` is **not user-configurable** — it is a property of the function.

**Run-scope semantics**:
- One waiting interrupt at a time per function per run.
- Blocks the entire pipeline progression past that function.
- `spec_id` is `null` on the `InterruptPoint`.

**Spec-scope semantics**:
- One waiting interrupt at a time per function per spec.
- Other specs in the same run progress independently.
- `spec_id` is required on the `InterruptPoint`.

### 4.3 Concurrent interrupts (resolves v1 OQ-1)

If 128 specs in parallel hit `phase2_klee_execution` with auto=false, the
UI must not open 128 panels. Resolution:

**The InterruptPoint list view replaces the modal-overlay pattern.**

```
/runs/:run_id/interrupts                  ← list of all waiting interrupts
/runs/:run_id/interrupts/:interrupt_id    ← single interrupt panel
```

UI behavior:
- A waiting interrupt is **never auto-opened** as a modal. When
  `interrupt_created` arrives via SSE and the user is not on that
  interrupt's panel, the UI shows a non-intrusive toast and increments
  a "waiting" badge in the navigation.
- The user opens the interrupts list explicitly and works through them.
- **"Apply to all matching"** (`InterruptResumeRequest.apply_to_all_matching`):
  when resuming with `apply_to_all_matching=true`, the same
  `option_overrides` are applied to all currently-waiting interrupts in
  this run with the same `function_name`. `modified_files` MUST be empty
  for this case — per-spec file edits cannot be broadcast. Server
  returns 422 with `code="bulk_modify_with_files"` if violated.
- **"Re-enable Auto"** (`InterruptResumeRequest.re_enable_auto`): toggles
  `AutoConfig[function_name]` back to `true` after this resume.
  Combined with `apply_to_all_matching=true`, this is the standard
  "I'm done supervising this function, just let it run" workflow.
- **Auto-skip on timeout**: deferred to a later iteration. Not in MVP.

### 4.4 AutoConfig endpoints

```
GET   /api/runs/:run_id/auto-config                 [viewer+]
      Response 200: AutoConfig (full map; missing keys = true)

PATCH /api/runs/:run_id/auto-config                 [operator+]
      Body:    AutoConfigPatch (partial; only included keys are changed)
      Response 200: AutoConfig (the full post-update config)
      Effect: takes effect at the NEXT occurrence of each changed function.
              Existing waiting interrupts for that function are not
              automatically resolved — the operator must resume/skip them
              explicitly. Audit event written with action="auto_config_change".
      SSE:    emits {kind: "auto_config_changed", payload: AutoConfigChangedPayload}
              on topic runs.<run_id>.
```

Critical rules:
- The body keys are exactly the `PipelineFunctionId` enum values. Keys
  with dots (e.g. `"phase2.klee_execution"`) are rejected with 422
  `code="invalid_function_name"`.
- Editing AutoConfig does NOT pause the pipeline. If a function is
  already running when its auto flag is toggled to `false`, the current
  invocation completes; the next one pauses.

### 4.5 Interrupt endpoints

```
GET   /api/runs/:run_id/interrupts                            [viewer+]
      Query:   status (default: waiting), function_name, spec_id, scope
      Response 200: paginated list of InterruptPoint

GET   /api/runs/:run_id/interrupts/:interrupt_id              [viewer+]
      Response 200: InterruptPoint with input_files populated
                    (each artifact_ref resolvable via GET /api/artifacts/:ref)

POST  /api/runs/:run_id/interrupts/:interrupt_id/files        [intervener+]
      Multipart upload of a single replacement file.
      Body:    multipart/form-data with field "file" and field "name" (logical name)
      Response 200: { artifact_ref: string, validation: FileValidationResult }
      Effect:  uploads to artifact store with a versioned path, runs validation
               server-side, returns both ref and validation. The user examines
               validation result; if severity=error, they typically retry with a
               corrected file. The returned artifact_ref is then passed in the
               subsequent resume call's modified_files entry.

POST  /api/runs/:run_id/interrupts/:interrupt_id/resume       [intervener+]
      Body:    InterruptResumeRequest
      Response 200: { interrupt: InterruptPoint (with status="resumed") }
      Response 409: ApiError code="version_mismatch" (a modified_files entry's
                    base_version is stale)
      Response 422: ApiError code="bulk_modify_with_files" (apply_to_all_matching
                    is true but modified_files is non-empty)
      Effect:  - Validates all referenced files (artifact_refs must exist).
               - Re-runs validation on the chosen files; if any has severity=error,
                 returns 422 with code="validation_failed" and the
                 FileValidationResult in detail.
               - Applies option_overrides via the function's option schema (§4.6).
               - Writes interrupt_points row to status="resumed".
               - Unblocks the worker task for this function.
               - Emits {kind: "interrupt_resolved", payload: {..., resolution: "resumed"}}.
               - If apply_to_all_matching=true, repeats for each matching waiting
                 interrupt in the same run; emits one interrupt_resolved per
                 affected interrupt.
               - Writes AuditEvent action="interrupt_resume".

POST  /api/runs/:run_id/interrupts/:interrupt_id/skip         [intervener+]
      Body:    InterruptSkipRequest
      Response 200: { interrupt: InterruptPoint (with status="skipped") }
      Effect:  - Writes interrupt_points row to status="skipped".
               - Worker proceeds with the default function output (the
                 LLM-generated artifact, the auto-classified verdict, etc.).
               - Emits {kind: "interrupt_resolved", payload: {..., resolution: "skipped"}}.
               - Writes AuditEvent action="interrupt_skip".

POST  /api/validate/file                                       [public]
      Body:    multipart/form-data with field "file" and field "filename"
               (logical name including extension — drives validator dispatch)
      Response 200: FileValidationResult
      Note:    Stateless; does NOT upload to artifact store. Used by the UI
               for inline pre-flight validation before /files upload.
               Even severity="error" returns HTTP 200.
```

### 4.6 Per-function option schemas

`InterruptResumeRequest.option_overrides` is an open `object` in the
shared schema — backend validates per `function_name`. The accepted
shapes are:

```
phase1_db_build:
  build_command:        string (optional override; defaults to RunConfig.build_command)
  existing_db_ref:      string (optional artifact_ref of a pre-built DB)
  → Validation: at least one of build_command or existing_db_ref must be present.

phase1_query_execution:
  query_ids:            string[] (subset of the run's configured queries)
  → Validation: at least 1; each must exist in the catalog or be a modified_file.

phase1_sarif_parsing:
  (no options; user only edits the sarif file)

phase1_fact_enrichment:
  (no options; user only edits findings.json)

phase1_spec_generation:
  skip_file_patterns:    string[] (regex overrides; replaces RunConfig.phase1_skip_files
                                    for this invocation only)
  skip_function_patterns: string[]

phase2_spec_selection:
  selected_spec_ids:    string[] (subset of Phase 1 emitted specs)
  → Validation: ≥ 1; all must be valid spec_ids in this run.

phase2_source_exploration:
  phase2_t_explore:     integer (override for this spec only)
  phase2_t_author:      integer
  phase2_t_max:         integer
  phase2_r_max:         integer
  → Validation: phase2_t_explore + phase2_t_author ≤ phase2_t_max.

phase2_driver_synthesis:
  (no options; user edits driver.c)

phase2_stub_synthesis:
  stub_overrides:       array of { function_name, granularity, return_value }
                        (overrides for which functions are stubbed and how)

phase2_compile_diagnose:
  apply_suggested_fix:  boolean (if true, server applies the auto-fix before resuming)

phase2_klee_execution:
  klee_search_strategies: string[]   (subset of {"random-path", "dfs", "bfs", "nurs:cov"})
  klee_timeout_seconds:   integer    (1 ≤ x ≤ 3600)
  klee_max_depth:         integer

phase3_replay_driver_generation:
  (no options; user edits replay_driver.c)

phase3_asan_compilation:
  asan_build_command:   string
  asan_options:         string    (value for ASAN_OPTIONS env var)

phase3_result_classification:
  classification:       ClassifyVerdictRequest (schema type)
                        { verdict: "confirmed"|"rejected", cwe?, reason? }
```

Unknown keys for a given function are rejected with 422 `code="unknown_option"`.

### 4.7 Input file validation rules

The validator dispatches by filename suffix (and signature for binary).
All rules return `FileValidationResult` shapes; the table summarizes:

```
*.sarif | *.json with "runs" key  → SARIFValidator
  detected_format: "sarif"
  ERROR:   not valid JSON
  ERROR:   missing top-level "runs" array
  WARNING: results count = 0
  WARNING: signature mismatch (PDF/ELF/ZIP detected as content)

findings.json                     → FindingsValidator
  detected_format: "json-array:findings"
  ERROR:   not a JSON array
  ERROR:   any element missing required fields (finding_id, rule_id,
           cwe, location.file, location.line)
  WARNING: any finding has empty suspect_calls

fact_packs.json                   → FactPacksValidator
  detected_format: "json-array:fact-packs"
  ERROR:   not a JSON array
  ERROR:   any element missing required fields (finding, build_context)

specifications.json | spec.json   → SpecValidator
  detected_format: "json:spec"
  ERROR:   not a VulnerabilitySpec (schema validation against Spec type)
  ERROR:   assertion_template empty
  ERROR:   entrypoint empty string

*.c                               → CSourceValidator
  detected_format: "c-source"
  ERROR:   clang --syntax-only fails (uses the run's include paths inside DockerRunner)
  Additional rules when filename matches replay_driver*.c:
  ERROR:   any of the following symbols appears as a call site:
             klee_make_symbolic, klee_assume, klee_assert, klee_warning_once
           Rule id: "replay_driver.klee_call_present"
           Issues list contains line numbers for each occurrence.
  ERROR:   no non-trivial concrete assignments detected (heuristic;
           rule id: "replay_driver.no_concrete_assigns").

*.ql                              → CodeQLValidator
  detected_format: "ql"
  ERROR:   codeql query compile --check-only fails

*.ktest                           → KTestValidator
  detected_format: "ktest"
  ERROR:   does not start with "KTEST" magic bytes
  WARNING: file empty

*.bc                              → BitcodeValidator
  detected_format: "bitcode"
  ERROR:   does not start with 0x42 0x43 magic bytes
  NOTE:    .bc files are view-only — InterruptInputFile.editable=false.
           The validator runs only on uploaded bitcode (rare; replacement
           is the only path, no inline edit).
```

The validator is the **same code path** server-side regardless of whether
called via `/api/validate/file` (pre-flight) or the implicit run during
`/files` upload. Frontend never validates structure locally.

### 4.8 File replacement workflow

```
        ┌─────────────────────────────────────┐
        │  User opens an InterruptPoint panel │
        └─────────────────┬───────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │ Panel lists input_files. For each,  │
        │ user may [View] [Edit] [Replace].   │
        └─────────────────┬───────────────────┘
                          │
                          ▼
        Optional pre-flight: POST /api/validate/file
        (UI runs this when user picks a file from disk
         BEFORE uploading, to give early feedback)
                          │
                          ▼
        Upload: POST /api/runs/.../interrupts/:id/files
        → Returns { artifact_ref, validation: FileValidationResult }
        → UI displays the validation result inline. If severity=error,
          the file is still uploaded (so the user doesn't lose work)
          but is marked as "won't be used unless fixed".
                          │
                          ▼
        Repeat for other files as needed.
                          │
                          ▼
        Resume: POST /api/runs/.../interrupts/:id/resume
        Body references the artifact_refs from the upload step.
        Server re-validates (cheap; just re-fetches the result from cache)
        and refuses to resume if any referenced file has severity=error.
```

**Why two-step** (upload then resume, vs. base64 inline):
- A single SARIF file can be 50–500 MB. Inlining as base64 in a JSON
  body inflates by 33% and pushes the request over typical proxy limits.
- Validation results are useful BEFORE committing to resume; the user
  may want to upload, see the warning, decide.
- Maps cleanly to the artifact store abstraction (`PUT artifact` →
  presigned upload URL → server-side validation hook).

**Archival**: when a file replaces an existing artifact, the old
`artifact_ref` is preserved (artifact store is content-addressed; no
overwrite). The `InterruptPoint.input_files[*].artifact_ref` is updated
to the new ref. Old refs remain reachable via the audit log
(`AuditEvent.diff` records the before/after refs).

### 4.9 Auto checkbox placement (UI)

Auto checkboxes appear in two places — both write to `AutoConfigPatch`:

**A. Run creation (`/runs/new` and "Edit run config")**

Displayed grouped by phase. Each row is a single checkbox. The form
collects an `AutoConfigPatch` (all keys initially unset = default `true`).
On submit, the patch is sent with the run-creation request and applied
atomically with the run's config.

**B. Run Detail page (`/runs/:run_id`)**

Collapsible sidebar "Pipeline Controls" panel with the same 14 checkboxes,
fed by `GET /api/runs/:run_id/auto-config`. Toggling a checkbox sends
a `PATCH` with a single-key `AutoConfigPatch`. Optimistic UI: flip the
checkbox immediately; revert on error.

Both surfaces use the same `PipelineFunctionId` → display-label map from
`frontend/src/lib/pipelineLabels.ts`.

### 4.10 Per-function interrupt panel specifications

For each function, this section lists:
- **What input files** appear in `InterruptPoint.input_files`.
- **What option_overrides** keys are accepted (cross-reference to §4.6).
- **What special validation** applies beyond §4.7's general rules.

All panels share the common chrome from §4.11.

#### 4.10.1 `phase1_db_build`

```
Input files:
  (none — this function generates files, doesn't consume them)
Options (§4.6):
  build_command, existing_db_ref
Special validation:
  - If existing_db_ref provided: the artifact must contain a marker file
    indicating a valid CodeQL DB (presence of `codeql-database.yml`).
  - If build_command empty and no existing_db_ref: resume blocked with
    code="missing_build_input".
```

#### 4.10.2 `phase1_query_execution` — Query Selector

```
Input files:
  Each query as a *.ql artifact (read-only by default, editable on demand).
Options:
  query_ids (subset selected)
Special validation:
  - ≥ 1 query selected.
  - Any modified .ql passes CodeQLValidator.
  - "Modified queries are used for this run only" — backend does NOT
    write them back to the query catalog.
UI notes:
  - Each query row expands to show .ql source in CodeMirror.
  - Edit button promotes to an editable view; on save, file is uploaded
    via /files and added to modified_files for this interrupt.
  - Estimated runtime hint is purely a UI affordance; not part of the
    contract.
```

#### 4.10.3 `phase1_sarif_parsing`

```
Input files:
  findings.sarif
Options:
  (none)
Special validation:
  - SARIFValidator rules from §4.7.
```

#### 4.10.4 `phase1_fact_enrichment`

```
Input files:
  findings.json
Options:
  (none)
Special validation:
  - FindingsValidator rules from §4.7.
```

#### 4.10.5 `phase1_spec_generation`

```
Input files:
  fact_packs.json
Options:
  skip_file_patterns, skip_function_patterns
Special validation:
  - FactPacksValidator rules.
  - Pattern lists must be valid regex (server compiles and validates;
    failure returns code="invalid_regex" with the bad pattern in detail).
UI notes:
  - "Filter preview: X of Y fact packs will pass the current filter rules"
    is a derived UI display computed client-side from the loaded
    fact_packs.json + the current skip patterns. Not stored.
```

#### 4.10.6 `phase2_spec_selection`

```
Input files:
  Each VulnerabilitySpec as a JSON artifact (editable).
Options:
  selected_spec_ids
Special validation:
  - SpecValidator on any edited spec.
  - At least 1 selected_spec_id.
UI notes:
  - Cost estimate is a UI calculation from settings.pricing[provider] ×
    avg_tokens_per_spec × selected_count. The pricing source is
    /api/settings.pricing (admin-managed).
```

#### 4.10.7 `phase2_source_exploration`

```
Input files:
  spec.json (the VulnerabilitySpec for this spec_id, editable)
Options:
  phase2_t_explore, phase2_t_author, phase2_t_max, phase2_r_max
Special validation:
  - SpecValidator.
  - phase2_t_explore + phase2_t_author ≤ phase2_t_max
    (server returns 422 code="invalid_budget" if violated).
```

#### 4.10.8 `phase2_driver_synthesis`

```
Input files:
  driver.c (LLM-generated; editable)
  spec.json (read-only reference)
Options:
  (none)
Special validation:
  - CSourceValidator. clang must accept driver.c with the run's include
    paths.
```

#### 4.10.9 `phase2_stub_synthesis`

```
Input files:
  slice.c (LLM-generated; editable)
Options:
  stub_overrides
Special validation:
  - CSourceValidator on slice.c.
  - CWE-416 rule: if slice.c contains free() calls, each stubbed
    free() function MUST internally call the real free(). Validator
    rule id "stub.cwe416_free_not_called"; severity=error blocks resume.
```

#### 4.10.10 `phase2_compile_diagnose`

```
Input files:
  driver.c, slice.c, stubs.c (all editable)
  compile_output.txt (read-only; the clang/llvm-link stderr)
Options:
  apply_suggested_fix
Special validation:
  - All three .c files must compile (CSourceValidator) after any edits.
UI notes:
  - error_class from the contract (CompileErrorClass enum) drives the UI
    badge: "incomplete_type" | "conflicting_proto" | "redefinition" | "other".
```

#### 4.10.11 `phase2_klee_execution`

```
Input files:
  harness.bc (binary, view-only; hex dump UI)
Options:
  klee_search_strategies, klee_timeout_seconds, klee_max_depth
Special validation:
  - klee_timeout_seconds ∈ [1, 3600].
  - klee_search_strategies: at least 1; each ∈ allowed set.
UI notes:
  - The previous KLEE run's output (if any) is shown read-only.
  - Coverage probe summary (entered/missed functions) is derived from
    the last KleeRunPayload on this spec's turn list.
  - harness.bc cannot be edited here; to change harness, the user must
    go back via phase2_driver_synthesis or phase2_stub_synthesis interrupts.
```

#### 4.10.12 `phase3_replay_driver_generation`

```
Input files:
  replay_driver.c (editable)
  witness.ktest (binary, view-only; UI parses witness values into a table)
Options:
  (none)
Special validation:
  - CSourceValidator + the replay_driver-specific rule from §4.7
    (no klee_* calls; severity=error blocks resume).
```

#### 4.10.13 `phase3_asan_compilation`

```
Input files:
  asan_build.log (read-only, last build output if any)
Options:
  asan_build_command, asan_options
Special validation:
  - Server checks the compile command will NOT include any
    LLM-generated stub files (file path inspection against the run's
    artifact store layout). If a stub path is detected, returns 422
    code="stub_in_asan_build".
  - asan_options is parsed as a colon-separated key=value string; invalid
    format returns code="invalid_asan_options".
```

#### 4.10.14 `phase3_result_classification`

```
Input files:
  asan_report.txt (read-only)
Options:
  classification (ClassifyVerdictRequest schema):
    verdict: "confirmed" | "rejected"
    cwe: optional override
    reason: optional free-text
Special validation:
  - verdict ∈ VerdictValue (lowercase only — "CONFIRMED" returns 422).
  - WARNING (non-blocking) if verdict="confirmed" but the parsed ASan
    stack trace has no frame in the project source. Issue rule id
    "classify.no_project_frame".
UI notes:
  - The parsed stack trace with "project source?" column is rendered
    from the asan_report.txt content — not from a separate API call.
```

### 4.11 Common interrupt panel chrome

Every panel has:

```
┌─────────────────────────────────────────────────────────────────┐
│  ⏸  Interrupted: <display label for function_name>              │
│  Run: <run_name>  |  Phase: <phase from function_name prefix>   │
│  [Spec: <spec_id> | Turn: <turn>/<phase2_t_max>] (spec-scope)   │
├─────────────────────────────────────────────────────────────────┤
│  INPUT FILES                                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  📄 <name>   <size>   <detected_format>                   │  │
│  │     [View] [Edit] [Replace] [Download]                     │  │
│  │     (FileValidationResult banner if last upload validated) │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  OPTIONS                                                        │
│  (function-specific form per §4.10)                             │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  [☐ Apply to all matching interrupts in this run]               │
│  [☐ Re-enable Auto for this function after resuming]            │
│                                                                 │
│  [ Resume ]    [ Skip ]    [ Cancel ]                           │
└─────────────────────────────────────────────────────────────────┘
```

UI behavior:
- **Cancel** closes the panel without submitting; the interrupt stays
  in `waiting`. It does not write any state.
- **Resume** is disabled while any uploaded file has severity=error.
- **Skip** is always enabled (skipping doesn't depend on file validity).
- The two checkboxes are mutually compatible. Re-enable Auto without
  Apply to all = "from now on, run automatically". Both together = the
  common case after deciding the function's defaults are fine.

### 4.12 Manual harness mode (resolves v1 §3.15 ambiguity)

"Disable LLM" is **a per-spec configuration flag**, not an interrupt
that fires every turn. It is exposed via:

```
POST  /api/runs/:run_id/specs/:spec_id/manual-harness          [intervener+]
      Body:    { enabled: boolean }
      Response 200: ManualHarnessMode

GET   /api/runs/:run_id/specs/:spec_id/manual-harness          [viewer+]
      Response 200: ManualHarnessMode
```

When `enabled=true`:
- For this spec only, the worker treats `phase2_driver_synthesis`,
  `phase2_stub_synthesis`, and `phase2_compile_diagnose` as if their
  `AutoConfig` were `false`, EVEN IF the run-level `AutoConfig` is `true`
  for those functions.
- Other specs in the run are unaffected.
- Run-level `AutoConfig` is unchanged in the DB.
- Re-queueing the spec preserves the flag (intentional — the typical
  use case is "I want to take over this one spec").

When `enabled=false` (default): no effect; AutoConfig governs as usual.

This is **not** an SSE event because it's a per-spec state. The frontend
reads it on spec detail page mount.

---

## 5. Phase-End Download

### 5.1 Where downloads appear in the UI

Three surfaces, all backed by the same endpoints from §5.6:

**A. Timeline event cards** (`frontend_spec.md §4b`). Each phase
   completion event shows inline download buttons:

```
✓ 14:02:11   Phase 1 complete — 1,260 specs
              [↓ Phase 1 outputs]

⚑ 14:09:42   Turn 24: bug_triggered
              [↓ KLEE witness (.ktest)]

✓ 14:11:23   CONFIRMED: heap-buffer-overflow
              [↓ Phase 3 outputs]   [↓ Evidence package]
```

**B. Artifacts pane** (`frontend_spec.md §4c`). Per-file [Download]
   buttons plus phase-level "Download all" buttons.

**C. Interrupt panel** (§4.11 above). Each input file row has a
   [Download] button. A "Download all phase inputs" button at the panel
   level downloads the union of `input_files`.

### 5.2 Phase 1 download manifest

Available after Phase 1 completes OR at any Phase 1 interrupt
(snapshot of whatever the function has produced so far).

| File                       | Description                                  | Format         |
| -------------------------- | -------------------------------------------- | -------------- |
| `findings.sarif`           | Raw CodeQL output                            | SARIF JSON     |
| `findings.json`            | Parsed `SARIFFinding` list                   | JSON array     |
| `fact_packs.json`          | Enriched `FactPack` list                     | JSON array     |
| `specifications.json`      | Final `VulnerabilitySpec` list (run-level)   | JSON array     |
| `phase1_summary.json`      | Statistics — see `Phase1Summary` in schema   | JSON           |
| `phase1_outputs.tar.gz`    | All of the above                             | tarball        |

### 5.3 Phase 2 download manifest

Available per-spec after Phase 2 reaches a terminal state OR at
`phase2_klee_execution` interrupt.

| File                                | Description                            | Format       |
| ----------------------------------- | -------------------------------------- | ------------ |
| `klee-out/test*.ktest`              | KLEE witness inputs                    | Binary       |
| `klee-out/messages.txt`             | KLEE log output                        | Text         |
| `klee-out/test*.kquery`             | Path constraint SMT queries            | Text         |
| `driver.vN.c`                       | Each version of the driver harness     | C source     |
| `slice.vN.c`                        | Each version of the code slice         | C source     |
| `assertions.vN.c`                   | Each version of the assertion fragment | C source     |
| `harness.bc`                        | Linked LLVM bitcode                    | Binary       |
| `outcome.json`                      | Phase 2 outcome + statistics           | JSON         |
| `phase2_spec.tar.gz`                | All of the above for this spec         | tarball      |

### 5.4 Phase 3 download manifest

Available per-spec after Phase 3 reaches a terminal state OR at
`phase3_result_classification` interrupt.

| File                       | Description                                  | Format       |
| -------------------------- | -------------------------------------------- | ------------ |
| `replay_driver.c`          | Concrete replay driver (`klee_*` stripped)   | C source     |
| `asan_report.txt`          | Full ASan crash report                       | Text         |
| `verified_bug.json`        | Final verdict; see `Verdict` schema type     | JSON         |
| `phase3_spec.tar.gz`       | All of the above for this spec               | tarball      |

### 5.5 Evidence package (cross-phase)

Available after Phase 3 with `verdict="confirmed"`.

```
evidence_<spec_id>/
  README.md               (auto-generated reproduction instructions)
  phase1/
    spec.json
  phase2/
    driver.c              (final version)
    slice.c               (final version)
    assertions.c          (final version, if any)
    witness.ktest
    path_constraints.txt
  phase3/
    replay_driver.c
    asan_report.txt
    verified_bug.json
```

### 5.6 Download API endpoints

```
# Phase 1 (run-level)
GET  /api/runs/:run_id/phase1/artifacts                          [viewer+]
GET  /api/runs/:run_id/phase1/artifacts/:filename                [viewer+]
GET  /api/runs/:run_id/phase1/artifacts.tar.gz                   [viewer+]

# Phase 2 (spec-level)
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts           [viewer+]
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts/:filename [viewer+]
GET  /api/runs/:run_id/specs/:spec_id/phase2/artifacts.tar.gz    [viewer+]

# Phase 3 (spec-level)
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts           [viewer+]
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts/:filename [viewer+]
GET  /api/runs/:run_id/specs/:spec_id/phase3/artifacts.tar.gz    [viewer+]

# Evidence
GET  /api/runs/:run_id/specs/:spec_id/evidence.tar.gz            [viewer+]
GET  /api/runs/:run_id/results/evidence-all.tar.gz               [viewer+]
```

Response contract:
- **List endpoints** (`/artifacts` without filename) return:
  ```
  { items: [{ name, size_bytes, mime_type, created_at, artifact_ref }] }
  ```
  NOT a tree with presigned URLs. The client requests presigned URLs
  per file on demand (consistent with `CLAUDE_backend.md` Constraint 10).
- **Individual file endpoints** return **HTTP 302** with a `Location`
  header pointing to a presigned URL (TTL 300s). Backend MUST NOT
  stream the bytes through the FastAPI process.
- **Tarball endpoints** with reasonable size (e.g. all Phase 1 for one
  run, ≤ 100MB) may return 302 to a pre-built tarball if it exists, or
  enqueue an `export_task` and return 202 with a job_id (see
  `backend_spec.md §4.4`). Caller polls `GET /api/jobs/:job_id` for the
  resulting artifact_ref, then GETs that for the 302.
- `Content-Disposition: attachment; filename="<original_filename>"` is
  set on the presigned URL via S3/MinIO query parameters.

### 5.7 Snapshot semantics during a running run

Downloads taken during a run are **snapshots of the current artifact
store state**. The endpoint returns whatever files exist at the moment
of the request. Versioned files (`driver.v3.c` etc.) accumulate; older
versions remain accessible.

A download taken from an interrupt panel is a snapshot of inputs the
function will consume IF the user clicks Resume. If the user uploads
new files via §4.8 before resuming, the next download reflects the new
files.

---

## 6. State persistence and recovery

### 6.1 Storage (backend implementation, not part of the wire contract)

Implementation details belong in `CLAUDE_backend.md`. This spec defines
the **observable state** via the schema's `InterruptPoint`, `AutoConfig`,
and `ManualHarnessMode` types, plus the endpoints in §4.4 / §4.5 / §4.12.

How the backend stores these (PostgreSQL tables, Redis state, etc.) is
not specified here. The contract is:
- An interrupt's state survives backend restart.
- An interrupt's `status` transitions are atomic
  (`waiting → resumed | skipped`, terminal).
- `AutoConfig` and `ManualHarnessMode` survive restart.
- All state-changing actions write an `AuditEvent` (§4.4, §4.5).

### 6.2 Browser refresh behavior

After a refresh, the UI:
1. Restores the AutoConfig sidebar via `GET /api/runs/:run_id/auto-config`.
2. Restores the waiting interrupts list via
   `GET /api/runs/:run_id/interrupts?status=waiting`.
3. Reconnects SSE; on reconnect, the server replays missed events from
   the 60s buffer (per the shared SSE contract). If gap > 60s, the
   server emits `resync_required` and the client refetches.

### 6.3 Run cancellation while interrupts are waiting

When a run is cancelled (POST `/api/runs/:id/cancel`):
- All `InterruptPoint`s with `status="waiting"` for this run transition
  to `status="skipped"` with `resolved_by="system"`.
- An `interrupt_resolved` event is emitted per affected interrupt
  (with `resolution="skipped"` and a special `resolved_by="system"`
  to let the UI distinguish from user-initiated skips).
- Worker tasks observe the cancel flag at the next turn boundary and
  exit cooperatively (per `backend_spec.md §7.2`).

---

## 7. SSE topic subscriptions for interactive control

The frontend subscribes to these topics depending on the route. All
topics conform to `SSETopicPattern` in the schema.

```
/runs/:run_id (Run Detail page)
  subscribes:  runs.<run_id>
               runs.<run_id>.specs
  receives:    run_status_changed, run_counters_updated,
               spec_state_changed,
               interrupt_created, interrupt_resolved,
               auto_config_changed

/runs/:run_id/interrupts (Interrupts list page)
  subscribes:  runs.<run_id>
  receives:    interrupt_created, interrupt_resolved, auto_config_changed

/runs/:run_id/interrupts/:interrupt_id (Single interrupt panel)
  subscribes:  runs.<run_id>
  receives:    interrupt_resolved (in case another user resumed/skipped it)
               interrupt_created (only for related interrupts of the same run)

/runs/:run_id/specs/:spec_id (Spec detail)
  subscribes:  runs.<run_id>.specs.<spec_id>
               runs.<run_id>.specs.<spec_id>.logs
  receives:    spec_state_changed (for this spec),
               turn_appended,
               log_line,
               interrupt_created / interrupt_resolved (for this spec)
```

Topic-level access control: viewers may subscribe to any topic in a run
they can read. Interrupt-related events are not restricted further — the
events themselves do not contain secrets (artifact_refs require a follow-up
GET to access content, which goes through the per-artifact access check).

---

## 8. Audit log entries

Every state-changing action in this document writes an `AuditEvent`
(see `AuditEvent.action` enum in the schema, extended to include the
new values):

| Action                | Written when                                             | `target`        | `diff` shape                                              |
| --------------------- | -------------------------------------------------------- | --------------- | --------------------------------------------------------- |
| `interrupt_resume`    | POST `.../interrupts/:id/resume` returns 200             | `interrupt:<id>`| `{ modified_files: [...], option_overrides: {...} }`      |
| `interrupt_skip`      | POST `.../interrupts/:id/skip` returns 200               | `interrupt:<id>`| `{ reason: string \| null }`                              |
| `auto_config_change`  | PATCH `.../auto-config` returns 200                      | `run:<id>`      | `{ before: AutoConfig, after: AutoConfig }`               |
| `file_replace`        | POST `.../interrupts/:id/files` returns 200              | `interrupt:<id>`| `{ name: string, previous_artifact_ref, new_artifact_ref }`|
| `user_register`       | POST `/api/auth/register` returns 201 (account created)  | `user:<id>`     | `{ username: string, role: UserRole }`                    |
| `role_change`         | POST `/api/users/:id/role` returns 200                   | `user:<id>`     | `{ before: UserRole, after: UserRole }`                   |

Bulk operations (`apply_to_all_matching=true`) write **one audit event
per affected interrupt**, not one for the bulk request. This makes the
audit log queryable by interrupt without special-casing.

---

## 9. Backwards-compatibility rules

Following `backend_spec.md §14`:

- Adding new `PipelineFunctionId` values is a **non-breaking change**
  (clients tolerate unknown enum values per backend §14). UI must hide
  unknown function names from the AutoConfig sidebar rather than crash.
- Adding new SSE `kind` values is a non-breaking change. Clients ignore
  unknown kinds (frontend's exhaustive switch should fall through to a
  no-op default for forward compat in production builds — TypeScript's
  exhaustiveness check is a development-time aid).
- Removing or renaming a `PipelineFunctionId` is **breaking** and
  requires an API version bump.

---

## 10. Removed sections (compared to v1 of this document)

The following content from v1 was moved or eliminated:

| v1 location                                              | Disposition                                                       |
| -------------------------------------------------------- | ----------------------------------------------------------------- |
| v1 §6 "Interrupt state persistence" with table schema    | Moved to `CLAUDE_backend.md` (storage implementation detail).     |
| v1 §3.18 verdict enum `CONFIRMED \| FALSE_POSITIVE \| INCONCLUSIVE` | Replaced by `VerdictValue` lowercase enum; `INCONCLUSIVE` removed (Phase 3 only has confirm/reject — inconclusive is a Phase 2 outcome). |
| v1 §3.15 "LLM Disable Mode" embedded in interrupt list   | Promoted to §4.12 — a config flag, not an interrupt.              |
| v1 §5.1 "Auto Mode Control" with dotted-key body         | Replaced by §4.4 with flat snake_case keys (`AutoConfigPatch`).   |
| v1 §5.2 endpoints with `content_base64` body             | Replaced by §4.5 two-step upload-then-resume flow.                |
| v1 §5.3 "/api/validate/file" with inline `content_base64`| Replaced by §4.5 multipart upload; same `FileValidationResult` shape. |
| v1 §7 five open questions                                | All resolved in v2: §4.2 (OQ-5), §4.3 (OQ-1), §6.3 (OQ-2), §4.12 (related to OQ-3). OQ-4 (mobile) and OQ-3 (query persistence) folded into §11. |

---

## 11. Deferred for future iterations

The following are intentionally not in MVP:

- **Mobile viewport** (formerly v1 OQ-4). Interrupt panels are
  desktop-only (≥ 1024px). On smaller viewports, the panel route
  redirects to a read-only summary with [Resume with defaults] and
  [Skip] buttons; no inline editors.
- **Auto-skip timeout** (formerly part of v1 OQ-1). Could be added as
  an `AutoConfig` value alongside `boolean` (e.g. `{ auto: false,
  skip_after_seconds: 600 }`). Not in MVP.
- **Saveable modified queries** (formerly v1 OQ-3). For now, modified
  `.ql` files are run-scoped only. A future iteration may add a query
  catalog API to persist variants.
- **Cross-run dedup of interrupts**. A future iteration could surface
  "this function paused in 3 previous runs of this project" as
  decision support. Out of scope here.

---

## 12. Implementation checklist (for Code)

When implementing this spec, the order is:

1. Verify `shared/contracts/sailor.schema.json` contains all 14 of:
   `PipelineFunctionId`, `InterruptScope`, `InterruptStatus`,
   `InterruptPoint`, `InterruptInputFile`, `InterruptResumeRequest`,
   `InterruptSkipRequest`, `AutoConfig`, `AutoConfigPatch`,
   `FileValidationResult`, `FileValidationSeverity`,
   `InterruptCreatedPayload`, `InterruptResolvedPayload`,
   `AutoConfigChangedPayload`, `ManualHarnessMode`, `RegisterRequest`,
   `RegisterResponse`, `ClassifyVerdictRequest`. (Yes, that's the list —
   if any are missing, run `./scripts/regen_contracts.sh` first.)
2. Backend: implement the endpoints in §4.4, §4.5, §3.1, §3.4, §4.12,
   §5.6 using the imported Pydantic models. Do not redeclare any of
   them.
3. Backend: in workers, replace the abstract "function boundary check"
   from `backend_spec.md §7.2` with the concrete check: for each
   `PipelineFunctionId`, immediately before the function runs, query
   `AutoConfig`; if false, write an `InterruptPoint`, emit
   `interrupt_created`, and block until the row transitions out of
   `waiting` (poll or pub/sub).
4. Frontend: implement the `pipelineLabels.ts` map from
   `PipelineFunctionId` to display strings. This is the only place
   display labels live.
5. Frontend: implement the InterruptList page and the InterruptPanel
   component (single component, parameterized by `function_name`). The
   panel reads `option_overrides`'s schema from `pipelineLabels.ts`'s
   companion `pipelineOptionSchemas.ts` (a per-function form schema).
6. Frontend: subscribe to the topics listed in §7 per route, and
   dispatch the three new SSE kinds in `useSSE.ts`.
7. Add interrupt scenarios to integration tests (one per
   `PipelineFunctionId` × `(resume happy path, skip path, file
   validation error, version mismatch, bulk apply)`).
