# paper_overview.md — Sailor: System Overview
# Cross-reference: paper_phase1.md, paper_phase2.md, paper_phase3.md

---

## Pipeline

```
[Phase 1] Static Analysis Informed Target Generation
  Input:  C/C++ project source + build configuration
  Engine: CodeQL (34 memory-safety queries)
  Stages: fact generation → fact enrichment → spec generation
  Output: List<VulnerabilitySpec>   (one self-contained JSON doc per target)

          ↓  specs are independent; processed in parallel

[Phase 2] LLM-Orchestrated Symbolic Execution
  Input:  VulnerabilitySpec
  Engine: LLM + KLEE
  Action: synthesizes H = (Driver, Code Slice, Assertions)
          iterative compile-execute-refine loop:
            feedback 1: compiler diagnostics (clang + llvm-link)
            feedback 2: KLEE outcome + klee_warning_once probes
  Budgets:
    T_explore = 8    source exploration turns
    T_author  = 12   harness authoring turns
    T_max     = 60   total turn budget
    T_klee    = 300s per KLEE run
    R_max     = 15   refinements after site reached
  Output: one of three outcomes:
    (a) bug_triggered          → .ktest witness inputs  → Phase 3
    (b) inconclusive           → T_max exhausted
    (c) likely_false_positive  → site reached, no bug, R_max hit

          ↓  only (a) proceeds

[Phase 3] Concrete Validation
  Input:  .ktest witness inputs
  Engine: AddressSanitizer on unmodified project source
  Action: rewrite klee_make_symbolic → memcpy of witness bytes
          compile unmodified project with -fsanitize=address → .a
          link replay driver against .a, execute
  Confirm rule: at least one ASan stack frame must point inside the
                project's own source files (frames in driver.c /
                stubs.c / system libs → not confirmed)
  Output: verified_bug.json + replay driver + ASan crash report
```

---

## VulnerabilitySpec (Phase 1 → Phase 2 interface)

```json
{
  "rule_id":            "local/cpp/cwe-120-overflow",
  "file":               "bfd/elfxx-x86.c",
  "line":               2699,
  "message":            "CWE-120: Buffer Overflow via memcpy (unchecked length).",
  "snippet":            "memcpy(htab->..->contents, ..eh_frame_plt, ..->size);",
  "trace":              [{"file": "bfd/elfxx-x86.c", "line": 2699}],
  "suspect_calls":      ["memcpy", "bfd_zalloc", "bfd_put_32"],
  "pointer_vars":       ["contents", "eh_frame_plt"],
  "length_vars":        ["size"],
  "bounds_hints":       [],
  "build_context":      {"include_paths": ["-Ibfd"], "defines": []},
  "entrypoint":         "LLM_INFER",
  "assertion_template": "n <= min(len(dst), len(src))"
}
```

Each spec is self-contained. Phase 2 needs nothing beyond it to begin
synthesis. This is what enables parallel processing.

---

## Harness H (Phase 2 output → Phase 3 input)

```
Driver      main() — allocates parameters, marks symbolic fields,
                     encodes klee_assume guards, calls entry e

Code Slice  self-contained C file along call chain e → ℓ, with stubs:
              function-level: off-path callees → symbolic-return stubs
              branch-level:   off-path if blocks → if(0)
              loop-level:     loops enclosing ℓ → if(1)
              type-level:     project structs → fields accessed only

Assertions  klee_assert(0) placed after ℓ (reachability check)
            + klee_assume constraints in driver that violate the
              safety property (forces KLEE to explore the bug path)
```

---

## Three-Phase Classification

Same vulnerability viewed at three abstraction levels.
ASan verdict is ground truth (produced from unmodified source).

```
Phase 1 → CodeQL → CWE pattern      → CWE-120
Phase 2 → KLEE   → memory error     → .ptr.err
Phase 3 → ASan   → concrete crash   → CWE-122 / heap-buffer-overflow
```

CWE refinement (Phase 3 narrows Phase 1):
  ASan "heap-buffer-overflow"   → CWE-122
  ASan "stack-buffer-overflow"  → CWE-121

---

## verified_bug.json (final pipeline output)

```json
{
  "verdict":   "CONFIRMED",
  "cwe":       "CWE-122",
  "file":      "elfxx-x86.c",
  "line":      2286,
  "func":      "_bfd_x86_elf_late_size_sections",
  "asan_type": "heap-buffer-overflow",
  "inputs": [
    {"copy_size": 17},
    {"dst_bytes": 16},
    {"src_bytes": 512}
  ]
}
```

Note: `line` here is ASan's reported line (2286). The CodeQL spec
reports line 2699. Both locate the same memcpy call; the difference
is how each tool maps the instruction back to source.

---

## Running Example (used in all four phase docs)

```
Project:  GNU Binutils
File:     bfd/elfxx-x86.c
Function: _bfd_x86_elf_late_size_sections()
Commit:   b2bc71a (March 2026)

Vulnerable code (line 2699):
  if (htab->plt_eh_frame != NULL
      && htab->plt_eh_frame->contents != NULL) {
    memcpy(htab->plt_eh_frame->contents,   // dst (16 B)
           htab->plt.eh_frame_plt,         // src (512 B)
           htab->plt_eh_frame->size);      // size: UNCHECKED ← bug
  }

Witness: copy_size = 17  →  17-byte write into 16-byte dst
ASan:    heap-buffer-overflow → CWE-122
```

---

## Assertion Templates (per CWE — used by Phase 2 to encode safety property)

| Vulnerability class          | CWEs               | Template                              |
|------------------------------|--------------------|---------------------------------------|
| Out-of-bounds read/write     | 120, 121, 125, 787 | n <= min(len(dst), len(src))          |
| Use-after-free / double-free | 415, 416           | no use of p after free(p)             |
| Stale pointer                | 416 (variants)     | p not dereferenced after realloc/free |
| Null dereference             | 476                | p != NULL before *p                   |
| Integer overflow             | 190                | arithmetic within type range          |
| Out-of-range offset          | 823                | offset within allocation bounds       |
| Return of stack address      | 562                | no return of stack-local address      |
| Uncontrolled recursion       | 674                | recursion depth bounded               |

No matching template → LLM derives the property from `message` + fact pack.

---

## Filtering (Phase 1 skip categories)

Removed before specs are emitted:
  File paths:    test/ testing/ bench*/ example/ fuzz/ oss-fuzz/
                 *.gen.c vendor/ third-party/  + project-specific CLI files
  Function names: main, test_*, _test, check_*, bench_*, perf_*, mock_*,
                  __builtin_*, __asan_*, __ubsan_*

Example reduction: Binutils 19,140 raw findings → 1,260 active targets.
