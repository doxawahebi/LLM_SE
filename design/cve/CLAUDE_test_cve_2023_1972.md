# CLAUDE_cve_2023_1972.md — CVE-2023-1972 Sailor Pipeline Test Design

> Claude Code reads this file during Session 5 — CVE-2023-1972 Evaluation.
> This is the PRIMARY pipeline validation test.
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## ⚠️ IMPORTANT: CVE-2023-1972 vs Sailor Paper Running Example

These are TWO DIFFERENT vulnerabilities in binutils:

| | Paper Running Example | CVE-2023-1972 |
|---|---|---|
| File | bfd/elfxx-x86.c | bfd/elf.c |
| Function | _bfd_x86_elf_late_size_sections() | _bfd_elf_slurp_version_tables() |
| Pattern | memcpy unchecked size (CWE-120) | heap OOB write via zero-length verdef table (CWE-787) |
| Commit | b2bc71a (March 2026) | c22d38b |

The paper's running example does NOT have a public CVE ID.
CVE-2023-1972 is a DIFFERENT binutils vulnerability chosen because:
  1. Same project (binutils) → same build environment
  2. Same vulnerability class (heap buffer overflow, CWE-787)
  3. bfd/ directory → same CodeQL DB coverage
  4. Publicly documented patch commit available

---

## CVE Overview

```
CVE ID:    CVE-2023-1972
CWE:       CWE-787 (Out-of-bounds Write) + CWE-119
Project:   GNU Binutils 2.35 ~ 2.40
File:      bfd/elf.c
Function:  _bfd_elf_slurp_version_tables()
Bugzilla:  https://sourceware.org/bugzilla/show_bug.cgi?id=30285
Patch:     c22d38baefc5a7a1e1f5cdc9dbb556b1f0ec5c57

Root cause:
  When processing a malformed ELF file with a zero-length verdef
  (version definition) table, _bfd_elf_slurp_version_tables()
  performs heap allocation and subsequent writes without properly
  validating the verdef entry count and sizes.
  This leads to heap-based buffer overflow.

Trigger:
  Craft an ELF file with:
    - SHT_GNU_verdef section present
    - vd_cnt = 0 or malformed vd_next offsets
    → function writes past allocated buffer
```

---

## Ground Truth

```python
CVERecord(
    cve_id             = "CVE-2023-1972",
    cwe                = "CWE-787",
    description        = (
        "Heap-based buffer overflow in _bfd_elf_slurp_version_tables() "
        "in bfd/elf.c when processing a malformed ELF file with "
        "zero-length or malformed verdef table."
    ),
    project            = "binutils",
    project_url        = "https://github.com/bminor/binutils-gdb.git",
    vulnerable_commit  = "binutils-2_40",       # git tag
    fixed_commit       = "c22d38baefc5a7a1e1f5cdc9dbb556b1f0ec5c57",
    vulnerable_file    = "bfd/elf.c",
    vulnerable_func    = "_bfd_elf_slurp_version_tables",
    expected_asan_type = "heap-buffer-overflow",
    build_system       = BuildSystem.AUTOTOOLS,
    build_commands     = [
        "git checkout binutils-2_40",
        "./configure --disable-gdb --disable-sim --disable-gold",
        "bear -- make -j4 all-bfd",
    ],
    dependencies       = [
        "build-essential", "bear", "autoconf", "automake",
        "libz-dev", "libtool", "texinfo", "git", "clang",
    ],
    docker_image       = "ubuntu:22.04",
    env_vars           = {"CC": "clang", "CXX": "clang++"},
    extra_cflags       = "-O1 -g",
)
```

---

## What Makes This a Good Pipeline Validation Test

```
✅ Same project as paper (binutils)
   → build environment already documented in CLAUDE.md

✅ Standard CWE-787 pattern
   → existing custom query cwe787-oob-write should detect it
   → no new queries needed (if pipeline is correct)

✅ No external dependencies
   → binutils builds standalone

✅ Standard function call entry point
   → no event loop bypass needed (unlike tcpdump)

✅ Patch commit is public and clearly identified
   → can verify fixed version does NOT trigger

✅ bfd/ directory is core library code
   → NOT filtered by FILE_SKIP_PATTERNS

Interpretation of results:
  CONFIRMED   → Phase 1~3 pipeline works end-to-end ✅
  Phase1 miss → CodeQL query suite needs improvement
  Phase2 fail → LLM harness synthesis has issues
  Phase3 fail → ASan compilation or replay driver has issues
```

---

## Phase 1: Expected Fact Generation Results

### Expected CodeQL Finding

```json
{
  "rule_id": "local/cpp/cwe-787-oob-write",
  "file": "bfd/elf.c",
  "message": "CWE-787: Out-of-bounds write ...",
  "suspect_calls": ["bfd_alloc", "bfd_zalloc", "memcpy"],
  "entrypoint": "LLM_INFER",
  "assertion_template": "n <= min(len(dst), len(src))"
}
```

### If Phase 1 Misses the Target

```
Diagnosis checklist:
  1. grep findings.json for "elf.c"
     → any findings in bfd/elf.c?

  2. grep findings.json for "_bfd_elf_slurp_version_tables"
     → function in results?

  3. Check compile_commands.json
     → does it contain bfd/elf.c?

Fix A — If no findings in bfd/elf.c:
  CodeQL DB may not have indexed bfd/elf.c.
  Rebuild DB with explicit source:
    codeql database create codeql_db \
      --language=cpp \
      --command="make -j4 all-bfd" \
      --source-root=.

Fix B — If bfd/elf.c indexed but no CWE-787 findings:
  The OOB write in verdef parsing may use
  indirect allocation + pointer arithmetic
  rather than direct memcpy with unchecked size.
  Add targeted query:

  --- cwe787-verdef-overflow.ql ---
  import cpp
  from FunctionCall fc
  where fc.getEnclosingFunction().getName()
          .regexpMatch(".*slurp_version.*") and
        fc.getTarget().getName().regexpMatch(
          "(bfd_alloc|bfd_zalloc|malloc|calloc|realloc)")
  select fc,
    "CWE-787: Allocation in version table parser — " +
    "verify bounds before writing to result."

Fix C — If filtered out:
  _bfd_elf_slurp_version_tables is NOT in test/ or bench/.
  If filtered: review FUNCTION_SKIP_PATTERNS for false matches.
```

---

## Phase 2: Driver Synthesis

### Entry Point Analysis

```
_bfd_elf_slurp_version_tables() signature:
  bfd_boolean _bfd_elf_slurp_version_tables(bfd *abfd,
                                             bfd_boolean default_imported_symver)

Parameters:
  abfd: pointer to bfd structure (the ELF file being processed)
  default_imported_symver: boolean flag

Call chain from objdump/readelf:
  main() → display_bfd() → bfd_check_format()
         → elf_object_p() → _bfd_elf_slurp_version_tables()

Entry point for KLEE:
  _bfd_elf_slurp_version_tables() directly
  (simpler than full bfd_check_format chain)
```

### KLEE Driver Template

```c
/*
 * KLEE driver for CVE-2023-1972
 * Target: _bfd_elf_slurp_version_tables() in bfd/elf.c
 */

#include "bfd.h"
#include "elf-bfd.h"
#include "elf/common.h"
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>

int main() {
    /* (1) Allocate bfd structure */
    bfd *abfd = calloc(1, sizeof(bfd));
    klee_assume(abfd != NULL);

    /* (2) Set up minimal ELF tdata */
    struct elf_obj_tdata *tdata = calloc(1, sizeof(struct elf_obj_tdata));
    abfd->tdata.elf_obj_data = tdata;

    /* (3) Set up section headers with malformed verdef */
    Elf_Internal_Shdr *verdef_hdr = calloc(1, sizeof(Elf_Internal_Shdr));

    /* Symbolic: verdef section size — make small to trigger overflow */
    bfd_size_type verdef_size;
    klee_make_symbolic(&verdef_size, sizeof(verdef_size), "verdef_size");
    klee_assume(verdef_size > 0);
    klee_assume(verdef_size < 64);   /* small — causes OOB on write */

    verdef_hdr->sh_size = verdef_size;

    /* Symbolic: verdef count — zero triggers the bug */
    bfd_vma verdef_count;
    klee_make_symbolic(&verdef_count, sizeof(verdef_count), "verdef_count");
    klee_assume(verdef_count == 0);  /* zero-length verdef → overflow */

    tdata->verdef = (Elf_Internal_Verdef *)calloc(1, sizeof(Elf_Internal_Verdef));
    tdata->verdef->vd_cnt = (unsigned)verdef_count;

    /* (4) Wire section to bfd */
    elf_tdata(abfd)->dynversym_section = NULL;
    elf_tdata(abfd)->dynverdef_section = verdef_hdr;

    /* (5) Guard bypass: abfd->xvec must be set */
    extern const bfd_target elf_x86_64_vec;
    abfd->xvec = &elf_x86_64_vec;

    /* (6) Call the vulnerable function directly */
    _bfd_elf_slurp_version_tables(abfd, FALSE);

    return 0;
}
```

### Assertion Template Application

```
Template: n <= min(len(dst), len(src))
For CWE-787:
  n   = bytes written to version table buffer
  dst = allocated buffer (verdef_size bytes)
  violation: write exceeds verdef_size

klee_assume constraints:
  verdef_size = small (e.g., 8 bytes)
  actual write size > verdef_size
  → KLEE detects out-of-bounds write
```

---

## Phase 2: Stub Synthesis

### Code Slice Rules

```
Entry:   _bfd_elf_slurp_version_tables()
Target ℓ: the heap write that exceeds allocated bounds

On-path (keep):
  - verdef section size check (or lack thereof)
  - bfd_alloc / bfd_zalloc calls
  - loop iterating over verdef entries
  - pointer arithmetic on verdef buffer

Off-path (stub):
  - dynversym processing (separate section)
  - symbol version string handling
  - error/warning output calls → stub returning 0

Type-level stubs:
  struct bfd        → keep: tdata, xvec fields only
  Elf_Internal_Shdr → keep: sh_size, sh_offset
  struct elf_obj_tdata → keep: verdef, dynverdef_section

Loop-level:
  Loops over verdef entries → if(1) single pass
  (enough to trigger the overflow on first iteration)
```

---

## Phase 3: Expected Validation Output

### Expected ASan Report

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size N at thread T0
  #0 _bfd_elf_slurp_version_tables()   bfd/elf.c:<line>
  #1 main()                             replay_driver.c

CONFIRMED conditions:
  - crash == True
  - "heap-buffer-overflow" in output
  - stack frame #0 points to bfd/elf.c ✅ (project source)
```

### Expected verified_bug.json

```json
{
  "verdict": "CONFIRMED",
  "cwe": "CWE-787",
  "file": "bfd/elf.c",
  "func": "_bfd_elf_slurp_version_tables",
  "asan_type": "heap-buffer-overflow",
  "inputs": [
    {"verdef_size": 8},
    {"verdef_count": 0}
  ]
}
```

---

## Pipeline Validation Checklist

Use this to verify each Phase output is correct.

```
Phase 1 ✅ criteria:
  □ findings.json contains entry with file = "bfd/elf.c"
  □ func = "_bfd_elf_slurp_version_tables"
  □ cwe = "CWE-787" or "CWE-119"
  □ suspect_calls includes "bfd_alloc" or "bfd_zalloc"
  □ assertion_template = "n <= min(len(dst), len(src))"
  □ phase1_summary.json written to output_dir/phase1/

Phase 2 ✅ criteria:
  □ outcome = "bug_triggered"
  □ .ktest files present in klee-out/
  □ phase2_summary.json written to output_dir/phase2/
  □ turns_used <= T_max (60)

Phase 3 ✅ criteria:
  □ verdict = "CONFIRMED"
  □ asan_type = "heap-buffer-overflow"
  □ file = "bfd/elf.c" (NOT replay_driver.c)
  □ verified_bug.json written to output_dir/phase3/
  □ phase3_summary.json written

Evaluation DB ✅ criteria:
  □ evaluation.db created
  □ CVEEvaluationResult row exists for CVE-2023-1972
  □ phase1_status = "completed"
  □ phase2_status = "completed"
  □ phase3_status = "completed"
  □ verdict = "true_positive"
  □ evaluation_report.md generated
```

---

## Comparison with Paper Running Example

Running this test lets you compare results with the paper directly.

```
Paper running example:
  File:     bfd/elfxx-x86.c
  Function: _bfd_x86_elf_late_size_sections()
  Pattern:  memcpy(contents, eh_frame_plt, size) unchecked
  Phase 2:  copy_size = 17, dst = 16 bytes → OOB write
  Phase 3:  heap-buffer-overflow @ elfxx-x86.c:2286

CVE-2023-1972:
  File:     bfd/elf.c
  Function: _bfd_elf_slurp_version_tables()
  Pattern:  verdef table write without size validation
  Phase 2:  verdef_size = small, verdef_count = 0 → OOB write
  Phase 3:  heap-buffer-overflow @ elf.c:<line>

Both are binutils, CWE-787, heap-buffer-overflow.
If CVE-2023-1972 is CONFIRMED:
  → Pipeline handles bfd/ directory correctly ✅
  → CodeQL query suite covers CWE-787 ✅
  → KLEE harness synthesis works for bfd structs ✅
  → ASan replay works for binutils ✅
```

---

## Claude Code Task Prompt

```
Read CLAUDE.md, then read CLAUDE_cve_2023_1972.md in full.

Your goal: validate the complete Sailor pipeline using CVE-2023-1972
and produce a verified_bug.json with verdict CONFIRMED.

Note: CVE-2023-1972 (_bfd_elf_slurp_version_tables in bfd/elf.c)
is DIFFERENT from the paper's running example
(_bfd_x86_elf_late_size_sections in bfd/elfxx-x86.c).
Both are binutils CWE-787 vulnerabilities.

Step 0. Environment setup.
        → Verify Docker is available.
        → Build binutils-2.40 using build_commands defined in this file.
        → Confirm compile_commands.json contains bfd/elf.c.
        → Confirm CodeQL database builds successfully.
        → Verify klee, clang, llvm-link are available.

Step 1. Run Phase 1.
        → Target: _bfd_elf_slurp_version_tables in bfd/elf.c
        → If detected: proceed to Step 2.
        → If NOT detected: apply Fix A → B → C in order.
          Re-run Phase 1 after each fix before trying the next.

Step 2. Run Phase 2.
        → Use driver template from this file as starting point.
        → If bug_triggered: proceed to Step 3.
        → If NOT_REACHED: check tdata and verdef struct setup.
        → If SITE_REACHED without bug:
          tighten verdef_size constraint (try verdef_size = 4).
        → If INCONCLUSIVE:
          simplify code slice, reduce KLEE depth to 100.

Step 3. Run Phase 3.
        → If CONFIRMED: write verified_bug.json → SUCCESS.
        → If crash in replay_driver.c only:
          check bfd/ source files included in ASan compilation.

Step 4. Save all results to evaluation.db.
        → Verify all Phase statuses = "completed".
        → Verify verdict = "true_positive".
        → Generate evaluation_report.md.

Step 5. Compare with pipeline validation checklist.
        → Check all □ items in the checklist section.
        → Report any unchecked items with diagnosis.
```
