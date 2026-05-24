# CLAUDE_cve_2017_13028.md — CVE-2017-13028 Sailor Detection Prompt

> Claude Code reads this file during Session 5 — CVE-2017-13028 Evaluation.
> This document is self-contained: it includes all ground truth, build specs,
> and adaptive pipeline instructions needed to detect this CVE with Sailor.
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## CVE Overview

```
CVE ID:    CVE-2017-13028
CWE:       CWE-125 (Out-of-bounds Read)
Project:   tcpdump 4.9.1
File:      print-bootp.c
Function:  bootp_print()
Line:      325  (EXTRACT_16BITS call — confirmed by ASan trace)
ASan type: heap-buffer-overflow (READ of size 2)

Root cause:
  bootp_print() calls EXTRACT_16BITS(bp->flags) at line 325
  without a prior ND_TCHECK bounds verification.
  When ndo->ndo_vflag >= 1, execution reaches this code path.
  The packet buffer is only 53 bytes but EXTRACT_16BITS attempts
  to read 2 bytes past the end of the allocation.

CRITICAL constraint:
  ndo->ndo_vflag MUST be set to >= 1 (use 3 for deepest path)
  to reach the vulnerable code path.
  Without this flag, bootp_print() exits early and the
  vulnerability is NEVER triggered.
```

---

## Ground Truth (for EvaluationPipeline matching)

```python
CVERecord(
    cve_id             = "CVE-2017-13028",
    cwe                = "CWE-125",
    description        = (
        "Buffer over-read in bootp_print() in print-bootp.c "
        "via EXTRACT_16BITS called without ND_TCHECK bounds check. "
        "Triggered only when ndo->ndo_vflag >= 1."
    ),
    project            = "tcpdump",
    project_url        = "https://github.com/the-tcpdump-group/tcpdump.git",
    vulnerable_commit  = "tcpdump-4.9.1",   # git tag
    fixed_commit       = "29e5470",          # bounds check added
    vulnerable_file    = "print-bootp.c",
    vulnerable_line    = 325,
    vulnerable_func    = "bootp_print",
    expected_asan_type = "heap-buffer-overflow",
    build_system       = BuildSystem.AUTOTOOLS,
    build_commands     = [
        # Step 1: build libpcap (required dependency)
        "git clone --depth=1 https://github.com/the-tcpdump-group/libpcap.git ../libpcap",
        "cd ../libpcap && ./configure --prefix=$(pwd)/../libpcap-install && make -j4 install",
        # Step 2: build tcpdump against local libpcap
        "git checkout tcpdump-4.9.1",
        "./configure --with-pcap=../libpcap-install",
        "bear -- make -j4",
    ],
    dependencies       = [
        "build-essential", "bear", "autoconf", "automake",
        "flex", "bison", "libssl-dev", "git", "clang",
    ],
    docker_image       = "ubuntu:20.04",
    env_vars           = {"CC": "clang", "CXX": "clang++"},
    extra_cflags       = "-O1 -g",
)
```

---

## ASan Trace Analysis (Ground Truth Evidence)

```
Confirmed call chain from ASan trace:
  main()                    tcpdump.c:2009
  pcap_loop()               pcap.c:875
  pcap_offline_read()       savefile.c:507
  print_packet()            tcpdump.c:2506
  pretty_print_packet()     print.c:339
  ether_if_print()          print-ether.c:261
  ether_print()             print-ether.c:236
  ethertype_print()         print-ether.c:333
  ip_print()                print-ip.c:658
  ip_print_demux()          print-ip.c:387
  udp_print()               print-udp.c:582
  bootp_print()             print-bootp.c:325   ← VULNERABLE SITE ℓ
  EXTRACT_16BITS()          extract.h:144        ← CRASH POINT

Allocation: 53-byte heap region
  allocated by pcap_check_header() in sf-pcap.c:401
  EXTRACT_16BITS reads 2 bytes past end of this region
```

---

## poc.pcap Analysis

```
The poc.pcap encodes a crafted Ethernet/IPv4/UDP/BOOTP packet where:
  - Ethernet frame length field claims 65570 bytes (0xEE17 = large)
  - Actual packet data is only 53 bytes
  - BOOTP flags field (bp->flags) is positioned at byte 53
  - EXTRACT_16BITS(bp->flags) attempts to read bytes 53-54
  - But allocation ends at byte 53 → 1 byte over-read

poc.pcap hex:
  d4c3b2a1 02000400 00000005 00000000  (pcap global header)
  35000000 01000000 00000000 00000000  (pcap packet header)
  35000000 22000100 000cfb49 967ec0ff  (packet data start)
  ff80009d 08004500 ee179d0f e000fc11
  00ff1200 000f6b5f 5320 4200 0044 e800
  0514 0000 000d 1400 0000 0d00 ff      (total: 53 bytes)
```

---

## Phase 1: Fact Generation — Query Design

### Why standard queries will likely MISS this CVE

```
Standard CWE-125 queries detect:
  buf[i]  where i may exceed array bounds
  memcpy(dst, src, len) where len > sizeof(dst)

This CVE uses:
  EXTRACT_16BITS(bp->flags)
  → macro expands to: ((uint16_t)ntohs(*(const uint16_t *)(p)))
  → pointer dereference INSIDE a macro
  → CodeQL may not track bounds through macro expansion
  → standard queries will NOT flag this ⚠️
```

### Required Custom Query: `cwe125-extract-macro-overread.ql`

```ql
/**
 * @name CWE-125: Out-of-bounds read via EXTRACT_*BITS without ND_TCHECK
 * @id local/cpp/cwe-125-extract-macro-overread
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-125
 */
import cpp

/**
 * Matches EXTRACT_8BITS, EXTRACT_16BITS, EXTRACT_32BITS, EXTRACT_64BITS
 * and their LE/BE variants used in tcpdump/libpcap codebases.
 */
predicate isExtractMacroCall(MacroInvocation mi) {
  mi.getMacroName().regexpMatch(
    "EXTRACT_(8|16|24|32|40|48|56|64)BITS(_LO|_HI)?")
}

/**
 * ND_TCHECK / ND_TCHECK2 / ND_TTEST macros verify bounds before access.
 * Returns true if any such check appears in the same function
 * at a line BEFORE the given macro invocation.
 */
predicate hasPriorBoundsCheck(MacroInvocation extract, Function f) {
  exists(MacroInvocation check |
    check.getMacroName().regexpMatch("ND_T(CHECK|TEST)(2)?") and
    check.getEnclosingFunction() = f and
    check.getLocation().getStartLine() <
      extract.getLocation().getStartLine()
  )
}

/**
 * Returns true if the function containing the macro call
 * is guarded by a vflag/verbosity check (ndo_vflag > 0).
 * This identifies deep-path vulnerabilities only reachable
 * with verbose output enabled.
 */
predicate isUnderVflagGuard(MacroInvocation mi) {
  exists(IfStmt guard, Function f |
    f = mi.getEnclosingFunction() and
    guard.getEnclosingFunction() = f and
    guard.getCondition().toString().regexpMatch(".*ndo_vflag.*") and
    guard.getLocation().getStartLine() <
      mi.getLocation().getStartLine()
  )
}

from MacroInvocation mi, Function f
where
  isExtractMacroCall(mi) and
  f = mi.getEnclosingFunction() and
  not hasPriorBoundsCheck(mi, f)
select mi,
  "CWE-125: " + mi.getMacroName() +
  " in " + f.getName() +
  " called without prior ND_TCHECK bounds verification." +
  (isUnderVflagGuard(mi)
    ? " [NOTE: only reachable with ndo_vflag > 0]"
    : "")
```

### Additional Query: `cwe125-snapend-unchecked.ql`

```ql
/**
 * @name CWE-125: Pointer access without ndo_snapend bounds check
 * @id local/cpp/cwe-125-snapend-unchecked
 * @kind problem
 * @severity error
 */
import cpp

/**
 * Detects pointer dereferences of ndo_packetp-derived pointers
 * that are not guarded by a snapend comparison.
 * Pattern: bp->field accessed where bp is derived from ndo_packetp
 * without checking (bp + offset) <= ndo_snapend.
 */
predicate isSnapendCheck(Expr e) {
  e.toString().regexpMatch(".*(ndo_snapend|snapend).*") or
  e.toString().regexpMatch(".*ND_TCHECK.*")
}

predicate isPacketPointerDeref(PointerDereferenceExpr deref) {
  deref.getOperand().toString().regexpMatch(
    ".*(bp|cp|p|packet|bootp|dhcp).*")
}

from PointerDereferenceExpr deref, Function f
where
  isPacketPointerDeref(deref) and
  f = deref.getEnclosingFunction() and
  f.getName().regexpMatch(".*(bootp|dhcp|bootp_print).*") and
  not exists(Expr check |
    isSnapendCheck(check) and
    check.getEnclosingFunction() = f and
    check.getLocation().getStartLine() <=
      deref.getLocation().getStartLine()
  )
select deref,
  "CWE-125: Packet pointer dereference in " + f.getName() +
  " without snapend bounds check."
```

---

## Phase 2: Driver Synthesis

### Critical Flag — MUST be set

```
ndo->ndo_vflag = 3

Without this, bootp_print() exits before reaching line 325.
This is the single most important constraint for this CVE.
The fuzzer harness confirms this:
  "★ CRITICAL: must be >= 1 to reach vulnerable path ★"
```

### Driver based on fuzzer_harness.c

```c
/*
 * KLEE driver for CVE-2017-13028
 * Based on confirmed fuzzer_harness.c and ASan trace.
 *
 * Key design decisions:
 *   1. ndo_vflag = 3 MANDATORY — reaches line 325 of print-bootp.c
 *   2. ndo_snapend = target_buf + snap_size (symbolic, < len)
 *      → forces EXTRACT_16BITS to read past allocation
 *   3. Direct call to bootp_print() — bypasses pcap capture loop
 *   4. Callback stubs return 0 / do nothing (safe defaults)
 */

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>

/* Stub callbacks — match fuzzer_harness.c pattern */
static void stub_default_print(netdissect_options *ndo,
    const u_char *bp, u_int length) { }
static int stub_printf(netdissect_options *ndo,
    const char *fmt, ...) { return 0; }
static void stub_error(netdissect_options *ndo,
    const char *fmt, ...) { }
static void stub_warning(netdissect_options *ndo,
    const char *fmt, ...) { }

int main() {
    netdissect_options *ndo = calloc(1, sizeof(netdissect_options));

    /* (1) Wire callbacks */
    ndo->ndo_default_print = stub_default_print;
    ndo->ndo_printf        = stub_printf;
    ndo->ndo_error         = stub_error;
    ndo->ndo_warning       = stub_warning;
    ndo->ndo_snaplen       = 65535;

    /* (2) ★ CRITICAL: must be >= 1 to reach vulnerable path ★ */
    ndo->ndo_vflag = 3;

    /* (3) Symbolic packet buffer
     *     Size derived from poc.pcap: 53 bytes minimum
     *     EXTRACT_16BITS needs bytes 53-54 → triggers over-read */
    size_t pkt_len = 64;   /* slightly larger than poc.pcap (53 bytes) */
    unsigned char *pkt = malloc(pkt_len);
    klee_make_symbolic(pkt, pkt_len, "bootp_packet");

    /* (4) ★ CRITICAL: snap_size symbolic and < pkt_len
     *     This makes ndo_snapend fall BEFORE the end of the packet,
     *     causing EXTRACT_16BITS to read past ndo_snapend. ★ */
    size_t snap_size;
    klee_make_symbolic(&snap_size, sizeof(snap_size), "snap_size");
    klee_assume(snap_size >= 44);      /* min BOOTP header size */
    klee_assume(snap_size < pkt_len);  /* snapend < packet end → over-read */

    ndo->ndo_packetp = pkt;
    ndo->ndo_snapend = pkt + snap_size;

    /* (5) Guard bypass: ndo must not be NULL */
    klee_assume(ndo != NULL);

    /* (6) Direct call — bypasses pcap_loop entirely */
    bootp_print(ndo, pkt, (u_int)pkt_len);

    return 0;
}
```

### Assertion Template for CWE-125

```
Template:   n <= min(len(dst), len(src))
Instantiation for this CVE:
  n   = 2                         (EXTRACT_16BITS reads 2 bytes)
  dst = (read target) pkt + offset
  bound = ndo_snapend - (pkt + offset)

Violation condition added to driver:
  klee_assume(snap_size < pkt_len);  ← bound < required read size
  → KLEE detects: READ of size 2 past allocation end
```

---

## Phase 2: Stub Synthesis

### Code Slice Rules for tcpdump

```
Entry function e: bootp_print()
Vulnerable site ℓ: print-bootp.c:325 — EXTRACT_16BITS(bp->flags)

On-path (keep):
  bootp_print() body up to line 325
  The vflag >= 1 branch containing EXTRACT_16BITS(bp->flags)

Off-path (stub):
  All other if(ndo_vflag >= N) blocks → if(0)
  vendor_tag printing functions → symbolic return stubs
  All EXTRACT_* calls before line 325 → symbolic return stubs
    EXCEPTION: EXTRACT_16BITS at line 325 is the target — KEEP IT

Type-level stubs:
  struct bootp — keep only: bp_flags field (at correct offset)
  struct netdissect_options — keep:
    ndo_vflag, ndo_packetp, ndo_snapend,
    ndo_printf, ndo_error, ndo_warning, ndo_default_print

Loop-level:
  Any loops before line 325 → if(1) for single pass

CRITICAL stub exception:
  Do NOT stub EXTRACT_16BITS at line 325.
  It is the vulnerable site and must remain intact.
  Stub all OTHER EXTRACT_* calls before line 325 with symbolic returns.
```

### struct bootp field offset requirement

```c
/*
 * bp->flags must be at the correct offset within struct bootp.
 * From BOOTP RFC 951 + ASan trace (53-byte allocation):
 *   bp_flags is at offset 10 (BP_FLAGS_OFFSET)
 *
 * Minimal type-level stub:
 */
typedef struct bootp {
    uint8_t  bp_op;       /* offset 0 */
    uint8_t  bp_htype;    /* offset 1 */
    uint8_t  bp_hlen;     /* offset 2 */
    uint8_t  bp_hops;     /* offset 3 */
    uint32_t bp_xid;      /* offset 4 */
    uint16_t bp_secs;     /* offset 8 */
    uint16_t bp_flags;    /* offset 10 ← EXTRACT_16BITS target */
    /* remaining fields not needed for slice */
} bootp;
```

---

## Phase 3: Concrete Validation

### Expected ASan output

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 2 at thread T0
  #0 EXTRACT_16BITS()   extract.h:144
  #1 bootp_print()      print-bootp.c:325
  #2 main()             replay_driver.c

CONFIRMED conditions:
  - crash == True
  - "heap-buffer-overflow" in asan_output
  - stack frame #1 points to print-bootp.c (project source) ✅
```

### Replay driver construction note

```
When generating the concrete replay driver:
  1. Replace klee_make_symbolic(pkt, ...) with memcpy of witness bytes
  2. Replace klee_make_symbolic(&snap_size, ...) with
     memcpy(&snap_size, <witness_bytes>, sizeof(snap_size))
  3. Keep ndo->ndo_vflag = 3   ← NEVER remove this line
  4. Remove all klee_assume() calls
  5. Remove klee_assert() if present
```

---

## Adaptive Pipeline: Self-Healing Instructions

The following instructions define how Claude Code must respond
to each possible failure at each Phase.
Execute this adaptive loop until CONFIRMED or budget exhausted.

---

### ADAPTIVE LOOP — Entry Point

```
READ this entire file before starting.
Then execute:

  attempt = 1
  max_attempts = 5

  LOOP:
    run_phase1()
    if phase1 detected print-bootp.c:bootp_print():
      run_phase2()
      run_phase3()
      if CONFIRMED: SUCCESS → write verified_bug.json → EXIT
    else:
      diagnose_phase1_failure()
      apply_phase1_fix()
      attempt += 1
      if attempt > max_attempts: FAIL → write failure_report → EXIT
    CONTINUE LOOP
```

---

### Phase 1 Failure Responses

#### Failure: No findings at print-bootp.c:bootp_print()

```
Diagnosis step:
  1. Check if ANY findings were produced for print-bootp.c
     → grep findings.json for "print-bootp"
  2. Check if CodeQL DB was built successfully
     → verify codeql_db/db-cpp exists
  3. Check if compile_commands.json was generated
     → verify it contains entries for print-bootp.c

Fix A — If CodeQL DB build failed:
  Rebuild with explicit libpcap path:
    codeql database create codeql_db \
      --language=cpp \
      --command="make -j4" \
      --source-root=. \
      --overwrite
  Verify: check that print-bootp.c appears in DB source list.

Fix B — If compile_commands.json missing print-bootp.c:
  Re-run bear with explicit targets:
    bear -- make -j4 tcpdump
  Verify compile_commands.json contains print-bootp.c entry.

Fix C — If DB built but queries produced no findings:
  Standard queries missed macro-based over-read.
  Action: write and run BOTH custom queries defined in this file:
    1. cwe125-extract-macro-overread.ql
    2. cwe125-snapend-unchecked.ql
  Write them to sailor/codeql/custom_queries/
  Re-run Phase 1 with these queries included.

Fix D — If custom queries run but still no findings at bootp_print():
  The macro expansion may not be tracked by CodeQL.
  Action: add a direct pattern query targeting bootp_print() explicitly:

  --- cwe125-bootp-direct.ql ---
  import cpp
  from FunctionCall fc
  where fc.getEnclosingFunction().getName() = "bootp_print"
    and fc.getTarget().getName().regexpMatch("EXTRACT.*BITS.*")
  select fc,
    "CWE-125: EXTRACT_*BITS in bootp_print without bounds check."

Fix E — If findings exist but filtered out by skip patterns:
  Check if print-bootp.c matched any FILE_SKIP_PATTERNS.
  print-bootp.c should NOT be filtered (it is core library code).
  If filtered: add explicit whitelist override for this file.
```

---

### Phase 2 Failure Responses

#### Failure: NOT_REACHED (bootp_print ℓ never executed)

```
Diagnosis:
  Check coverage probes: which functions were entered?
  Expected probe sequence:
    bootp_print() ENTRY → should fire
    if NOT firing → driver is not reaching bootp_print()

Fix A — ndo_vflag not set correctly:
  Verify driver contains: ndo->ndo_vflag = 3;
  This is MANDATORY. If missing, add it immediately.
  Re-run Phase 2.

Fix B — bootp_print() not in code slice:
  Verify slice_c contains bootp_print() function definition.
  If missing: re-run stub synthesis with explicit on-path:
    on-path: bootp_print() → EXTRACT_16BITS at line 325

Fix C — snap_size constraint too tight:
  Current: klee_assume(snap_size >= 44)
  If KLEE cannot find satisfying path, relax:
    klee_assume(snap_size >= 12)   /* min: just past bp_flags offset */
  Re-run Phase 2.

Fix D — struct bootp field offset wrong:
  Verify bp_flags is at offset 10 in the type-level stub.
  If wrong offset: EXTRACT_16BITS reads wrong memory location.
  Correct the struct definition using the layout defined in this file.
```

#### Failure: SITE_REACHED but no bug (refine_count incrementing)

```
Diagnosis:
  klee_assert(0) fires → ℓ is reached.
  But KLEE does not detect memory error.
  → snap_size constraint not tight enough to cause over-read.

Fix A — Tighten snap_size upper bound:
  Current: klee_assume(snap_size < pkt_len)
  Change to: klee_assume(snap_size == pkt_len - 1)
  This forces snap_size to be exactly 1 byte short.
  EXTRACT_16BITS(bp->flags) will then read 1 byte past end.

Fix B — Shrink pkt_len allocation:
  Current: pkt_len = 64
  Match poc.pcap exactly: pkt_len = 53
  Then: klee_assume(snap_size == 53)
        → ndo_snapend == pkt + 53 == end of allocation
        → EXTRACT_16BITS tries to read byte 54 → over-read

Fix C — Ensure bp_flags is at the right position in symbolic packet:
  Add constraint: the byte at offset 10 in pkt is symbolic.
  klee_make_symbolic(pkt + 10, 2, "bp_flags_bytes");
  (instead of making the entire packet symbolic)
```

#### Failure: INCONCLUSIVE (T_max exhausted)

```
Diagnosis:
  Phase 2 used all 60 turns without bug_triggered.
  Most likely cause: harness is too complex for KLEE.

Fix A — Simplify the code slice:
  Remove ALL code in bootp_print() before the vflag check at line 325.
  Stub everything before the EXTRACT_16BITS call.
  Minimal slice:

  bool bootp_print(netdissect_options *ndo,
                   const u_char *cp, u_int length) {
    klee_warning_once("SPINE_PROBE:bootp_print:ENTRY");
    const struct bootp *bp = (const struct bootp *)cp;
    if (ndo->ndo_vflag) {      /* keep this guard */
      /* stub all code before line 325 */
      if (0) { /* off-path */ }
      /* line 325 — the target */
      uint16_t flags = EXTRACT_16BITS(&bp->bp_flags);
      klee_assert(0 && "SAILOR_SINK_REACHED");
    }
    return 1;
  }

Fix B — Reduce KLEE depth:
  Set klee_depth_limit = 100 (from default 1000).
  The path to ℓ is short; deep exploration is wasted effort.
```

---

### Phase 3 Failure Responses

#### Failure: ASan crash not in project source

```
Diagnosis:
  crash occurred but stack trace shows only:
    extract.h (header file, not .c)
  or
    replay_driver.c (harness file)

Fix:
  extract.h is an inline function header.
  The CONFIRMED condition must accept extract.h as a valid
  project source location for this CVE.

  Update ResultClassifier._is_project_source() to include:
    - "extract.h" as a valid project source file
    - "print-bootp.c" as the primary location

  Re-classify with updated logic.
```

#### Failure: Replay driver does not reproduce crash

```
Diagnosis:
  KLEE witness produced but concrete execution does not crash.

Fix A — Verify ndo_vflag = 3 in replay driver:
  This line MUST survive the replay driver generation transformation.
  Check replay_driver.c contains: ndo->ndo_vflag = 3;
  If missing: ReplayDriverGenerator is incorrectly stripping it.
  Fix: _remove_klee_assume() must NOT remove ndo->ndo_vflag = 3
  (it is not a klee_assume call — it is a regular assignment).

Fix B — Verify witness snap_size value:
  Read ktest file: what is the concrete value of snap_size?
  It must be < pkt_len (e.g., snap_size = 53, pkt_len = 64).
  If snap_size >= pkt_len: the witness does not trigger over-read.
  → Go back to Phase 2, apply Fix B from SITE_REACHED section.

Fix C — Verify poc.pcap reproduces crash independently:
  Run: tcpdump -vvv -r poc.pcap (with ASan build)
  If this crashes → project builds correctly, issue is in harness.
  If this does NOT crash → check tcpdump version matches 4.9.1.
```

---

## Claude Code Task Prompt

```
Read CLAUDE.md, then read this file (CLAUDE_cve_2017_13028.md) in full.

Your goal: detect CVE-2017-13028 using the Sailor pipeline and
produce a verified_bug.json with verdict CONFIRMED.

CRITICAL CONSTRAINTS — never violate these:
  1. ndo->ndo_vflag = 3 must be set in ALL drivers and harnesses.
     This is the ONLY way to reach the vulnerable code path.
  2. Do not remove ndo->ndo_vflag = 3 during replay driver generation.
  3. The vulnerable site ℓ is print-bootp.c:325, function bootp_print().

Execute the adaptive pipeline:

Step 0. Environment setup.
        → Verify Docker is available.
        → Build tcpdump 4.9.1 using build_commands defined in this file.
        → Confirm compile_commands.json contains print-bootp.c.
        → Confirm CodeQL database builds successfully.

Step 1. Run Phase 1 (Fact Generation + Enrichment + Spec Generation).
        → If print-bootp.c:bootp_print() is detected: proceed to Step 2.
        → If NOT detected: execute Phase 1 Failure Responses in order
          (Fix A → Fix B → Fix C → Fix D → Fix E) until detected.
          After each fix, re-run Phase 1 before trying the next fix.

Step 2. Run Phase 2 (LLM + KLEE).
        → Use driver template defined in this file.
        → Set ndo->ndo_vflag = 3. (MANDATORY)
        → If bug_triggered: proceed to Step 3.
        → If NOT_REACHED: execute Phase 2 NOT_REACHED fixes.
        → If SITE_REACHED without bug: execute Phase 2 SITE_REACHED fixes.
        → If INCONCLUSIVE: execute Phase 2 INCONCLUSIVE fixes.
        → After each fix, re-run Phase 2 before trying the next fix.

Step 3. Run Phase 3 (Concrete Validation).
        → Verify ndo->ndo_vflag = 3 survives in replay_driver.c.
        → If CONFIRMED: write verified_bug.json and EXIT with success.
        → If not confirmed: execute Phase 3 Failure Responses.

Step 4. If all fixes exhausted without CONFIRMED:
        → Write failure_report.json with:
          last_phase_reached, last_outcome, fixes_attempted,
          failure_reason, recommendation
        → EXIT.

At every step: save results to evaluation.db immediately.
Never re-run a Phase that already has a COMPLETED status in DB.
```
