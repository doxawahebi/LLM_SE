"""
End-to-End Self-Validation Test
=================================
Generates two deliberately vulnerable C programs, builds SARIF files that
simulate CodeQL output, runs the full HAST pipeline through LangGraph, and
asserts all four success criteria:

  1. The AI generates a harness from the SARIF warning (no manual intervention).
  2. Phase 2 (KLEE) produces a concrete PoC binary.
  3. Phase 3 injects that PoC into a separately compiled ASan binary.
  4. AddressSanitizer emits a verified crash dump.

Vulnerability catalog
---------------------
  CASE 1 — Stack-based buffer overflow (CWE-121)
    `stack_overflow.c` / `stack_overflow()`
    Copies a 64-byte symbolic input into a 16-byte stack buffer via `memcpy`.
    The overflow is unconditional and size-fixed, making it trivially reachable
    by KLEE without path explosion.

  CASE 2 — Heap buffer overflow (CWE-122)
    `heap_overflow.c` / `heap_write()`
    Allocates 8 bytes and writes 32 bytes into the allocation.
    KLEE can immediately detect the out-of-bounds write.

Each case is run as an independent pipeline invocation with its own thread_id
and evaluated against the strict success criteria.

Usage
-----
  python3 -m pytest tests/e2e_self_test.py -v
  # or directly:
  python3 tests/e2e_self_test.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
TEST_DIR = PROJECT_ROOT / "tests" / "e2e_workspace"

# Add project root so imports work when run directly
sys.path.insert(0, str(PROJECT_ROOT))

from core.workflow import pipeline_app
from langchain_core.runnables import RunnableConfig


# ===========================================================================
# Vulnerable target definitions
# ===========================================================================

@dataclass
class VulnCase:
    name: str
    filename: str
    source_code: str
    cwe_id: str
    vuln_line: int        # 1-indexed line number of the vulnerable statement
    description: str


VULN_CASES = [
    VulnCase(
        name="Stack Buffer Overflow",
        filename="stack_overflow.c",
        cwe_id="CWE-121",
        vuln_line=12,
        description="memcpy with fixed 64-byte source into 16-byte stack buffer",
        source_code=textwrap.dedent("""\
            #include <stdio.h>
            #include <string.h>
            #include <stdlib.h>

            /*
             * DELIBERATE VULNERABILITY: stack-based buffer overflow.
             * `buf` is 16 bytes; we copy INPUT_SIZE bytes unconditionally.
             */
            #define INPUT_SIZE 64

            void stack_overflow(const char *input) {
                char buf[16];
                memcpy(buf, input, INPUT_SIZE);   /* line 12 — overflow */
            }

            #ifndef HARNESS
            int main(void) {
                char input[INPUT_SIZE];
                /* read exactly INPUT_SIZE bytes from stdin for reproducibility */
                size_t n = 0;
                while (n < INPUT_SIZE) {
                    int c = getchar();
                    if (c == EOF) break;
                    input[n++] = (char)c;
                }
                stack_overflow(input);
                return 0;
            }
            #endif
        """),
    ),
    VulnCase(
        name="Heap Buffer Overflow",
        filename="heap_overflow.c",
        cwe_id="CWE-122",
        vuln_line=13,
        description="memcpy 32 bytes into an 8-byte heap allocation",
        source_code=textwrap.dedent("""\
            #include <stdio.h>
            #include <string.h>
            #include <stdlib.h>

            /*
             * DELIBERATE VULNERABILITY: heap buffer overflow.
             * Only 8 bytes are allocated; 32 bytes are written.
             */
            #define WRITE_SIZE 32

            void heap_write(const char *input) {
                char *heap_buf = (char *)malloc(8);
                if (!heap_buf) return;
                memcpy(heap_buf, input, WRITE_SIZE);  /* line 13 — overflow */
                free(heap_buf);
            }

            #ifndef HARNESS
            int main(void) {
                char input[WRITE_SIZE];
                size_t n = 0;
                while (n < WRITE_SIZE) {
                    int c = getchar();
                    if (c == EOF) break;
                    input[n++] = (char)c;
                }
                heap_write(input);
                return 0;
            }
            #endif
        """),
    ),
]


# ===========================================================================
# Test harness setup
# ===========================================================================

def _write_source(case: VulnCase, out_dir: Path) -> Path:
    src = out_dir / case.filename
    src.write_text(case.source_code)
    return src


def _make_sarif(case: VulnCase, src_path: Path, source_dir: Path) -> Path:
    rel = src_path.relative_to(source_dir)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "version": "2.17.0", "rules": []}},
            "results": [{
                "ruleId": case.cwe_id,
                "message": {"text": case.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(rel)},
                        "region": {
                            "startLine": case.vuln_line,
                            "endLine":   case.vuln_line,
                        },
                    }
                }],
            }],
        }],
    }
    sarif_path = source_dir / f"{case.filename}.sarif"
    sarif_path.write_text(json.dumps(sarif, indent=2))
    return sarif_path


def _compile_asan(src_path: Path) -> Path:
    """Compile with ASan + debug info. Returns binary path."""
    import shutil
    out = src_path.with_suffix(".asan")
    res = None
    for cc in (["clang"], ["gcc"]):
        if not shutil.which(cc[0]):
            continue
        res = subprocess.run(
            [*cc, "-fsanitize=address", "-g", "-O0",
             "-fno-omit-frame-pointer",
             str(src_path), "-o", str(out)],
            capture_output=True, text=True,
        )
        if res.returncode == 0:
            print(f"    ASan binary → {out.name} (via {cc[0]})")
            return out
    raise RuntimeError(
        f"Cannot compile ASan binary for {src_path.name}:\n"
        f"{res.stderr if res else 'no compiler found'}"
    )


def _compile_plain(src_path: Path) -> Path:
    """Compile a plain (non-ASan) binary for angr / sanity checks."""
    out = src_path.with_suffix("")
    res = subprocess.run(
        ["gcc", "-g", "-O0", str(src_path), "-o", str(out)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"Plain compile failed:\n{res.stderr}")
    return out


# ===========================================================================
# Pipeline runner
# ===========================================================================

MAX_HITL_LOOPS = 8   # safety cap against infinite HITL cycling

@dataclass
class RunResult:
    case_name: str
    thread_id: str
    passed: bool = False
    failure_reason: str = ""
    hitl_loops: int = 0
    poc_path: Optional[str] = None
    rca_summary: Optional[str] = None
    results: list = field(default_factory=list)


def run_case(case: VulnCase, source_dir: Path, sarif_path: Path, asan_binary: Path) -> RunResult:
    thread_id = f"e2e_{case.cwe_id.lower()}_{uuid.uuid4().hex[:6]}"
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    result = RunResult(case_name=case.name, thread_id=thread_id)

    inputs = {
        # ── Launch inputs ────────────────────────────────────────────────
        "sarif_path":   str(sarif_path),
        "source_dir":   str(source_dir),
        "target_binary": str(asan_binary),   # used by angr; KLEE ignores it
        "asan_binary":  str(asan_binary),    # pre-compiled ASan binary for Phase 3
        "engine":       "klee",
        "klee_whitebox": False,              # white-box mode OFF → avoids uClibc timeout
        "max_retries":  3,
        # ── Multi-finding state ──────────────────────────────────────────
        "findings":      None,
        "current_index": 0,
        "results":       [],
        # ── Per-finding working state ────────────────────────────────────
        "metadata":     None,
        "harness_code": None,
        "poc_path":     None,
        "rca_report":   None,
        "retry_count":  0,
        "skip_reason":  None,
        "status":       "started",
        "error_msg":    None,
    }

    print(f"  Streaming pipeline (thread={thread_id})...")
    for update in pipeline_app.stream(inputs, config=config, stream_mode="updates"):
        node = list(update.keys())[0]
        print(f"    → {node}")

    # ── HITL auto-resume loop ────────────────────────────────────────────
    while result.hitl_loops < MAX_HITL_LOOPS:
        state = pipeline_app.get_state(config)
        if not state.next:
            break
        if state.next[0] != "run_symbex":
            break

        result.hitl_loops += 1
        err = state.values.get("error_msg")
        print(f"  ⏸  HITL pause #{result.hitl_loops}  (error: {err[:80] if err else 'none'})")

        # Auto-resume without editing (LLM already corrected the harness if needed)
        for update in pipeline_app.stream(None, config=config, stream_mode="updates"):
            node = list(update.keys())[0]
            print(f"    → {node}")

    # ── Final state evaluation ───────────────────────────────────────────
    state = pipeline_app.get_state(config)
    vals  = state.values
    result.results = vals.get("results") or []

    # Look for a verified finding in the accumulated results list
    verified_entry = next((r for r in result.results if r.get("status") == "verified"), None)

    if verified_entry:
        result.passed      = True
        result.poc_path    = verified_entry.get("poc_path")
        result.rca_summary = verified_entry.get("rca_summary")
    else:
        # Collect diagnostics
        not_triggered = [r for r in result.results if r.get("status") == "not_triggered"]
        skipped       = [r for r in result.results if r.get("status") == "skipped"]

        if not result.results:
            result.failure_reason = (
                f"Pipeline status={vals.get('status')!r}  "
                f"error={vals.get('error_msg')!r}"
            )
        elif not_triggered:
            result.failure_reason = (
                f"ASan did not crash: {not_triggered[0].get('reason','')}"
            )
        elif skipped:
            result.failure_reason = (
                f"Skipped by engine: {skipped[0].get('reason','')}"
            )
        else:
            result.failure_reason = f"status={result.results[-1].get('status')}"

    return result


# ===========================================================================
# Assertion helpers
# ===========================================================================

def _assert_criterion(label: str, ok: bool, detail: str = ""):
    icon = "✓" if ok else "✗"
    print(f"    {icon}  Criterion: {label}")
    if not ok and detail:
        print(f"         Detail : {detail}")
    return ok


# ===========================================================================
# Main
# ===========================================================================

def main():
    print("=" * 70)
    print(" Antigravity HAST — End-to-End Self-Validation Test")
    print("=" * 70)

    TEST_DIR.mkdir(parents=True, exist_ok=True)

    overall_pass = True
    case_results: list[RunResult] = []

    for case in VULN_CASES:
        print(f"\n{'─'*60}")
        print(f" Case: {case.name}  ({case.cwe_id})")
        print(f"{'─'*60}")

        # ── Set up workspace ─────────────────────────────────────────────
        case_dir = TEST_DIR / case.cwe_id.lower().replace("-", "_")
        case_dir.mkdir(exist_ok=True)

        try:
            src_path   = _write_source(case, case_dir)
            sarif_path = _make_sarif(case, src_path, case_dir)
            asan_bin   = _compile_asan(src_path)
            _compile_plain(src_path)  # just to verify it builds at all
        except RuntimeError as e:
            print(f"  SETUP FAILED: {e}")
            overall_pass = False
            continue

        print(f"  Source  : {src_path.name}")
        print(f"  SARIF   : {sarif_path.name}")
        print(f"  ASan bin: {asan_bin.name}")

        # ── Run pipeline ─────────────────────────────────────────────────
        try:
            r = run_case(case, case_dir, sarif_path, asan_bin)
        except Exception as e:
            print(f"  PIPELINE EXCEPTION: {e}")
            traceback.print_exc()
            overall_pass = False
            continue

        case_results.append(r)

        # ── Evaluate four strict criteria ─────────────────────────────────
        print(f"\n  Results ({len(r.results)} finding(s) processed):")
        all_ok = True

        # Criterion 1: AI generated a harness (pipeline reached Phase 2 at least once)
        reached_symbex = r.hitl_loops > 0 or any(
            res.get("status") in ("verified", "not_triggered", "skipped")
            for res in r.results
        )
        all_ok &= _assert_criterion(
            "AI generated harness from SARIF",
            reached_symbex,
            "No HITL pause reached — harness generation may have failed",
        )

        # Criterion 2: Phase 2 produced a PoC (poc_path set)
        has_poc = bool(r.poc_path)
        all_ok &= _assert_criterion(
            "Phase 2 produced a concrete PoC input",
            has_poc,
            "poc_path is empty — KLEE may have returned UNSAT or timed out",
        )

        # Criterion 3: Phase 3 ran (results list non-empty)
        ran_phase3 = bool(r.results)
        all_ok &= _assert_criterion(
            "Phase 3 (ASan injection) executed",
            ran_phase3,
            "results list is empty — pipeline may have failed before verify node",
        )

        # Criterion 4: ASan crash confirmed
        all_ok &= _assert_criterion(
            "ASan crash dump confirmed (exploitability proved)",
            r.passed,
            r.failure_reason,
        )

        if all_ok:
            print(f"\n  ✅  PASS  — {case.name}")
            print(f"     RCA : {r.rca_summary}")
            print(f"     PoC : {r.poc_path}")
        else:
            print(f"\n  ❌  FAIL  — {case.name}")
            overall_pass = False

    # ── Final summary ────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    passed = sum(1 for r in case_results if r.passed)
    total  = len(VULN_CASES)
    print(f" SUMMARY: {passed} / {total} cases passed")
    for r in case_results:
        icon = "✅" if r.passed else "❌"
        print(f"  {icon}  {r.case_name:40s}  loops={r.hitl_loops}")
    print("=" * 70)

    if not overall_pass:
        sys.exit(1)
    print("\n🎉  All self-validation criteria satisfied.\n")


if __name__ == "__main__":
    main()
