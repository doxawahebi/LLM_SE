"""
LangGraph Pipeline Orchestrator — Multi-Finding Edition
========================================================
Flow
----
  phase1
    ↓  (all findings loaded into state)
  process_next_finding          ← router: advance index or finish
    ↓
  generate_harness              ← LLM generates / self-corrects harness
    ↓  [HITL interrupt here]
  run_symbex                    ← KLEE or angr execution
    ↓
  verify                        ← ASan verification
    ↓
  process_next_finding          ← loop back for next finding

UNSAT / Timeout handling
------------------------
When `run_symbex_node` raises an "UNSAT" or "Timeout" error it does NOT
enter the auto-correction loop.  Instead it records the skipped finding
with a reason code in `results` and routes directly back to
`process_next_finding` so the remaining findings are still processed.

Persistence
-----------
Full state (including the `results` list accumulated across all findings)
is persisted in Redis via RedisSaver, so HITL pauses survive restarts.
"""

import os
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.redis import RedisSaver
from redis import Redis

from phases.phase1_parser import parse_all_findings
from phases.phase3_verifier import verify_vulnerability


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class FindingResult(TypedDict):
    """Logged record for one processed vulnerability finding."""
    index: int
    file_path: str
    function_name: str
    cwe_id: str
    status: str       # 'verified' | 'not_triggered' | 'skipped' | 'failed'
    reason: str       # human-readable detail
    poc_path: Optional[str]
    rca_summary: Optional[str]


class AgentState(TypedDict):
    # ── Launch-time inputs ────────────────────────────────────────────────
    sarif_path: str
    source_dir: str
    target_binary: str
    engine: str           # 'angr' | 'klee'
    klee_whitebox: bool   # toggles --libc=uclibc --posix-runtime
    max_retries: int      # per-finding LLM correction attempts
    asan_binary: Optional[str]  # pre-compiled ASan binary (skips verifier compile step)

    # ── Multi-finding iteration ───────────────────────────────────────────
    findings: Optional[list]    # all parsed findings (set by phase1)
    current_index: int          # index of the finding being processed now
    results: Optional[list]     # accumulated FindingResult records

    # ── Per-finding working state (reset each iteration) ──────────────────
    metadata: Optional[dict]
    harness_code: Optional[str]
    poc_path: Optional[str]
    rca_report: Optional[dict]
    retry_count: int
    skip_reason: Optional[str]  # set when UNSAT/Timeout forces a skip

    # ── Pipeline bookkeeping ──────────────────────────────────────────────
    status: str
    error_msg: Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_per_finding(extra: dict = None) -> dict:
    """Return a state patch that clears all per-finding working variables."""
    patch = {
        "metadata": None,
        "harness_code": None,
        "poc_path": None,
        "rca_report": None,
        "retry_count": 0,
        "skip_reason": None,
        "error_msg": None,
    }
    if extra:
        patch.update(extra)
    return patch


# ---------------------------------------------------------------------------
# Node: Phase 1 — parse all SARIF findings
# ---------------------------------------------------------------------------

def phase1_node(state: AgentState):
    print("Executing Phase 1 — parsing all SARIF findings...")
    try:
        findings = parse_all_findings(state["sarif_path"], state["source_dir"])
        if not findings:
            return {"status": "failed", "error_msg": "No parseable findings in SARIF file."}
        print(f"  Found {len(findings)} vulnerability finding(s).")
        return {
            "findings": findings,
            "current_index": 0,
            "results": [],
            "status": "phase1_completed",
            "error_msg": None,
        }
    except Exception as e:
        return {"status": "failed", "error_msg": str(e)}


# ---------------------------------------------------------------------------
# Node: Advance to the next finding (or finish)
# ---------------------------------------------------------------------------

def process_next_finding_node(state: AgentState):
    """
    Advance `current_index` to the next finding.  If the previous finding was
    skipped or failed, record it in `results` first.

    This node intentionally has *no* side-effects other than updating the
    index and working-state variables.
    """
    findings     = state.get("findings", [])
    idx          = state.get("current_index", 0)
    results      = list(state.get("results") or [])
    skip_reason  = state.get("skip_reason")

    # ── Record the outcome of the finding that just finished ──────────────
    # (The verify node records 'verified'/'not_triggered'; we only need to
    #  record skipped/failed outcomes that never reached verify.)
    if skip_reason and idx < len(findings):
        meta = findings[idx]
        results.append(FindingResult(
            index=idx,
            file_path=meta["file_path"],
            function_name=meta["function_name"],
            cwe_id=meta["cwe_id"],
            status="skipped",
            reason=skip_reason,
            poc_path=None,
            rca_summary=None,
        ))
        print(
            f"  [Finding {idx+1}/{len(findings)}] SKIPPED — {skip_reason}"
        )

    # ── Advance index ─────────────────────────────────────────────────────
    next_idx = idx + (1 if skip_reason else 0)
    # (If we arrived here from verify, the index was already current; we
    #  just need to move past it.)
    # Normalise: always move at least one step forward from the current idx
    # unless this is the very first call (idx == 0, no skip, no verify done).
    # We use status to detect "arrived from verify vs. arrived from skip":
    if state.get("status") in ("verified", "not_triggered"):
        next_idx = idx + 1

    if next_idx >= len(findings):
        # All findings processed
        return {**_reset_per_finding(), "current_index": next_idx, "results": results, "status": "all_done"}

    meta = findings[next_idx]
    print(
        f"  [Finding {next_idx+1}/{len(findings)}] Processing: "
        f"{meta['function_name']} in {meta['file_path']} ({meta['cwe_id']})"
    )
    return {
        **_reset_per_finding({"metadata": meta, "current_index": next_idx}),
        "results": results,
        "status": "finding_ready",
    }


# ---------------------------------------------------------------------------
# Node: Generate / correct harness via LLM
# ---------------------------------------------------------------------------

def generate_harness_node(state: AgentState):
    from phases.phase2_symbex import generate_harness_code

    prior_error = state.get("error_msg")
    prior_code  = state.get("harness_code")

    if prior_code and not prior_error:
        print("  Using existing harness (no error to correct).")
        return {"status": "harness_ready", "error_msg": None}

    retry = state.get("retry_count", 0)
    print(f"  Generating harness (attempt {retry + 1})...")
    try:
        code = generate_harness_code(
            metadata=state["metadata"],
            target_binary=state["target_binary"],
            engine=state.get("engine", "angr"),
            prior_error=prior_error,
            prior_code=prior_code,
        )
        return {"harness_code": code, "status": "harness_generated", "error_msg": None}
    except Exception as e:
        return {"status": "failed", "error_msg": str(e)}


# ---------------------------------------------------------------------------
# Node: Run symbolic execution
# ---------------------------------------------------------------------------

def run_symbex_node(state: AgentState):
    from phases.phase2_symbex import run_harness
    print("  Running symbolic execution...")

    try:
        poc_path = run_harness(
            code=state["harness_code"],
            engine=state.get("engine", "angr"),
            klee_whitebox=state.get("klee_whitebox", True),
        )
        return {"poc_path": poc_path, "status": "symbex_completed", "error_msg": None}

    except RuntimeError as e:
        error_msg = str(e)

        # ── Graceful UNSAT / Timeout skip ─────────────────────────────────
        # These are not code bugs — the path is genuinely unreachable or the
        # state space is too large.  We log the finding and move on.
        _lower = error_msg.lower()
        if "unsat" in _lower:
            reason = f"UNSAT: Path Unreachable — {error_msg[:200]}"
            print(f"  ⚠ {reason}")
            return {"status": "skip_finding", "skip_reason": reason, "error_msg": error_msg}

        if "timeout" in _lower or "state explosion" in _lower or "halttimer" in _lower:
            reason = f"Timeout: State Explosion — {error_msg[:200]}"
            print(f"  ⚠ {reason}")
            return {"status": "skip_finding", "skip_reason": reason, "error_msg": error_msg}

        # ── Auto-correction loop ──────────────────────────────────────────
        max_retries = state.get("max_retries", 3)
        retry_count = state.get("retry_count", 0)
        if retry_count < max_retries:
            print(f"  Compilation/execution failed — will retry ({retry_count+1}/{max_retries})")
            return {
                "status": "compilation_failed",
                "error_msg": error_msg,
                "retry_count": retry_count + 1,
                "poc_path": None,
            }

        # Max retries exhausted — skip this finding
        reason = f"Max retries ({max_retries}) exceeded: {error_msg[:200]}"
        print(f"  ✗ {reason}")
        return {"status": "skip_finding", "skip_reason": reason, "error_msg": error_msg}


# ---------------------------------------------------------------------------
# Node: Phase 3 — ASan verification
# ---------------------------------------------------------------------------

def verify_node(state: AgentState):
    print("  Running Phase 3 ASan verifier...")
    findings = state.get("findings", [])
    idx      = state.get("current_index", 0)
    results  = list(state.get("results") or [])
    meta     = state.get("metadata", {})

    if not state.get("poc_path"):
        results.append(FindingResult(
            index=idx,
            file_path=meta.get("file_path", ""),
            function_name=meta.get("function_name", ""),
            cwe_id=meta.get("cwe_id", ""),
            status="failed",
            reason="No PoC path for verification",
            poc_path=None,
            rca_summary=None,
        ))
        return {"status": "not_triggered", "results": results,
                "error_msg": "No PoC path available"}

    try:
        rca_report = verify_vulnerability(
            meta.get("file_path", state["source_dir"]),
            state["poc_path"],
            asan_binary=state.get("asan_binary"),
        )
        verified   = rca_report.get("verified", False)
        rca_sum    = rca_report.get("rca_summary", "")

        entry_status = "verified" if verified else "not_triggered"
        reason = rca_sum if verified else "No AddressSanitizer error triggered"

        print(
            f"  [Finding {idx+1}/{len(findings)}] "
            f"{'✓ VERIFIED' if verified else '○ NOT triggered'}: {reason}"
        )
        results.append(FindingResult(
            index=idx,
            file_path=meta.get("file_path", ""),
            function_name=meta.get("function_name", ""),
            cwe_id=meta.get("cwe_id", ""),
            status=entry_status,
            reason=reason,
            poc_path=state.get("poc_path"),
            rca_summary=rca_sum,
        ))
        return {
            "rca_report": rca_report,
            "status": entry_status,
            "results": results,
            "error_msg": None,
        }
    except Exception as e:
        results.append(FindingResult(
            index=idx,
            file_path=meta.get("file_path", ""),
            function_name=meta.get("function_name", ""),
            cwe_id=meta.get("cwe_id", ""),
            status="failed",
            reason=str(e),
            poc_path=None,
            rca_summary=None,
        ))
        return {"status": "not_triggered", "results": results, "error_msg": str(e)}


# ---------------------------------------------------------------------------
# Routing conditions
# ---------------------------------------------------------------------------

def _after_phase1(state: AgentState):
    return END if state["status"] == "failed" else "process_next_finding"


def _after_process_next(state: AgentState):
    if state["status"] == "all_done":
        return END
    return "generate_harness"


def _after_harness(state: AgentState):
    return END if state["status"] == "failed" else "run_symbex"


def _after_symbex(state: AgentState):
    s = state["status"]
    if s == "skip_finding":
        # UNSAT / Timeout / max-retries: log and move to next finding
        return "process_next_finding"
    if s == "compilation_failed":
        # Auto-correction: regenerate harness with error context
        return "generate_harness"
    if s == "failed":
        return END
    return "verify"


def _after_verify(state: AgentState):
    # Always continue to next finding regardless of verify outcome
    return "process_next_finding"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("phase1",               phase1_node)
    workflow.add_node("process_next_finding", process_next_finding_node)
    workflow.add_node("generate_harness",     generate_harness_node)
    workflow.add_node("run_symbex",           run_symbex_node)
    workflow.add_node("verify",               verify_node)

    workflow.add_edge(START, "phase1")
    workflow.add_conditional_edges("phase1",               _after_phase1)
    workflow.add_conditional_edges("process_next_finding", _after_process_next)
    workflow.add_conditional_edges("generate_harness",     _after_harness)
    workflow.add_conditional_edges("run_symbex",           _after_symbex)
    workflow.add_conditional_edges("verify",               _after_verify)

    # Redis checkpointer — requires redis/redis-stack-server for FT.SEARCH
    redis_url    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    connection   = Redis.from_url(redis_url)
    checkpointer = RedisSaver(redis_client=connection)
    checkpointer.setup()

    return workflow.compile(
        checkpointer=checkpointer,
        # Pause before executing so the user can inspect / edit the harness
        interrupt_before=["run_symbex"],
    )


pipeline_app = build_graph()
