#!/usr/bin/env python3
"""
Regenerate the canonical SSE JSON examples in
shared/contracts/examples/sse/ from the Pydantic models.

These examples are used by:
  - sse_contract.md (embeds them as illustrations)
  - scripts/check_sse_contract.py (CI check for drift)
  - Frontend conformance tests (fixtures)
  - Backend conformance tests (fixtures)

If you edit this file, also update sse_contract.md's embedded blocks
to match (or run scripts/check_sse_contract.py and copy the diffs).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = REPO_ROOT / "shared" / "contracts"
EXAMPLES_DIR = CONTRACTS_DIR / "examples" / "sse"

sys.path.insert(0, str(CONTRACTS_DIR))
import sailor_models as m  # type: ignore  # noqa: E402


def main() -> int:
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    examples: dict[str, dict] = {}

    examples["run_status_changed"] = m.SSEMessageRunStatusChanged(
        topic="runs.r_42",
        sequence=128,
        timestamp="2026-05-25T09:30:14.521Z",
        kind="run_status_changed",
        payload=m.RunStatusChangedPayload(
            run_id="r_42",
            status=m.RunStatus.running,
            previous_status=m.RunStatus.queued,
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["run_counters_updated"] = m.SSEMessageRunCountersUpdated(
        topic="runs.r_42",
        sequence=129,
        timestamp="2026-05-25T09:30:15.001Z",
        kind="run_counters_updated",
        payload=m.RunCountersUpdatedPayload(
            run_id="r_42",
            counters=m.RunCounters(
                specs_total=1260, specs_filtered_out=8, specs_emitted=1252,
                specs_phase2_queued=994, specs_phase2_running=128,
                specs_phase2_bug_triggered=42, specs_phase2_inconclusive=58,
                specs_phase2_likely_fp=27, specs_phase2_errored=3,
                specs_phase3_queued=10, specs_phase3_confirmed=18,
                specs_phase3_rejected=14, specs_phase3_errored=0,
                unique_confirmed=15, total_llm_tokens=8420000,
                total_klee_seconds=14200,
            ),
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["spec_state_changed"] = m.SSEMessageSpecStateChanged(
        topic="runs.r_42.specs.s_001",
        sequence=130,
        timestamp="2026-05-25T09:30:16.117Z",
        kind="spec_state_changed",
        payload=m.SpecStateChangedPayload(
            spec=m.Spec(
                spec_id="s_001",
                run_id="r_42",
                rule_id="local/cpp/cwe-122-heap-overflow",
                cwe="CWE-122",
                file="bfd/elfxx-x86.c",
                line=2286,
                func="elf_x86_link_hash_table",
                message="Potential heap buffer overflow at memcpy site",
                phase1_status=m.Phase1Status.emitted,
                phase2_status=m.Phase2Status.bug_triggered,
                current_turn=24,
                turn_count_total=24,
                refine_count=3,
                phase2_outcome=m.Phase2Outcome.bug_triggered,
                artifacts_root="runs/r_42/phase2/s_001/",
                created_at="2026-05-25T09:00:00Z",
                last_event_at="2026-05-25T09:30:16.117Z",
                token_cost=47200,
                intervention_pending=False,
            )
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["spec_intervention_applied"] = m.SSEMessageSpecInterventionApplied(
        topic="runs.r_42.specs.s_001",
        sequence=131,
        timestamp="2026-05-25T09:30:17.401Z",
        kind="spec_intervention_applied",
        payload=m.SpecInterventionAppliedPayload(
            spec_id="s_001",
            intervention_type="edit_harness",
            applied_at="2026-05-25T09:30:17.380Z",
            actor="u_alice",
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["turn_appended"] = m.SSEMessageTurnAppended(
        topic="runs.r_42.specs.s_001",
        sequence=132,
        timestamp="2026-05-25T09:30:18.005Z",
        kind="turn_appended",
        payload=m.TurnAppendedPayload(
            turn=m.Turn(
                turn_id="t_5731",
                spec_id="s_001",
                turn_number=24,
                kind=m.TurnKind.klee_run,
                started_at="2026-05-25T09:30:00Z",
                ended_at="2026-05-25T09:30:18Z",
                duration_ms=18000,
                payload_ref="runs/r_42/phase2/s_001/turns/24.json",
                summary="KLEE: bug_triggered after 18s (heap-buffer-overflow at line 2286)",
                tokens_consumed=0,
                klee_seconds=18,
            )
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["worker_heartbeat"] = m.SSEMessageWorkerHeartbeat(
        topic="runs.r_42.workers",
        sequence=133,
        timestamp="2026-05-25T09:30:18.500Z",
        kind="worker_heartbeat",
        payload=m.WorkerHeartbeatPayload(
            worker_id="celery@worker-7",
            status="busy",
            current_spec_id="s_001",
            last_heartbeat="2026-05-25T09:30:18.500Z",
            throughput_specs_per_min=2.4,
            tokens_per_min=8200.0,
            klee_seconds_per_min=42.0,
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["log_line"] = m.SSEMessageLogLine(
        topic="runs.r_42.logs",
        sequence=134,
        timestamp="2026-05-25T09:30:19.220Z",
        kind="log_line",
        payload=m.LogLinePayload(
            timestamp="2026-05-25T09:30:19.220Z",
            level="info",
            source="phase2",
            run_id="r_42",
            spec_id="s_001",
            worker_id="celery@worker-7",
            trace_id="trc_8a1f9c",
            message="KLEE search strategy=random-path; depth=347",
            fields={"strategy": "random-path", "depth": 347},
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["resync_required"] = m.SSEMessageResyncRequired(
        topic="runs.r_42.specs",
        sequence=200,
        timestamp="2026-05-25T09:31:00.000Z",
        kind="resync_required",
        payload=m.ResyncRequiredPayload(
            reason="buffer_overflow",
            last_known_sequence=99,
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["interrupt_created"] = m.SSEMessageInterruptCreated(
        topic="runs.r_42",
        sequence=135,
        timestamp="2026-05-25T09:30:20.001Z",
        kind="interrupt_created",
        payload=m.InterruptCreatedPayload(
            interrupt=m.InterruptPoint(
                interrupt_id="i_88",
                run_id="r_42",
                spec_id="s_001",
                function_name=m.PipelineFunctionId.phase2_klee_execution,
                scope=m.InterruptScope.spec,
                turn=24,
                status=m.InterruptStatus.waiting,
                created_at="2026-05-25T09:30:20.000Z",
                input_files=[
                    m.InterruptInputFile(
                        name="harness.bc",
                        artifact_ref="runs/r_42/phase2/s_001/bitcode/harness.v3.bc",
                        size_bytes=48211,
                        mime_type="application/octet-stream",
                        editable=False,
                        version=3,
                    )
                ],
                option_overrides={
                    "klee_search_strategies": ["random-path"],
                    "klee_timeout_seconds": 300,
                    "klee_max_depth": 1000,
                },
            )
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["interrupt_resolved"] = m.SSEMessageInterruptResolved(
        topic="runs.r_42",
        sequence=140,
        timestamp="2026-05-25T09:32:11.500Z",
        kind="interrupt_resolved",
        payload=m.InterruptResolvedPayload(
            interrupt_id="i_88",
            run_id="r_42",
            spec_id="s_001",
            resolution="resumed",
            resolved_by="u_alice",
        ),
    ).model_dump(mode="json", exclude_none=True)

    examples["auto_config_changed"] = m.SSEMessageAutoConfigChanged(
        topic="runs.r_42",
        sequence=141,
        timestamp="2026-05-25T09:32:12.000Z",
        kind="auto_config_changed",
        payload=m.AutoConfigChangedPayload(
            run_id="r_42",
            auto_config=m.AutoConfig(
                phase2_klee_execution=False,
                phase3_result_classification=False,
            ),
            changed_by="u_alice",
        ),
    ).model_dump(mode="json", exclude_none=True)

    # Batch (two consecutive messages on one topic)
    batch = m.SSEBatch(
        topic="runs.r_42.specs.s_001",
        sequence=132,
        batch=[
            m.SSEMessageSpecStateChanged(**examples["spec_state_changed"]),
            m.SSEMessageTurnAppended(**examples["turn_appended"]),
        ],
    ).model_dump(mode="json", exclude_none=True)

    # Write files
    for kind, ex in examples.items():
        path = EXAMPLES_DIR / f"{kind}.json"
        path.write_text(json.dumps(ex, indent=2) + "\n")
        print(f"  Wrote {path.relative_to(REPO_ROOT)}")

    batch_path = EXAMPLES_DIR / "batch.json"
    batch_path.write_text(json.dumps(batch, indent=2) + "\n")
    print(f"  Wrote {batch_path.relative_to(REPO_ROOT)}")

    print(f"\nGenerated {len(examples) + 1} fixture files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
