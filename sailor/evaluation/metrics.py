"""MetricsCalculator — compute evaluation metrics from DB results."""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel

from sailor.models.schemas import CVEEvaluationResult, EvaluationVerdict
from sailor.evaluation.db import EvaluationDB

logger = logging.getLogger("sailor.evaluation.metrics")


class EvaluationMetrics(BaseModel):
    """Aggregate evaluation metrics across all CVEs and runs.

    Attributes:
        total_cves: Number of distinct CVEs evaluated.
        total_runs: Total number of evaluation runs.
        true_positives: Runs ending with TRUE_POSITIVE verdict.
        false_negatives: Runs ending with FALSE_NEGATIVE verdict.
        false_positives: Runs ending with FALSE_POSITIVE verdict.
        partials: Runs ending with PARTIAL verdict.
        recall: TP / (TP + FN).
        precision: TP / (TP + FP).
        phase1_detection_rate: Fraction of CVEs where Phase 1 detected the spec.
        phase2_trigger_rate: Fraction of Phase 1 hits that triggered a bug.
        phase3_confirm_rate: Fraction of triggered bugs confirmed by ASan.
        failure_reason_counts: Count per failure reason string.
        avg_phase2_turns: Average LLM turns used in Phase 2.
        avg_total_duration_sec: Average total wall-clock seconds per run.
        total_llm_calls: Sum of LLM calls across all runs.
        total_estimated_tokens: Sum of estimated tokens across all runs.
        total_estimated_cost_usd: Sum of estimated USD cost across all runs.
        avg_cost_per_cve_usd: Average USD cost per distinct CVE.
    """

    total_cves: int
    total_runs: int
    true_positives: int
    false_negatives: int
    false_positives: int
    partials: int
    recall: float
    precision: float
    phase1_detection_rate: float
    phase2_trigger_rate: float
    phase3_confirm_rate: float
    failure_reason_counts: dict[str, int]
    avg_phase2_turns: float
    avg_total_duration_sec: float
    total_llm_calls: int
    total_estimated_tokens: int
    total_estimated_cost_usd: float
    avg_cost_per_cve_usd: float


class CVEMetrics(BaseModel):
    """Per-CVE metrics aggregated across all runs.

    Attributes:
        cve_id: The CVE identifier.
        total_runs: Number of evaluation runs for this CVE.
        success_count: Number of runs ending in TRUE_POSITIVE.
        success_rate: success_count / total_runs.
        best_verdict: Best verdict achieved across all runs.
        failure_reasons: Failure reason strings across failed runs.
        avg_phase2_turns: Average LLM turns per run.
        avg_cost_usd: Average USD cost per run.
    """

    cve_id: str
    total_runs: int
    success_count: int
    success_rate: float
    best_verdict: Optional[EvaluationVerdict]
    failure_reasons: list[str]
    avg_phase2_turns: float
    avg_cost_usd: float


class MetricsCalculator:
    """Computes evaluation metrics from DB results.

    Args:
        db: Initialised :class:`EvaluationDB` instance.
    """

    def __init__(self, db: EvaluationDB) -> None:
        self._db = db

    def compute(
        self, cve_ids: Optional[list[str]] = None
    ) -> EvaluationMetrics:
        """Compute all metrics from DB.

        Args:
            cve_ids: Filter to these CVE IDs. None means all CVEs.

        Returns:
            Populated :class:`EvaluationMetrics`.
        """
        all_results = self._db.list_evaluations()
        if cve_ids is not None:
            id_set = set(cve_ids)
            all_results = [r for r in all_results if r.cve_id in id_set]

        distinct_cves = set(r.cve_id for r in all_results)
        total_cves = len(distinct_cves)
        total_runs = len(all_results)

        tp = sum(1 for r in all_results if r.verdict == EvaluationVerdict.TRUE_POSITIVE)
        fn = sum(1 for r in all_results if r.verdict == EvaluationVerdict.FALSE_NEGATIVE)
        fp = sum(1 for r in all_results if r.verdict == EvaluationVerdict.FALSE_POSITIVE)
        partial = sum(1 for r in all_results if r.verdict == EvaluationVerdict.PARTIAL)

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        p1_detected = sum(1 for r in all_results if r.phase1_detected)
        p2_triggered = sum(1 for r in all_results if r.phase2_triggered)
        p3_confirmed = sum(1 for r in all_results if r.phase3_confirmed)

        p1_rate = p1_detected / total_runs if total_runs > 0 else 0.0
        p2_rate = p2_triggered / p1_detected if p1_detected > 0 else 0.0
        p3_rate = p3_confirmed / p2_triggered if p2_triggered > 0 else 0.0

        failure_counts: dict[str, int] = {}
        for r in all_results:
            if r.failure_reason:
                key = r.failure_reason.value
                failure_counts[key] = failure_counts.get(key, 0) + 1

        turns = [r.phase2_turns_used for r in all_results]
        durations = [r.total_duration_sec for r in all_results]
        costs = [r.estimated_cost_usd for r in all_results]
        tokens = [r.estimated_tokens_used for r in all_results]
        llm_calls = [r.llm_calls for r in all_results]

        avg_turns = sum(turns) / len(turns) if turns else 0.0
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        total_cost = sum(costs)
        avg_cost_per_cve = total_cost / total_cves if total_cves > 0 else 0.0

        return EvaluationMetrics(
            total_cves=total_cves,
            total_runs=total_runs,
            true_positives=tp,
            false_negatives=fn,
            false_positives=fp,
            partials=partial,
            recall=round(recall, 4),
            precision=round(precision, 4),
            phase1_detection_rate=round(p1_rate, 4),
            phase2_trigger_rate=round(p2_rate, 4),
            phase3_confirm_rate=round(p3_rate, 4),
            failure_reason_counts=failure_counts,
            avg_phase2_turns=round(avg_turns, 2),
            avg_total_duration_sec=round(avg_duration, 2),
            total_llm_calls=sum(llm_calls),
            total_estimated_tokens=sum(tokens),
            total_estimated_cost_usd=round(total_cost, 4),
            avg_cost_per_cve_usd=round(avg_cost_per_cve, 4),
        )

    def compute_for_cve(self, cve_id: str) -> CVEMetrics:
        """Per-CVE metrics across all runs.

        Args:
            cve_id: The CVE to compute metrics for.

        Returns:
            Populated :class:`CVEMetrics`.
        """
        runs = self._db.list_evaluations(cve_id=cve_id)
        total = len(runs)
        success = sum(1 for r in runs if r.verdict == EvaluationVerdict.TRUE_POSITIVE)
        success_rate = success / total if total > 0 else 0.0

        best: Optional[EvaluationVerdict] = None
        verdict_rank = {
            EvaluationVerdict.TRUE_POSITIVE: 0,
            EvaluationVerdict.PARTIAL: 1,
            EvaluationVerdict.FALSE_POSITIVE: 2,
            EvaluationVerdict.FALSE_NEGATIVE: 3,
        }
        for r in runs:
            if r.verdict is not None:
                if best is None or verdict_rank.get(r.verdict, 99) < verdict_rank.get(best, 99):
                    best = r.verdict

        failure_reasons = [
            r.failure_reason.value for r in runs if r.failure_reason
        ]
        turns = [r.phase2_turns_used for r in runs]
        costs = [r.estimated_cost_usd for r in runs]

        return CVEMetrics(
            cve_id=cve_id,
            total_runs=total,
            success_count=success,
            success_rate=round(success_rate, 4),
            best_verdict=best,
            failure_reasons=failure_reasons,
            avg_phase2_turns=round(sum(turns) / len(turns), 2) if turns else 0.0,
            avg_cost_usd=round(sum(costs) / len(costs), 4) if costs else 0.0,
        )
