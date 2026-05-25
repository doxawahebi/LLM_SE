"""ReportGenerator — human-readable and machine-readable evaluation reports."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from sailor.models.schemas import CVEEvaluationResult, EvaluationVerdict, PhaseStatus
from sailor.evaluation.db import EvaluationDB
from sailor.evaluation.metrics import EvaluationMetrics, MetricsCalculator

logger = logging.getLogger("sailor.evaluation.report")

_STATUS_EMOJI = {
    PhaseStatus.COMPLETED: "✅",
    PhaseStatus.FAILED: "❌",
    PhaseStatus.SKIPPED: "⏭",
    PhaseStatus.RUNNING: "⏳",
    PhaseStatus.PENDING: "⬜",
}

_VERDICT_SHORT = {
    EvaluationVerdict.TRUE_POSITIVE: "TP",
    EvaluationVerdict.FALSE_NEGATIVE: "FN",
    EvaluationVerdict.FALSE_POSITIVE: "FP",
    EvaluationVerdict.PARTIAL: "P",
}

_FAILURE_SUGGESTIONS: dict[str, str] = {
    "query_missed": "Add a custom CodeQL query for this vulnerability pattern.",
    "filtered_out": "Review skip patterns in Phase 1 SpecificationGenerator.",
    "build_failed": "Check Docker build environment and dependency list.",
    "structural_miss": "Vulnerability uses macro or function-pointer indirection.",
    "inconclusive": "Increase T_max or improve harness initialisation rules.",
    "likely_false_positive": "Lower R_max or tighten spec filtering in Phase 1.",
    "harness_compile_error": "Review stub synthesis for missing prototypes.",
    "se_not_reached": "Verify entrypoint and guard-condition negation logic.",
    "asan_not_confirmed": "Check ASan toolchain and replay driver generation.",
    "asan_wrong_location": "Crash at different site — review ground-truth mapping.",
    "docker_error": "Verify Docker daemon and image availability.",
    "timeout": "Increase phase_timeout_sec in EvaluationConfig.",
    "unknown": "Inspect logs for unclassified error.",
}


class ReportGenerator:
    """Generates human-readable and machine-readable evaluation reports.

    Args:
        db: Initialised :class:`EvaluationDB` instance.
        output_dir: Directory where reports are written.
    """

    def __init__(self, db: EvaluationDB, output_dir: Path) -> None:
        self._db = db
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._metrics_calc = MetricsCalculator(db)

    def generate(
        self, cve_ids: Optional[list[str]] = None
    ) -> Path:
        """Generate evaluation_report.md.

        Sections:
            1. Summary table (per run: verdict, phase statuses, cost).
            2. Phase-level metrics.
            3. Failure analysis breakdown.
            4. Token / cost summary.
            5. Per-CVE detail sections.

        Args:
            cve_ids: Filter to these CVE IDs. None means all CVEs.

        Returns:
            Path to the written report file.
        """
        results = self._db.list_evaluations()
        if cve_ids is not None:
            id_set = set(cve_ids)
            results = [r for r in results if r.cve_id in id_set]

        metrics = self._metrics_calc.compute(cve_ids)

        lines: list[str] = []
        lines.append("# Sailor Evaluation Report\n")

        lines.append("## Summary Table\n")
        lines.append(self._format_summary_table(results))
        lines.append("")

        lines.append("## Phase-Level Metrics\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total CVEs | {metrics.total_cves} |")
        lines.append(f"| Total Runs | {metrics.total_runs} |")
        lines.append(f"| True Positives | {metrics.true_positives} |")
        lines.append(f"| False Negatives | {metrics.false_negatives} |")
        lines.append(f"| False Positives | {metrics.false_positives} |")
        lines.append(f"| Partials | {metrics.partials} |")
        lines.append(f"| Recall | {metrics.recall:.4f} |")
        lines.append(f"| Precision | {metrics.precision:.4f} |")
        lines.append(f"| Phase 1 Detection Rate | {metrics.phase1_detection_rate:.4f} |")
        lines.append(f"| Phase 2 Trigger Rate | {metrics.phase2_trigger_rate:.4f} |")
        lines.append(f"| Phase 3 Confirm Rate | {metrics.phase3_confirm_rate:.4f} |")
        lines.append("")

        lines.append("## Failure Analysis\n")
        lines.append(self._format_failure_analysis(results))
        lines.append("")

        lines.append("## Token / Cost Summary\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total LLM Calls | {metrics.total_llm_calls} |")
        lines.append(f"| Total Tokens (est.) | {metrics.total_estimated_tokens:,} |")
        lines.append(f"| Total Cost (est.) | ${metrics.total_estimated_cost_usd:.4f} |")
        lines.append(f"| Avg Cost / CVE | ${metrics.avg_cost_per_cve_usd:.4f} |")
        lines.append(f"| Avg Phase 2 Turns | {metrics.avg_phase2_turns:.1f} |")
        lines.append(f"| Avg Duration / Run | {metrics.avg_total_duration_sec:.1f}s |")
        lines.append("")

        lines.append("## Per-CVE Details\n")
        for cve_id in sorted(set(r.cve_id for r in results)):
            cve_runs = [r for r in results if r.cve_id == cve_id]
            lines.append(f"### {cve_id}\n")
            for run in sorted(cve_runs, key=lambda r: r.run_number):
                lines.append(self._format_run_detail(run))
            lines.append("")

        report_path = self._output_dir / "evaluation_report.md"
        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Wrote report → %s", report_path)
        return report_path

    def generate_json(
        self, cve_ids: Optional[list[str]] = None
    ) -> Path:
        """Write evaluation_report.json with full EvaluationMetrics.

        Args:
            cve_ids: Filter to these CVE IDs. None means all CVEs.

        Returns:
            Path to the written JSON file.
        """
        metrics = self._metrics_calc.compute(cve_ids)
        out = self._output_dir / "evaluation_report.json"
        out.write_text(
            json.dumps(metrics.model_dump(), indent=2),
            encoding="utf-8",
        )
        logger.info("Wrote metrics JSON → %s", out)
        return out

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def _format_summary_table(
        self, results: list[CVEEvaluationResult]
    ) -> str:
        """Markdown table: CVE ID | Phase1 | Phase2 | Phase3 | Verdict | Turns | Cost."""
        header = "| CVE ID | Run | Phase1 | Phase2 | Phase3 | Verdict | Turns | Cost |"
        sep = "|--------|-----|--------|--------|--------|---------|-------|------|"
        rows = [header, sep]
        for r in sorted(results, key=lambda x: (x.cve_id, x.run_number)):
            p1 = _STATUS_EMOJI.get(r.phase1_status, "?")
            p2 = _STATUS_EMOJI.get(r.phase2_status, "?")
            p3 = _STATUS_EMOJI.get(r.phase3_status, "?")
            verdict = _VERDICT_SHORT.get(r.verdict, "-") if r.verdict else "-"
            cost = f"${r.estimated_cost_usd:.4f}"
            rows.append(
                f"| {r.cve_id} | {r.run_number} | {p1} | {p2} | {p3} "
                f"| {verdict} | {r.phase2_turns_used} | {cost} |"
            )
        return "\n".join(rows)

    def _format_failure_analysis(
        self, results: list[CVEEvaluationResult]
    ) -> str:
        """Breakdown of failure reasons with suggested fixes."""
        counts: dict[str, int] = {}
        for r in results:
            if r.failure_reason:
                key = r.failure_reason.value
                counts[key] = counts.get(key, 0) + 1

        if not counts:
            return "_No failures recorded._"

        lines = ["| Reason | Count | Suggestion |", "|--------|-------|------------|"]
        for reason, count in sorted(counts.items(), key=lambda x: -x[1]):
            suggestion = _FAILURE_SUGGESTIONS.get(reason, "See logs.")
            lines.append(f"| {reason} | {count} | {suggestion} |")
        return "\n".join(lines)

    def _format_run_detail(self, r: CVEEvaluationResult) -> str:
        """Compact detail block for a single run."""
        verdict = r.verdict.value if r.verdict else "pending"
        failure = (
            f" ({r.failure_reason.value}: {r.failure_detail})"
            if r.failure_reason else ""
        )
        return (
            f"**Run {r.run_number}** — `{verdict}`{failure}  \n"
            f"Phase1: {r.phase1_status.value} | "
            f"Phase2: {r.phase2_status.value} | "
            f"Phase3: {r.phase3_status.value}  \n"
            f"Turns: {r.phase2_turns_used} | "
            f"Duration: {r.total_duration_sec:.1f}s | "
            f"Cost: ${r.estimated_cost_usd:.4f}  \n"
        )
