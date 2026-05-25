"""Phase 2 Pipeline — top-level entry point for LLM + Symbolic Execution."""

from __future__ import annotations

import json
import logging
import concurrent.futures
import datetime
from pathlib import Path

from sailor.models.schemas import Phase2Result, SEOutcome, VulnerabilitySpec
from sailor.phase2.llm_orchestrator import LLMOrchestrator, Phase2Config

logger = logging.getLogger("sailor.phase2.pipeline")


class Phase2Pipeline:
    """Process a list of :class:`VulnerabilitySpec` objects using Phase 2.

    Each spec is processed independently and in parallel using a thread pool.

    Args:
        config: A :class:`Phase2Config` instance.
    """

    def __init__(self, config: Phase2Config) -> None:
        self.config = config
        config.output_dir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        specs: list[VulnerabilitySpec],
        max_workers: int = 4,
    ) -> list[Phase2Result]:
        """Process all specs in parallel and write results.

        Args:
            specs: List of vulnerability specifications from Phase 1.
            max_workers: Maximum number of parallel worker threads.

        Returns:
            List of :class:`Phase2Result` objects, one per spec.
        """
        if not specs:
            logger.info("No specifications to process — Phase 2 complete.")
            results: list[Phase2Result] = []
            self._write_results(results)
            self._write_summary(results)
            return results

        logger.info(
            "=== Phase 2: LLM + SE — project=%s, specs=%d, workers=%d ===",
            self.config.project_name,
            len(specs),
            max_workers,
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.run_single, spec): spec for spec in specs}
            results = []
            for future in concurrent.futures.as_completed(futures):
                spec = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(
                        "Spec %s:%d → %s",
                        spec.file,
                        spec.line,
                        result.outcome.value,
                    )
                except Exception as exc:
                    logger.error(
                        "Spec %s:%d failed: %s",
                        spec.file,
                        spec.line,
                        exc,
                    )
                    results.append(
                        Phase2Result(
                            spec_id=f"{spec.rule_id}:{spec.file}:{spec.line}",
                            outcome=SEOutcome.INCONCLUSIVE,
                            turns_used=0,
                            timestamp=_now(),
                        )
                    )

        self._write_results(results)
        self._write_summary(results)

        total = len(results)
        bug = sum(1 for r in results if r.outcome == SEOutcome.BUG_TRIGGERED)
        logger.info(
            "Phase 2 complete — %d specs processed, %d bugs triggered.", total, bug
        )
        return results

    def run_single(self, spec: VulnerabilitySpec) -> Phase2Result:
        """Run Phase 2 for a single :class:`VulnerabilitySpec`.

        Args:
            spec: The vulnerability specification to process.

        Returns:
            A :class:`Phase2Result`.
        """
        orchestrator = LLMOrchestrator(self.config, spec)
        return orchestrator.run()

    # ------------------------------------------------------------------
    # Output writers
    # ------------------------------------------------------------------

    def _write_results(self, results: list[Phase2Result]) -> None:
        """Serialise all results to ``output_dir/phase2_results.json``."""
        out = self.config.output_dir / "phase2_results.json"
        data = [r.model_dump() for r in results]
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Wrote %d results → %s", len(results), out)

    def _write_summary(self, results: list[Phase2Result]) -> None:
        """Write aggregated summary to ``output_dir/phase2_summary.json``."""
        out = self.config.output_dir / "phase2_summary.json"

        by_cwe: dict[str, dict[str, int]] = {}
        outcome_counts: dict[str, int] = {e.value: 0 for e in SEOutcome}

        for r in results:
            outcome_counts[r.outcome.value] = outcome_counts.get(r.outcome.value, 0) + 1

        summary = {
            "total": len(results),
            "bug_triggered": outcome_counts.get(SEOutcome.BUG_TRIGGERED.value, 0),
            "site_reached": outcome_counts.get(SEOutcome.SITE_REACHED.value, 0),
            "not_reached": outcome_counts.get(SEOutcome.NOT_REACHED.value, 0),
            "inconclusive": outcome_counts.get(SEOutcome.INCONCLUSIVE.value, 0),
            "likely_false_positive": outcome_counts.get(SEOutcome.LIKELY_FP.value, 0),
            "by_cwe": by_cwe,
            "timestamp": _now(),
        }
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Wrote summary → %s", out)


def _now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
