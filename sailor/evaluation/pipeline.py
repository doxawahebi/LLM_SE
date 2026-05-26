"""EvaluationPipeline — top-level orchestrator for the Sailor evaluation framework.

Connects DockerEnvironment, Phase1/2/3 pipelines, EvaluationDB, and
ReportGenerator. Enforces checkpoint-resume logic to protect the token budget.
"""

from __future__ import annotations

import datetime
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sailor.models.schemas import (
    CVEEvaluationResult,
    CVERecord,
    EvaluationVerdict,
    FailureReason,
    Phase1Result,
    Phase2Result,
    Phase3Result,
    PhaseStatus,
    SEOutcome,
    ValidationResult,
    ValidationVerdict,
    VulnerabilitySpec,
)
from sailor.evaluation.dataset import CVEDataset, INITIAL_DATASET
from sailor.evaluation.db import EvaluationDB
from sailor.evaluation.environment import DockerEnvironment, EnvironmentSetupError
from sailor.evaluation.metrics import EvaluationMetrics, MetricsCalculator
from sailor.evaluation.report import ReportGenerator
from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
from sailor.phase2.pipeline import Phase2Pipeline
from sailor.phase2.llm_orchestrator import Phase2Config
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config

logger = logging.getLogger("sailor.evaluation.pipeline")

# Sonnet 4.5 pricing (input / output per million tokens)
_PRICE_INPUT_PER_M = 3.0
_PRICE_OUTPUT_PER_M = 15.0


def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class EvaluationConfig:
    """Configuration for :class:`EvaluationPipeline`.

    Attributes:
        db_path: Path to the SQLite database file.
        dataset_path: JSON file with CVERecord list (optional; INITIAL_DATASET used if absent).
        workspace_dir: Host path used as Docker volume mount base.
        output_dir: Directory for reports and per-CVE artifacts.
        llm_model: Model name passed to Phase 2 orchestrator.
        klee_path: Path or name of the klee executable.
        clang_path: Path or name of the clang executable.
        runs_per_cve: Number of evaluation runs per CVE (1 for single-run evaluation).
        phase_timeout_sec: Maximum seconds per phase per CVE.
        skip_docker: When True, skip DockerEnvironment setup (use pre-built project root).
        pre_built_project_root: Required when skip_docker=True; path to project source.
        pre_built_build_command: Build command passed to Phase1Config when skip_docker=True.
    """

    db_path: Path
    workspace_dir: Path
    output_dir: Path
    dataset_path: Optional[Path] = None
    llm_model: str = "gemini-2.5-flash"
    klee_path: str = "klee"
    clang_path: str = "clang-14"
    klee_include_path: str = "/tmp/klee_include"
    use_docker_klee: bool = True
    runs_per_cve: int = 1
    phase_timeout_sec: int = 3600
    skip_docker: bool = False
    pre_built_project_root: Optional[Path] = None
    pre_built_build_command: Optional[str] = None
    codeql_search_path: Optional[str] = None

    def __post_init__(self) -> None:
        import shutil as _shutil
        if self.codeql_search_path is None:
            codeql_bin = _shutil.which("codeql")
            if codeql_bin:
                candidate = Path(codeql_bin).parent / "qlpacks"
                if candidate.is_dir():
                    self.codeql_search_path = str(candidate)


class EvaluationPipeline:
    """End-to-end CVE evaluation orchestrator.

    For each CVE in the dataset:
      1. Check DB for a resumable run (avoids re-running completed phases).
      2. Set up Docker environment (unless skip_docker=True).
      3. Run Phase 1 → Phase 2 → Phase 3 sequentially.
      4. Save each phase result to DB immediately (checkpoint).
      5. Compute and save verdict.
      6. Generate final report.

    Args:
        config: :class:`EvaluationConfig` instance.
    """

    def __init__(self, config: EvaluationConfig) -> None:
        self.config = config
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
        config.output_dir.mkdir(parents=True, exist_ok=True)
        config.workspace_dir.mkdir(parents=True, exist_ok=True)

        self._db = EvaluationDB(config.db_path)
        self._dataset = CVEDataset(self._db)
        self._metrics_calc = MetricsCalculator(self._db)
        self._report_gen = ReportGenerator(
            self._db, config.output_dir / "evaluation"
        )
        self._load_dataset()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self, cve_ids: Optional[list[str]] = None
    ) -> EvaluationMetrics:
        """Main evaluation loop.

        Args:
            cve_ids: Restrict evaluation to these CVE IDs. None means all CVEs.

        Returns:
            Aggregate :class:`EvaluationMetrics` after all runs complete.
        """
        records = self._dataset.list_all()
        if cve_ids is not None:
            id_set = set(cve_ids)
            records = [r for r in records if r.cve_id in id_set]

        if not records:
            logger.warning("No CVE records found in dataset (cve_ids=%s).", cve_ids)
            return self._metrics_calc.compute()

        logger.info(
            "=== EvaluationPipeline: %d CVEs × %d run(s) each ===",
            len(records),
            self.config.runs_per_cve,
        )

        for record in records:
            for run_idx in range(self.config.runs_per_cve):
                self._run_one(record, run_idx + 1)

        self._report_gen.generate()
        self._report_gen.generate_json()
        metrics = self._metrics_calc.compute()
        logger.info(
            "Evaluation complete — TP=%d FN=%d FP=%d partial=%d recall=%.2f",
            metrics.true_positives,
            metrics.false_negatives,
            metrics.false_positives,
            metrics.partials,
            metrics.recall,
        )
        return metrics

    # ------------------------------------------------------------------
    # Per-CVE run
    # ------------------------------------------------------------------

    def _run_one(self, record: CVERecord, run_number: int) -> None:
        cve_id = record.cve_id
        logger.info("--- CVE %s run %d ---", cve_id, run_number)

        # Checkpoint: check if we can resume a previous run
        resumable = self._db.get_resumable_phase(cve_id)
        if resumable and run_number == 1:
            eval_id, next_phase = resumable
            logger.info(
                "Resuming eval_id=%s from Phase %d (checkpoint found).",
                eval_id,
                next_phase,
            )
        else:
            eval_id = str(uuid.uuid4())
            next_phase = 1
            result = CVEEvaluationResult(
                eval_id=eval_id,
                cve_id=cve_id,
                run_number=run_number,
                timestamp_start=_now(),
            )
            self._db.create_evaluation(result)
            self._db.update_timestamps(eval_id, _now(), "")

        self._db.update_timestamps(eval_id, _now(), "")
        t_run_start = time.perf_counter()

        cve_output_dir = self.config.output_dir / "evaluation" / cve_id
        cve_output_dir.mkdir(parents=True, exist_ok=True)

        env: Optional[DockerEnvironment] = None
        project_root: Optional[Path] = None

        try:
            # Environment setup
            if self.config.skip_docker:
                project_root = self.config.pre_built_project_root
                if project_root is None:
                    raise EnvironmentSetupError(
                        "skip_docker=True but pre_built_project_root is not set."
                    )
            else:
                env = DockerEnvironment(
                    record=record,
                    workspace=self.config.workspace_dir / cve_id,
                )
                try:
                    project_root = env.setup()
                except EnvironmentSetupError as exc:
                    self._db.update_phase_status(eval_id, 1, PhaseStatus.FAILED)
                    self._db.update_verdict(
                        eval_id,
                        EvaluationVerdict.FALSE_NEGATIVE,
                        FailureReason.DOCKER_ERROR,
                        str(exc),
                    )
                    logger.error("Docker setup failed for %s: %s", cve_id, exc)
                    return

            # Phase 1
            phase1_result: Optional[Phase1Result] = None
            if next_phase <= 1:
                phase1_result = self._run_phase1(
                    eval_id, record, project_root, cve_output_dir
                )
                if phase1_result is None:
                    self._compute_verdict(eval_id, record)
                    return
            else:
                # Load from DB checkpoint
                row = self._db.get_evaluation(eval_id)
                if row and row.phase1_result:
                    phase1_result = row.phase1_result

            # Phase 2
            phase2_results: Optional[list[Phase2Result]] = None
            if next_phase <= 2 and phase1_result is not None:
                phase2_results = self._run_phase2(
                    eval_id, record, phase1_result, cve_output_dir
                )
            elif next_phase > 2:
                row = self._db.get_evaluation(eval_id)
                if row:
                    phase2_results = row.phase2_result

            # Phase 3
            if (
                next_phase <= 3
                and phase2_results is not None
                and phase1_result is not None
            ):
                self._run_phase3(
                    eval_id, record, phase2_results, phase1_result, cve_output_dir
                )

            # Verdict
            self._compute_verdict(eval_id, record)

        finally:
            if env is not None:
                env.teardown()
            elapsed = time.perf_counter() - t_run_start
            self._db.update_timestamps(eval_id, "", _now())
            logger.info(
                "CVE %s run %d finished in %.1fs", cve_id, run_number, elapsed
            )

    # ------------------------------------------------------------------
    # Phase runners
    # ------------------------------------------------------------------

    def _run_phase1(
        self,
        eval_id: str,
        record: CVERecord,
        project_root: Path,
        cve_output_dir: Path,
    ) -> Optional[Phase1Result]:
        """Run Phase1Pipeline and checkpoint result to DB."""
        self._db.update_phase_status(eval_id, 1, PhaseStatus.RUNNING)
        t0 = time.perf_counter()
        try:
            build_cmd = (
                self.config.pre_built_build_command
                if self.config.skip_docker
                else " && ".join(record.build_commands)
            )
            cfg = Phase1Config(
                project_name=record.project,
                project_root=project_root,
                output_dir=cve_output_dir / "phase1",
                build_command=build_cmd,
                codeql_path="codeql",
                codeql_search_path=self.config.codeql_search_path,
            )
            result = Phase1Pipeline(cfg).run()
            duration = time.perf_counter() - t0
            result_json = result.model_dump_json()
            self._db.update_phase_status(eval_id, 1, PhaseStatus.COMPLETED, result_json)
            self._db.update_metrics(
                eval_id,
                phase1_duration=duration,
                phase2_duration=0.0,
                phase3_duration=0.0,
                phase2_turns=0,
                llm_calls=0,
                estimated_tokens=0,
                estimated_cost=0.0,
            )
            logger.info(
                "Phase 1 done for %s: %d specs in %.1fs",
                record.cve_id,
                len(result.specifications),
                duration,
            )
            return result
        except Exception as exc:
            self._db.update_phase_status(eval_id, 1, PhaseStatus.FAILED)
            self._db.update_verdict(
                eval_id,
                EvaluationVerdict.FALSE_NEGATIVE,
                FailureReason.BUILD_FAILED,
                str(exc),
            )
            logger.error("Phase 1 failed for %s: %s", record.cve_id, exc)
            return None

    def _run_phase2(
        self,
        eval_id: str,
        record: CVERecord,
        phase1_result: Phase1Result,
        cve_output_dir: Path,
    ) -> Optional[list[Phase2Result]]:
        """Run Phase2Pipeline on ground-truth matching specs only.

        Token budget rule: only process specs matching vulnerable_file + vulnerable_func.
        """
        self._db.update_phase_status(eval_id, 2, PhaseStatus.RUNNING)
        t0 = time.perf_counter()

        # Filter to ground-truth location to protect token budget.
        # When entrypoint is "LLM_INFER" (unresolved), match by file only.
        target_specs = [
            s for s in phase1_result.specifications
            if (
                record.vulnerable_file in s.file
                and (
                    s.entrypoint == "LLM_INFER"
                    or record.vulnerable_func in s.entrypoint
                )
            )
        ]

        if not target_specs:
            logger.info(
                "Phase 2 skipped for %s: no specs match ground truth location (%s:%s).",
                record.cve_id,
                record.vulnerable_file,
                record.vulnerable_func,
            )
            self._db.update_phase_status(eval_id, 2, PhaseStatus.SKIPPED, "[]")
            return []

        logger.info(
            "Phase 2: running on %d/%d specs matching ground truth for %s.",
            len(target_specs),
            len(phase1_result.specifications),
            record.cve_id,
        )

        try:
            p2_cfg = Phase2Config(
                project_name=record.project,
                project_root=Path(phase1_result.project_root),
                output_dir=cve_output_dir / "phase2",
                llm_model=self.config.llm_model,
                klee_path=self.config.klee_path,
                clang_path=self.config.clang_path,
                klee_include_path=self.config.klee_include_path,
                use_docker_klee=self.config.use_docker_klee,
            )
            results = Phase2Pipeline(p2_cfg).run(target_specs, max_workers=1)
            duration = time.perf_counter() - t0
            total_turns = sum(r.turns_used for r in results)
            # Estimate token cost: 2000 tokens/turn average for Sonnet 4.5
            est_tokens = total_turns * 2000
            est_cost = round(
                (est_tokens * 0.5 * _PRICE_INPUT_PER_M / 1_000_000)
                + (est_tokens * 0.5 * _PRICE_OUTPUT_PER_M / 1_000_000),
                4,
            )
            result_json = json.dumps([r.model_dump() for r in results], default=str)
            self._db.update_phase_status(eval_id, 2, PhaseStatus.COMPLETED, result_json)
            self._db.update_metrics(
                eval_id,
                phase1_duration=0.0,
                phase2_duration=duration,
                phase3_duration=0.0,
                phase2_turns=total_turns,
                llm_calls=total_turns,
                estimated_tokens=est_tokens,
                estimated_cost=est_cost,
            )
            logger.info(
                "Phase 2 done for %s: %d results, %d turns in %.1fs (est. $%.4f).",
                record.cve_id,
                len(results),
                total_turns,
                duration,
                est_cost,
            )
            return results
        except Exception as exc:
            self._db.update_phase_status(eval_id, 2, PhaseStatus.FAILED)
            logger.error("Phase 2 failed for %s: %s", record.cve_id, exc)
            return None

    def _run_phase3(
        self,
        eval_id: str,
        record: CVERecord,
        phase2_results: list[Phase2Result],
        phase1_result: Phase1Result,
        cve_output_dir: Path,
    ) -> Optional[Phase3Result]:
        """Run Phase3Pipeline on BUG_TRIGGERED results only."""
        self._db.update_phase_status(eval_id, 3, PhaseStatus.RUNNING)
        t0 = time.perf_counter()
        try:
            p3_cfg = Phase3Config(
                project_name=record.project,
                project_root=Path(phase1_result.project_root),
                output_dir=cve_output_dir / "phase3",
                clang_path=self.config.clang_path,
            )
            result = Phase3Pipeline(p3_cfg).run(
                phase2_results, phase1_result.specifications
            )
            duration = time.perf_counter() - t0
            result_json = result.model_dump_json()
            self._db.update_phase_status(eval_id, 3, PhaseStatus.COMPLETED, result_json)
            # Accumulate phase3 duration (merge with existing metrics row)
            row = self._db.get_evaluation(eval_id)
            if row:
                self._db.update_metrics(
                    eval_id,
                    phase1_duration=row.phase1_duration_sec,
                    phase2_duration=row.phase2_duration_sec,
                    phase3_duration=duration,
                    phase2_turns=row.phase2_turns_used,
                    llm_calls=row.llm_calls,
                    estimated_tokens=row.estimated_tokens_used,
                    estimated_cost=row.estimated_cost_usd,
                )
            logger.info(
                "Phase 3 done for %s: confirmed=%d in %.1fs.",
                record.cve_id,
                result.confirmed,
                duration,
            )
            return result
        except Exception as exc:
            self._db.update_phase_status(eval_id, 3, PhaseStatus.FAILED)
            logger.error("Phase 3 failed for %s: %s", record.cve_id, exc)
            return None

    # ------------------------------------------------------------------
    # Verdict computation
    # ------------------------------------------------------------------

    def _compute_verdict(
        self,
        eval_id: str,
        record: CVERecord,
    ) -> EvaluationVerdict:
        """Load latest phase results from DB and compute final verdict."""
        row = self._db.get_evaluation(eval_id)
        if row is None:
            return EvaluationVerdict.FALSE_NEGATIVE

        phase1_detected = False
        if row.phase1_result:
            phase1_detected = any(
                record.vulnerable_file in s.file
                and record.vulnerable_func in s.entrypoint
                for s in row.phase1_result.specifications
            )

        phase2_triggered = False
        if row.phase2_result:
            for r2 in row.phase2_result:
                if r2.outcome == SEOutcome.BUG_TRIGGERED:
                    phase2_triggered = True
                    break

        phase3_confirmed = False
        correct_location = False
        if row.phase3_result:
            for vr in row.phase3_result.results:
                if vr.verdict == ValidationVerdict.CONFIRMED:
                    phase3_confirmed = True
                    correct_location = self._match_ground_truth(vr, record)
                    break

        self._db.update_ground_truth_flags(
            eval_id, phase1_detected, phase2_triggered, phase3_confirmed
        )

        # Determine verdict
        if phase3_confirmed and correct_location:
            verdict = EvaluationVerdict.TRUE_POSITIVE
            failure_reason = None
            failure_detail = ""
        elif phase3_confirmed and not correct_location:
            verdict = EvaluationVerdict.FALSE_POSITIVE
            failure_reason = FailureReason.ASAN_WRONG_LOCATION
            failure_detail = "ASan confirmed but at wrong location."
        elif phase1_detected and not phase2_triggered and not phase3_confirmed:
            verdict = EvaluationVerdict.PARTIAL
            failure_reason = self._infer_p2_failure_reason(row.phase2_result)
            failure_detail = "Phase 1 detected but Phase 2/3 did not confirm."
        elif not phase1_detected:
            verdict = EvaluationVerdict.FALSE_NEGATIVE
            failure_reason = self._infer_p1_failure_reason(row)
            failure_detail = "Phase 1 did not detect vulnerability."
        else:
            # phase2 triggered but phase3 didn't confirm
            verdict = EvaluationVerdict.PARTIAL
            failure_reason = FailureReason.ASAN_NOT_CONFIRMED
            failure_detail = "Bug triggered but ASan did not confirm."

        self._db.update_verdict(eval_id, verdict, failure_reason, failure_detail)
        logger.info(
            "Verdict for %s eval_id=%s: %s", record.cve_id, eval_id, verdict.value
        )
        return verdict

    def _match_ground_truth(
        self,
        result: ValidationResult,
        record: CVERecord,
        line_tolerance: int = 20,
    ) -> bool:
        """True if the validation result matches the CVE ground truth.

        Args:
            result: A :class:`ValidationResult` from Phase 3.
            record: The CVERecord with ground-truth location.
            line_tolerance: Acceptable line number offset.
        """
        file_match = record.vulnerable_file in result.file
        func_match = record.vulnerable_func in result.func
        line_match = abs(result.line - record.vulnerable_line) <= line_tolerance
        return file_match and func_match and line_match

    # ------------------------------------------------------------------
    # Failure reason inference helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_p1_failure_reason(
        row: CVEEvaluationResult,
    ) -> FailureReason:
        if row.phase1_status == PhaseStatus.FAILED:
            return FailureReason.BUILD_FAILED
        if row.phase1_result and row.phase1_result.after_filtering == 0:
            return FailureReason.QUERY_MISSED
        return FailureReason.STRUCTURAL_MISS

    @staticmethod
    def _infer_p2_failure_reason(
        p2_results: Optional[list[Phase2Result]],
    ) -> FailureReason:
        if not p2_results:
            return FailureReason.HARNESS_COMPILE_ERROR
        outcomes = [r.outcome for r in p2_results]
        if all(o == SEOutcome.NOT_REACHED for o in outcomes):
            return FailureReason.SE_NOT_REACHED
        if any(o == SEOutcome.INCONCLUSIVE for o in outcomes):
            return FailureReason.INCONCLUSIVE
        if any(o == SEOutcome.LIKELY_FP for o in outcomes):
            return FailureReason.LIKELY_FALSE_POSITIVE
        return FailureReason.UNKNOWN

    # ------------------------------------------------------------------
    # Dataset loading
    # ------------------------------------------------------------------

    def _load_dataset(self) -> None:
        cfg = self.config
        if cfg.dataset_path and cfg.dataset_path.exists():
            self._dataset.load_from_file(cfg.dataset_path)
        else:
            existing = self._dataset.list_all()
            if not existing:
                self._dataset.load_initial_dataset()
                logger.info("Loaded INITIAL_DATASET (1 CVE).")
