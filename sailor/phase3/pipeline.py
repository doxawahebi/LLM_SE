"""Phase 3 Pipeline — concrete validation of Phase 2 witnesses.

Processes all BUG_TRIGGERED Phase 2 results by generating a concrete replay
driver, compiling it with ASan, executing it, and classifying the result as
CONFIRMED or FALSE_POSITIVE.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from sailor.models.schemas import (
    Phase2Result,
    Phase3Result,
    SEOutcome,
    ValidationResult,
    ValidationVerdict,
    VulnerabilitySpec,
)
from sailor.phase3.asan_compiler import ASanCompileError, ASanCompiler
from sailor.phase3.concrete_executor import ConcreteExecutor
from sailor.phase3.replay_driver_gen import ReplayDriverGenerator
from sailor.phase3.result_classifier import ResultClassifier

logger = logging.getLogger("sailor.phase3.pipeline")

_SAFE_ID_RE = re.compile(r"[:/\\]")


def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_dir_name(spec_id: str) -> str:
    """Convert a spec_id to a filesystem-safe directory name."""
    return _SAFE_ID_RE.sub("_", spec_id)[:120]


@dataclass
class Phase3Config:
    """Configuration for :class:`Phase3Pipeline`.

    Attributes:
        project_name: Short identifier for the project (e.g. ``'binutils'``).
        project_root: Absolute path to the unmodified project source tree.
        output_dir: Directory where Phase 3 artifacts are written.
        clang_path: Path to the ``clang`` binary (local fallback only).
        execution_timeout: Maximum seconds per reproducer execution.
        max_workers: Thread-pool size for parallel processing.
        docker_runner: When provided, ASan compilation and concrete execution
            are delegated to this :class:`~sailor.infra.docker_runner.DockerRunner`
            instance.  When ``None``, local subprocess calls are used.
        replay_driver_preamble: Optional C source preamble prepended to the
            generated replay driver (e.g. project-specific includes). When
            set, inline struct definitions named in
            ``replay_driver_struct_names`` are stripped so the project headers
            take precedence over the Phase 2 inline definitions.
        replay_driver_struct_names: Names of typedef'd structs defined by the
            project headers that should be removed from the inline driver.
    """

    project_name: str
    project_root: Path
    output_dir: Path
    clang_path: str = "clang"
    execution_timeout: int = 30
    max_workers: int = 4
    docker_runner: object | None = None
    build_command: str = ""
    replay_driver_preamble: str = ""
    replay_driver_struct_names: list[str] = field(default_factory=list)


class Phase3Pipeline:
    """Orchestrate Phase 3 concrete validation for all BUG_TRIGGERED specs.

    Args:
        config: A :class:`Phase3Config` instance.
    """

    def __init__(self, config: Phase3Config) -> None:
        self.config = config
        config.output_dir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        phase2_results: list[Phase2Result],
        specs: list[VulnerabilitySpec],
    ) -> Phase3Result:
        """Process all BUG_TRIGGERED Phase 2 results in parallel.

        Skips results with any outcome other than BUG_TRIGGERED (logged at
        DEBUG level).  For each qualifying result, runs the full validation
        pipeline: replay driver generation → ASan compilation → concrete
        execution → classification.

        Writes to ``output_dir``:
        - ``<spec_id>/replay_driver.c``
        - ``<spec_id>/asan_output.txt``
        - ``<spec_id>/verified_bug.json`` (only for CONFIRMED results)
        - ``phase3_results.json``
        - ``phase3_summary.json``

        Args:
            phase2_results: All results from Phase 2.
            specs: All :class:`VulnerabilitySpec` objects from Phase 1.

        Returns:
            Aggregate :class:`Phase3Result`.
        """
        spec_by_id: dict[str, VulnerabilitySpec] = {
            f"{s.rule_id}:{s.file}:{s.line}": s for s in specs
        }

        qualifying = [
            r for r in phase2_results if r.outcome == SEOutcome.BUG_TRIGGERED
        ]
        skipped = len(phase2_results) - len(qualifying)
        logger.info(
            "=== Phase 3: Validation — project=%s, qualifying=%d, skipped=%d ===",
            self.config.project_name,
            len(qualifying),
            skipped,
        )

        if not qualifying:
            logger.info("No BUG_TRIGGERED results — Phase 3 complete.")
            result = Phase3Result(
                total_processed=0,
                confirmed=0,
                false_positives=0,
                errors=0,
                results=[],
                timestamp=_now(),
            )
            self._write_results(result.results)
            self._write_summary(result)
            return result

        validation_results: list[ValidationResult] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.max_workers
        ) as pool:
            futures = {
                pool.submit(self._process_one, r, spec_by_id): r
                for r in qualifying
            }
            for future in concurrent.futures.as_completed(futures):
                p2r = futures[future]
                try:
                    vr = future.result()
                    validation_results.append(vr)
                    logger.info(
                        "Spec %s → %s", p2r.spec_id, vr.verdict.value
                    )
                except Exception as exc:
                    logger.error(
                        "Unexpected error processing spec %s: %s", p2r.spec_id, exc
                    )
                    spec = spec_by_id.get(p2r.spec_id)
                    error_result = ValidationResult(
                        spec_id=p2r.spec_id,
                        verdict=ValidationVerdict.ERROR,
                        cwe=spec.cwe if spec else "CWE-UNKNOWN",
                        file=spec.file if spec else "",
                        line=spec.line if spec else 0,
                        func=spec.entrypoint if spec else "",
                        timestamp=_now(),
                    )
                    validation_results.append(error_result)

        confirmed = sum(
            1 for r in validation_results if r.verdict == ValidationVerdict.CONFIRMED
        )
        false_positives = sum(
            1 for r in validation_results if r.verdict == ValidationVerdict.FALSE_POSITIVE
        )
        errors = sum(
            1 for r in validation_results if r.verdict == ValidationVerdict.ERROR
        )

        phase3_result = Phase3Result(
            total_processed=len(qualifying),
            confirmed=confirmed,
            false_positives=false_positives,
            errors=errors,
            results=validation_results,
            timestamp=_now(),
        )

        self._write_results(validation_results)
        self._write_summary(phase3_result)

        logger.info(
            "Phase 3 complete — processed=%d confirmed=%d false_positives=%d errors=%d",
            len(qualifying),
            confirmed,
            false_positives,
            errors,
        )
        return phase3_result

    def run_single(
        self,
        phase2_result: Phase2Result,
        spec: VulnerabilitySpec,
    ) -> ValidationResult:
        """Run Phase 3 validation for a single BUG_TRIGGERED result.

        Args:
            phase2_result: A Phase 2 result with ``outcome == BUG_TRIGGERED``.
            spec: The originating :class:`VulnerabilitySpec`.

        Returns:
            A :class:`ValidationResult`.
        """
        spec_id = phase2_result.spec_id
        spec_dir = self._setup_output_dir(_safe_dir_name(spec_id))

        witness = phase2_result.witness
        if witness is None:
            raise ValueError(
                f"Phase2Result {spec_id!r} is BUG_TRIGGERED but has no witness."
            )

        # 1. Generate concrete replay driver.
        gen = ReplayDriverGenerator(
            witness=witness,
            output_dir=spec_dir,
            project_preamble=self.config.replay_driver_preamble,
            project_struct_names=self.config.replay_driver_struct_names,
        )
        replay_driver_path = gen.generate()

        # 2. Parse witness values for classification later.
        witness_values = gen._parse_ktest(witness.ktest_paths[0])

        # 3. Compile project with ASan and link replay driver.
        compiler = ASanCompiler(
            clang_path=self.config.clang_path,
            project_root=self.config.project_root,
            build_context=spec.build_context,
            output_dir=spec_dir,
            build_command=self.config.build_command,
            docker_runner=self.config.docker_runner,
        )
        project_archive = compiler.compile_project()
        reproducer_path = compiler.compile_replay_driver(
            replay_driver_path, project_archive
        )

        # 4. Execute the reproducer.
        executor = ConcreteExecutor(
            timeout=self.config.execution_timeout,
            output_dir=spec_dir,
            docker_runner=self.config.docker_runner,
        )
        crashed, asan_output = executor.execute(
            reproducer_path,
            replay_driver_path=replay_driver_path,
            project_archive=project_archive,
            include_paths=spec.build_context.include_paths,
        )

        # 5. Classify the result.
        classifier = ResultClassifier(project_root=self.config.project_root)
        result = classifier.classify(
            crashed=crashed,
            asan_output=asan_output,
            spec=spec,
            witness_values=witness_values,
        )

        # 6. Write output files and fill in paths.
        asan_report_path = spec_dir / "asan_output.txt"
        if not asan_report_path.exists():
            asan_report_path.write_text(asan_output, encoding="utf-8")

        result.replay_driver_path = str(replay_driver_path)
        result.asan_report_path = str(asan_report_path)

        if result.verdict == ValidationVerdict.CONFIRMED:
            bug_data = classifier.build_verified_bug_json(result, spec)
            verified_path = spec_dir / "verified_bug.json"
            verified_path.write_text(
                json.dumps(bug_data, indent=2), encoding="utf-8"
            )
            result.verdict_path = str(verified_path)
            logger.info("Confirmed bug → %s", verified_path)

        return result

    def _process_one(
        self,
        phase2_result: Phase2Result,
        spec_by_id: dict[str, VulnerabilitySpec],
    ) -> ValidationResult:
        """Resolve the spec and delegate to run_single; raises on missing spec."""
        spec = spec_by_id.get(phase2_result.spec_id)
        if spec is None:
            raise ValueError(
                f"No VulnerabilitySpec found for spec_id={phase2_result.spec_id!r}."
            )
        return self.run_single(phase2_result, spec)

    def _setup_output_dir(self, spec_id_safe: str) -> Path:
        """Create and return the per-spec output subdirectory.

        Args:
            spec_id_safe: Filesystem-safe spec identifier (colons and slashes
                replaced with underscores).

        Returns:
            Path to the created directory.
        """
        spec_dir = self.config.output_dir / spec_id_safe
        spec_dir.mkdir(parents=True, exist_ok=True)
        return spec_dir

    # ------------------------------------------------------------------
    # Output writers
    # ------------------------------------------------------------------

    def _write_results(self, results: list[ValidationResult]) -> None:
        """Serialise all validation results to ``phase3_results.json``."""
        out = self.config.output_dir / "phase3_results.json"
        data = [r.model_dump() for r in results]
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Wrote %d validation results → %s", len(results), out)

    def _write_summary(self, result: Phase3Result) -> None:
        """Write aggregated summary to ``phase3_summary.json``."""
        confirmed_bugs = [
            {
                "spec_id": r.spec_id,
                "cwe": r.cwe,
                "file": r.file,
                "line": r.line,
                "asan_type": r.asan_type.value if r.asan_type else None,
            }
            for r in result.results
            if r.verdict == ValidationVerdict.CONFIRMED
        ]
        summary = {
            "project": self.config.project_name,
            "total_processed": result.total_processed,
            "confirmed": result.confirmed,
            "false_positives": result.false_positives,
            "errors": result.errors,
            "confirmed_bugs": confirmed_bugs,
            "timestamp": result.timestamp,
        }
        out = self.config.output_dir / "phase3_summary.json"
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Wrote summary → %s", out)
