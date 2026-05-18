"""Phase 1 Pipeline — orchestrator.

Composes :class:`FactGenerator`, :class:`FactEnricher`, and
:class:`SpecificationGenerator` into a single, independently executable unit.

Usage::

    from pathlib import Path
    from sailor import Phase1Config, Phase1Pipeline

    config = Phase1Config(
        project_name="binutils",
        project_root=Path("/path/to/binutils"),
        output_dir=Path("/tmp/sailor-out"),
        build_command="make -j8",
    )
    result = Phase1Pipeline(config).run()
    # result.specifications → list[VulnerabilitySpec] ready for Phase 2
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from codeql.wrapper import CodeQLRunner
from models.schemas import Phase1Result, VulnerabilitySpec
from sailor.codeql.queries import CodeQLQuerySuite
from sailor.phase1.fact_enrichment import FactEnricher
from sailor.phase1.fact_generation import FactGenerator
from sailor.phase1.spec_generation import SpecificationGenerator

logger = logging.getLogger("sailor.phase1.pipeline")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Phase1Config:
    """Configuration for a Phase 1 pipeline run.

    Attributes:
        project_name: Short identifier for the analysed project (e.g. ``"binutils"``).
        project_root: Absolute path to the project's source root directory.
        output_dir: Directory where all Phase 1 output files are written.
        build_command: Shell command used to build the project (e.g. ``"make -j8"``).
            May be ``None`` when ``compile_commands.json`` is present at *project_root*.
        codeql_path: Path or name of the ``codeql`` executable.
            Defaults to ``"codeql"`` (resolved via ``$PATH``).
        codeql_db: Path to an existing CodeQL database.  When ``None``, a new
            database is created inside *output_dir*.
        codeql_home: Root directory of the CodeQL installation, used to resolve
            standard library query paths.  Standard queries are skipped when ``None``.
        max_workers: Maximum number of parallel CodeQL query invocations.
    """

    project_name: str
    project_root: Path
    output_dir: Path
    build_command: Optional[str] = None
    codeql_path: str = "codeql"
    codeql_db: Optional[Path] = None
    codeql_home: Optional[Path] = None
    max_workers: int = 4

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root).resolve()
        self.output_dir = Path(self.output_dir).resolve()
        if self.codeql_db is not None:
            self.codeql_db = Path(self.codeql_db).resolve()
        if self.codeql_home is not None:
            self.codeql_home = Path(self.codeql_home).resolve()


# ---------------------------------------------------------------------------
# Phase 1 Pipeline
# ---------------------------------------------------------------------------

class Phase1Pipeline:
    """Orchestrates the three Phase 1 sub-stages.

    Each stage is independently serialisable: if a stage has already written
    its output JSON to *output_dir*, it can be skipped by calling
    :meth:`run_from_findings`, :meth:`run_from_fact_packs`, or
    :meth:`run_from_specifications` directly.

    Args:
        config: A :class:`Phase1Config` instance.
    """

    def __init__(self, config: Phase1Config) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def run(self) -> Phase1Result:
        """Execute all three stages and return the aggregate :class:`~models.schemas.Phase1Result`.

        Stages:
            1. **Fact Generation** — build/verify CodeQL DB, run 34 queries,
               parse SARIF → ``findings.json``.
            2. **Fact Enrichment** — apply 5 regex extractors →
               ``fact_packs.json``.
            3. **Specification Generation** — filter + annotate →
               ``specifications.json``.

        Returns:
            Fully populated :class:`~models.schemas.Phase1Result` with all
            surviving :class:`~models.schemas.VulnerabilitySpec` objects.

        Raises:
            Various exceptions from sub-components; none are swallowed here
            so the caller can implement its own retry/fallback strategy.
        """
        cfg = self.config
        cfg.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("=== Phase 1: Static Analysis — project=%s ===", cfg.project_name)

        # ── Stage 1: Fact Generation ─────────────────────────────────────
        db_path = cfg.codeql_db or (cfg.output_dir / "codeql_db")
        runner = CodeQLRunner(
            codeql_path=cfg.codeql_path,
            db_path=db_path,
            timeout=3600,
        )

        if not db_path.exists():
            logger.info("Building CodeQL database at %s ...", db_path)
            runner.create_database(
                source_root=cfg.project_root,
                build_command=cfg.build_command,
                language="cpp",
                overwrite=True,
            )
        else:
            logger.info("Using existing CodeQL database at %s.", db_path)

        suite = CodeQLQuerySuite()
        generator = FactGenerator(
            runner=runner,
            suite=suite,
            project_root=cfg.project_root,
            output_dir=cfg.output_dir,
            codeql_home=cfg.codeql_home,
            max_workers=cfg.max_workers,
        )
        findings = generator.run()
        total_findings = len(findings)
        logger.info("Stage 1 complete: %d findings.", total_findings)

        return self._run_stages_2_3(findings, total_findings)

    # ------------------------------------------------------------------
    # Resume entry points (skip completed stages)
    # ------------------------------------------------------------------

    def run_from_findings(self) -> Phase1Result:
        """Resume Phase 1 from an existing ``findings.json``, skipping Stage 1.

        Raises:
            FileNotFoundError: If ``findings.json`` is missing from *output_dir*.
        """
        logger.info("Resuming from findings.json (skipping fact generation).")
        findings = FactGenerator.load(self.config.output_dir)
        total_findings = len(findings)
        return self._run_stages_2_3(findings, total_findings)

    def run_from_fact_packs(self) -> Phase1Result:
        """Resume Phase 1 from an existing ``fact_packs.json``, skipping Stages 1–2.

        Raises:
            FileNotFoundError: If ``fact_packs.json`` is missing from *output_dir*.
        """
        logger.info("Resuming from fact_packs.json (skipping enrichment).")
        packs = FactEnricher.load(self.config.output_dir)
        return self._run_stage_3(packs, total_findings=len(packs))

    def run_from_specifications(self) -> Phase1Result:
        """Return a :class:`~models.schemas.Phase1Result` from an existing ``specifications.json``.

        Raises:
            FileNotFoundError: If ``specifications.json`` is missing from *output_dir*.
        """
        logger.info("Loading specifications.json (all stages already complete).")
        specs = SpecificationGenerator.load(self.config.output_dir)
        return self._build_result(
            specs=specs,
            total_findings=len(specs),
        )

    # ------------------------------------------------------------------
    # Internal stage runners
    # ------------------------------------------------------------------

    def _run_stages_2_3(self, findings, total_findings: int) -> Phase1Result:
        cfg = self.config

        # Stage 2: Fact Enrichment
        enricher = FactEnricher(
            project_root=cfg.project_root,
            output_dir=cfg.output_dir,
        )
        packs = enricher.run(findings)
        logger.info("Stage 2 complete: %d fact packs.", len(packs))

        return self._run_stage_3(packs, total_findings)

    def _run_stage_3(self, packs, total_findings: int) -> Phase1Result:
        # Stage 3: Specification Generation
        spec_gen = SpecificationGenerator(output_dir=self.config.output_dir)
        specs = spec_gen.run(packs)
        logger.info("Stage 3 complete: %d specifications.", len(specs))

        result = self._build_result(specs=specs, total_findings=total_findings)
        self._write_summary(result)
        return result

    def _build_result(
        self,
        specs: list[VulnerabilitySpec],
        total_findings: int,
    ) -> Phase1Result:
        return Phase1Result.build(
            project=self.config.project_name,
            project_root=str(self.config.project_root),
            total_findings=total_findings,
            specifications=specs,
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def _write_summary(self, result: Phase1Result) -> None:
        out = self.config.output_dir / "phase1_summary.json"
        summary = {
            "project": result.project,
            "project_root": result.project_root,
            "timestamp": result.timestamp,
            "total_findings": result.total_findings,
            "after_filtering": result.after_filtering,
            "reduction_rate": result.reduction_rate,
            "by_cwe": result.by_cwe,
        }
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info(
            "Phase 1 complete — %d findings → %d specifications (%.0f%% reduction). "
            "Summary: %s",
            result.total_findings,
            result.after_filtering,
            result.reduction_rate * 100,
            out,
        )
