"""Celery task definitions for Sailor Phase 1/2/3.

Each task creates a DockerRunner, executes the phase inside the container,
saves the result to EvaluationDB, then destroys the container (always in a
finally block — CLAUDE.md Rule 3).

Import path: sailor.infra.celery_tasks
Celery app:  sailor.infra.celery_tasks.celery_app
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from celery import Celery

from sailor.infra.docker_runner import DockerRunner, RunnerConfig

log = logging.getLogger("sailor.infra.celery_tasks")

celery_app = Celery("sailor")
celery_app.config_from_object("sailor.infra.celery_config")


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def run_phase1_task(
    self,
    eval_id: str,
    cve_record: dict,
    db_path: str,
    output_base: str,
) -> dict:
    """Celery task: run Phase 1 (CodeQL) for one CVE inside a Docker container.

    Steps:
      1. Start DockerRunner container.
      2. Setup target (clone + build) inside container.
      3. Run Phase 1 (CodeQL DB + query analysis) inside container.
      4. Parse SARIF results locally (no container needed for JSON parsing).
      5. Save result to EvaluationDB.
      6. Stop container (always, even on failure).

    Args:
        eval_id: Evaluation record ID in EvaluationDB.
        cve_record: Serialised :class:`~sailor.models.schemas.CVERecord` dict.
        db_path: Host-side path to the SQLite EvaluationDB.
        output_base: Host-side base path for phase output volumes.

    Returns:
        Dict with ``{"status": "completed"|"failed", "findings_count": N}``.
    """
    from sailor.evaluation.db import EvaluationDB, PhaseStatus, FailureReason
    from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
    from sailor.models.schemas import CVERecord

    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=1, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        sarif_dict = runner.run_phase1(
            project_dir=str(project_dir),
            build_command=record.build_commands[-1],
        )

        config = Phase1Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase1",
            prebuilt_sarif=sarif_dict,
        )
        result = Phase1Pipeline(config).run_from_sarif(sarif_dict)

        db.update_phase_status(
            eval_id,
            phase=1,
            status=PhaseStatus.COMPLETED,
            result_json=result.model_dump_json(),
        )
        log.info(
            "[%s] Phase 1 completed: %d findings, %d active",
            record.cve_id,
            result.total_findings,
            result.after_filtering,
        )
        return {"status": "completed", "findings_count": result.after_filtering}

    except Exception as exc:
        db.update_phase_status(
            eval_id,
            phase=1,
            status=PhaseStatus.FAILED,
            failure_reason=FailureReason.UNKNOWN,
            failure_detail=str(exc),
        )
        log.error("[%s] Phase 1 failed: %s", record.cve_id, exc)
        raise self.retry(exc=exc)

    finally:
        runner.stop()


@celery_app.task(bind=True, max_retries=1, default_retry_delay=30)
def run_phase2_task(
    self,
    eval_id: str,
    cve_record: dict,
    spec_json: str,
    db_path: str,
    output_base: str,
    llm_model: str = "claude-sonnet-4-6",
) -> dict:
    """Celery task: run Phase 2 (LLM + KLEE) for one VulnerabilitySpec.

    The LLM orchestrator runs LOCALLY (API calls from the worker process).
    compile_harness() and run_klee() execute INSIDE the runner container.

    Args:
        eval_id: Evaluation record ID.
        cve_record: Serialised CVERecord dict.
        spec_json: JSON-serialised :class:`~sailor.models.schemas.VulnerabilitySpec`.
        db_path: Host-side path to the SQLite EvaluationDB.
        output_base: Host-side base path for phase output volumes.
        llm_model: Anthropic model identifier.

    Returns:
        Dict with ``{"status": "completed"|"failed", "outcome": <SEOutcome>}``.
    """
    from sailor.evaluation.db import EvaluationDB, PhaseStatus
    from sailor.models.schemas import CVERecord, VulnerabilitySpec
    from sailor.phase2.pipeline import Phase2Pipeline
    from sailor.phase2.llm_orchestrator import Phase2Config

    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    spec = VulnerabilitySpec(**json.loads(spec_json))
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=2, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        config = Phase2Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase2",
            llm_model=llm_model,
            docker_runner=runner,
        )
        results = Phase2Pipeline(config).run([spec])

        outcome = results[0].outcome if results else "inconclusive"
        db.update_phase_status(
            eval_id,
            phase=2,
            status=PhaseStatus.COMPLETED,
            result_json=results[0].model_dump_json() if results else "{}",
        )
        log.info("[%s] Phase 2 completed: %s", record.cve_id, outcome)
        return {"status": "completed", "outcome": str(outcome)}

    except Exception as exc:
        db.update_phase_status(
            eval_id,
            phase=2,
            status=PhaseStatus.FAILED,
            failure_detail=str(exc),
        )
        log.error("[%s] Phase 2 failed: %s", record.cve_id, exc)
        raise self.retry(exc=exc)

    finally:
        runner.stop()


@celery_app.task(bind=True, max_retries=1)
def run_phase3_task(
    self,
    eval_id: str,
    cve_record: dict,
    witness_json: str,
    spec_json: str,
    db_path: str,
    output_base: str,
) -> dict:
    """Celery task: run Phase 3 (ASan validation) inside a Docker container.

    Uses UNMODIFIED project source compiled with ASan inside the container.
    Never uses LLM-generated stubs for ASan compilation.

    Args:
        eval_id: Evaluation record ID.
        cve_record: Serialised CVERecord dict.
        witness_json: JSON-serialised :class:`~sailor.models.schemas.WitnessInput`.
        spec_json: JSON-serialised VulnerabilitySpec.
        db_path: Host-side path to the SQLite EvaluationDB.
        output_base: Host-side base path for phase output volumes.

    Returns:
        Dict with ``{"status": "completed"|"failed", "confirmed": bool}``.
    """
    from sailor.evaluation.db import EvaluationDB, PhaseStatus
    from sailor.models.schemas import CVERecord, WitnessInput, VulnerabilitySpec
    from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config

    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    witness = WitnessInput(**json.loads(witness_json))
    spec = VulnerabilitySpec(**json.loads(spec_json))
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=3, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        config = Phase3Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase3",
            docker_runner=runner,
        )
        # Phase2Result wrapper for a single witness
        from sailor.models.schemas import Phase2Result, SEOutcome
        import datetime
        p2_result = Phase2Result(
            spec_id=witness.spec_id,
            outcome=SEOutcome.BUG_TRIGGERED,
            witness=witness,
            turns_used=witness.turns_used,
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        p3_result = Phase3Pipeline(config).run([p2_result], [spec])

        confirmed = bool(p3_result.confirmed_count > 0)
        db.update_phase_status(
            eval_id,
            phase=3,
            status=PhaseStatus.COMPLETED,
            result_json=p3_result.model_dump_json(),
        )
        log.info("[%s] Phase 3: confirmed=%s", record.cve_id, confirmed)
        return {"status": "completed", "confirmed": confirmed}

    except Exception as exc:
        db.update_phase_status(
            eval_id,
            phase=3,
            status=PhaseStatus.FAILED,
            failure_detail=str(exc),
        )
        log.error("[%s] Phase 3 failed: %s", record.cve_id, exc)
        raise self.retry(exc=exc)

    finally:
        runner.stop()
