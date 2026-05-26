"""Phase 1 Celery task — CodeQL analysis; emits Specs.

Implements worker_spec.md §6 with interrupt gates at all 5 Phase 1 function
boundaries and SSE publication at every state transition.

PipelineFunctionId values used (from shared/contracts/sailor.schema.json):
  phase1_db_build, phase1_query_execution, phase1_sarif_parsing,
  phase1_fact_enrichment, phase1_spec_generation
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.phase1")

WORKER_ID: str = f"{os.environ.get('HOSTNAME', 'worker')}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


@celery_app.task(
    name="tasks.phase1_task",
    queue="phase1",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=3,
)
def phase1_task(self, run_id: str) -> dict:  # type: ignore[no-untyped-def]
    """Execute Phase 1 pipeline for a run."""
    return asyncio.get_event_loop().run_until_complete(_phase1(run_id))


async def _phase1(run_id: str) -> dict:
    from database import AsyncSessionLocal
    from models.run import Run
    from services.artifact_service import get_artifact_store
    from services.event_service import get_event_service
    from services.run_service import get_run, transition_run
    from tasks._control import CooperativeExit
    from tasks._interrupt import interrupt_gate

    event_svc = get_event_service()

    async with AsyncSessionLocal() as db:
        run = await get_run(db, run_id)
        if not run:
            logger.error("Phase 1: run %s not found", run_id)
            return {"error": "run_not_found"}

        # Idempotency guard
        if run.status not in ("queued", "created"):
            logger.warning("Phase 1: run %s status=%s, skipping (idempotency)", run_id, run.status)
            return {"skipped": True}

        await transition_run(db, run_id, "running", ["queued", "created"],
                              extra={"started_at": datetime.utcnow()})

    await event_svc.publish_run_status_changed(run_id, "running")

    store = get_artifact_store()
    project_zip_ref: str | None = None
    build_command: str | None = None
    codeql_build_mode: str = "autodetect"

    async with AsyncSessionLocal() as db:
        run = await get_run(db, run_id)
        if run:
            project_zip_ref = run.project_zip_ref
            build_command = run.build_command
            codeql_build_mode = run.codeql_build_mode or "autodetect"

    if not project_zip_ref:
        await _fail_run(run_id, "no_project_zip", event_svc)
        return {"error": "no_project_zip"}

    from sailor.infra.docker_runner import DockerRunner, RunnerConfig
    runner = DockerRunner(cve_id=run_id, config=RunnerConfig())
    runner.start()

    try:
        # ── Materialize source ───────────────────────────────────────────────
        workspace_dir = Path(f"/data/workspace/{run_id}/src")
        workspace_dir.mkdir(parents=True, exist_ok=True)

        zip_data = await store.get(project_zip_ref)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(zip_data)
            zip_path = Path(f.name)
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(workspace_dir)
        except Exception:
            # Not a valid zip — may be a single C file; copy directly
            workspace_dir.mkdir(parents=True, exist_ok=True)
            (workspace_dir / "target.c").write_bytes(zip_data)
        finally:
            zip_path.unlink(missing_ok=True)

        # ── Gate: phase1_db_build ────────────────────────────────────────────
        gate = await interrupt_gate(
            session=None,  # gate reads its own session internally
            function_id="phase1_db_build",
            run_id=run_id,
            spec_id=None,
            worker_id=WORKER_ID,
            event_service=event_svc,
            scope="run",
            input_files=[],
        )
        if gate.get("skipped"):
            await _fail_run(run_id, "phase1_build_skipped", event_svc)
            return {}

        # ── Gate: phase1_query_execution — build DB + run queries ────────────
        gate = await interrupt_gate(
            session=None,
            function_id="phase1_query_execution",
            run_id=run_id,
            spec_id=None,
            worker_id=WORKER_ID,
            event_service=event_svc,
            scope="run",
            input_files=[],
        )
        sarif_dict: dict[str, Any] = {"runs": [{"results": []}]}
        if gate.get("skipped"):
            logger.info("Phase 1 query_execution skipped for run %s — 0 findings", run_id)
        else:
            try:
                sarif_dict = runner.run_phase1(
                    project_dir=f"/workspace/{run_id}/src",
                    build_command=build_command or None,
                    build_mode=codeql_build_mode,
                )
                sarif_bytes = json.dumps(sarif_dict).encode()
                await store.put(f"runs/{run_id}/phase1/findings.sarif", sarif_bytes)
            except Exception as build_or_query_err:
                await _fail_run(run_id, f"codeql_build_failure: {build_or_query_err}", event_svc)
                return {}

        # ── Gate: phase1_sarif_parsing ────────────────────────────────────────
        gate = await interrupt_gate(
            session=None,
            function_id="phase1_sarif_parsing",
            run_id=run_id,
            spec_id=None,
            worker_id=WORKER_ID,
            event_service=event_svc,
            scope="run",
            input_files=[],
        )
        from sailor.phase1.fact_generation import _parse_sarif
        if gate.get("skipped"):
            raw_findings = []
        else:
            raw_findings = _parse_sarif(sarif_dict, project_root=workspace_dir)
        logger.info("Phase 1: %d raw findings for run %s", len(raw_findings), run_id)

        # ── Gate: phase1_fact_enrichment ─────────────────────────────────────
        gate = await interrupt_gate(
            session=None,
            function_id="phase1_fact_enrichment",
            run_id=run_id,
            spec_id=None,
            worker_id=WORKER_ID,
            event_service=event_svc,
            scope="run",
            input_files=[],
        )
        output_dir = Path(f"/data/output/{run_id}")
        output_dir.mkdir(parents=True, exist_ok=True)

        from sailor.phase1.fact_enrichment import FactEnricher
        if gate.get("skipped"):
            enriched_findings = [(f, {}) for f in raw_findings]
        else:
            enricher = FactEnricher(project_root=workspace_dir, output_dir=output_dir)
            fact_packs = enricher.run(raw_findings)
            enriched_findings = list(zip(raw_findings, fact_packs))

        # ── Gate: phase1_spec_generation ─────────────────────────────────────
        gate = await interrupt_gate(
            session=None,
            function_id="phase1_spec_generation",
            run_id=run_id,
            spec_id=None,
            worker_id=WORKER_ID,
            event_service=event_svc,
            scope="run",
            input_files=[],
        )

        from sailor.phase1.spec_generation import SpecificationGenerator
        from sailor.phase1.pipeline import Phase1Config, Phase1Pipeline
        config = Phase1Config(
            project_name=run_id,
            project_root=workspace_dir,
            output_dir=output_dir,
            build_command=build_command or "make",
            codeql_db=Path(f"/data/workspace/{run_id}/codeql_db"),
        )
        pipeline = Phase1Pipeline(config)

        if gate.get("skipped"):
            specifications = _make_stub_specs(run_id, [f for f, _ in enriched_findings])
        else:
            findings_data = [f.model_dump() for f, _ in enriched_findings]
            (output_dir / "findings.json").write_text(json.dumps(findings_data, indent=2))
            result = pipeline.run_from_findings()
            specifications = result.specifications

        # ── Persist specs and publish events ─────────────────────────────────
        async with AsyncSessionLocal() as db:
            spec_ids = await _save_specs(db, run_id, specifications)

        n_specs = len(specifications)
        n_total = len(raw_findings)
        counters = {
            "specs_total": n_specs,
            "specs_filtered_out": max(0, n_total - n_specs),
            "specs_emitted": n_specs,
        }

        for spec_id in spec_ids:
            spec_data = await _get_spec_data(spec_id)
            if spec_data:
                await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)

        await event_svc.publish_counters_throttled(run_id, counters)

        async with AsyncSessionLocal() as db:
            from sqlalchemy import update as sqlupdate
            from models.run import Run
            await db.execute(
                sqlupdate(Run).where(Run.run_id == run_id)
                .values(counters=counters)
            )
            await db.commit()

        # ── Dispatch Phase 2 tasks ────────────────────────────────────────────
        from tasks.phase2 import phase2_task
        for sid in spec_ids:
            phase2_task.delay(sid)

        await event_svc.publish_run_status_changed(run_id, "running")
        logger.info("Phase 1 complete for run %s: %d specs emitted", run_id, n_specs)
        return {"run_id": run_id, "status": "running", "specs": n_specs}

    except CooperativeExit as ce:
        logger.info("Phase 1 cooperative exit for run %s: %s", run_id, ce.reason)
        return {}

    except Exception as exc:
        logger.exception("Phase 1 failed for run %s", run_id)
        await _fail_run(run_id, str(exc), event_svc)
        raise

    finally:
        runner.stop()


async def _fail_run(run_id: str, error: str, event_svc: Any) -> None:
    from database import AsyncSessionLocal
    from services.run_service import transition_run
    async with AsyncSessionLocal() as db:
        try:
            await transition_run(db, run_id, "failed", ["running", "queued", "created"],
                                 extra={"error": error})
        except Exception:
            pass
    try:
        await event_svc.publish_run_status_changed(run_id, "failed")
    except Exception:
        pass


async def _save_specs(db: Any, run_id: str, specifications: list) -> list[str]:
    """Persist VulnerabilitySpec objects as Spec rows. Returns spec_id list."""
    from models.spec import Spec

    now = datetime.utcnow()
    spec_ids: list[str] = []
    for spec in specifications:
        # Deterministic spec_id from rule_id + file + line
        key = f"{run_id}:{getattr(spec, 'rule_id', '')}:{getattr(spec, 'file', '')}:{getattr(spec, 'line', '')}"
        spec_id = hashlib.sha256(key.encode()).hexdigest()[:32]

        db_spec = Spec(
            spec_id=spec_id,
            run_id=run_id,
            rule_id=getattr(spec, "rule_id", None),
            file=getattr(spec, "file", None),
            line=getattr(spec, "line", None),
            message=getattr(spec, "message", None),
            snippet=getattr(spec, "snippet", None),
            entrypoint=getattr(spec, "entrypoint", None),
            assertion_template=getattr(spec, "assertion_template", None),
            trace=[s.model_dump() for s in getattr(spec, "trace", [])],
            suspect_calls=list(getattr(spec, "suspect_calls", [])),
            pointer_vars=list(getattr(spec, "pointer_vars", [])),
            length_vars=list(getattr(spec, "length_vars", [])),
            bounds_hints=list(getattr(spec, "bounds_hints", [])),
            build_context=getattr(spec, "build_context", None) and spec.build_context.model_dump(),
            phase1_status="emitted",
            phase2_status="queued",
            phase3_status="not_eligible",
            last_event_at=now,
        )
        try:
            db.add(db_spec)
            await db.flush()
        except Exception:
            await db.rollback()
            # Already exists (ON CONFLICT DO NOTHING semantics via try/except)
        spec_ids.append(spec_id)

    await db.commit()
    return spec_ids


def _make_stub_specs(run_id: str, findings: list) -> list:
    """Return findings as minimal stub specs (for skipped spec_generation gate)."""
    return findings  # raw findings treated as stub specs


async def _get_spec_data(spec_id: str) -> dict | None:
    """Load a spec row and convert to dict for SSE publishing."""
    from database import AsyncSessionLocal
    from services.spec_service import get_spec
    async with AsyncSessionLocal() as db:
        spec = await get_spec(db, spec_id)
    if spec is None:
        return None
    return {
        "spec_id": spec.spec_id,
        "run_id": spec.run_id,
        "rule_id": spec.rule_id or "",
        "file": spec.file or "",
        "line": spec.line or 0,
        "message": spec.message or "",
        "phase1_status": spec.phase1_status or "emitted",
        "phase2_status": spec.phase2_status,
        "phase3_status": spec.phase3_status,
        "current_turn": spec.current_turn,
        "turn_count_total": spec.turn_count_total,
    }
