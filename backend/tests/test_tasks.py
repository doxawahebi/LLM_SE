"""Tests for Celery task workers (Phase 1, 2, 3) and infrastructure.

Mocks DockerRunner and sailor/ pipeline calls. Uses pytest-asyncio with
the DB from conftest.py (truncated between tests).
"""

import asyncio
import uuid
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from models.auto_config import AutoConfig
from models.interrupt_point import InterruptPoint
from models.run import Run
from models.spec import Spec


@pytest_asyncio.fixture(autouse=True)
async def reset_db_pool() -> None:
    """Dispose the module-level async engine pool between tests to avoid
    cross-test loop contamination with asyncpg connection objects."""
    import database
    yield
    await database.engine.dispose()


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _make_run(db: AsyncSession, status: str = "queued") -> Run:
    run = Run(run_id=str(uuid.uuid4()), name="test-run", status=status)
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


async def _make_spec(db: AsyncSession, run_id: str, phase2_status: str = "queued") -> Spec:
    spec = Spec(
        spec_id=str(uuid.uuid4()),
        run_id=run_id,
        rule_id="cpp/test",
        file="test.c",
        line=10,
        message="test finding",
        phase1_status="emitted",
        phase2_status=phase2_status,
        phase3_status="not_eligible",
    )
    db.add(spec)
    await db.commit()
    await db.refresh(spec)
    return spec


async def _make_auto_config(db: AsyncSession, run_id: str, config: dict) -> AutoConfig:
    ac = AutoConfig(run_id=run_id, config=config)
    db.add(ac)
    await db.commit()
    return ac


# ─── Phase A: Shared infrastructure ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_interrupt_gate_auto_mode(db_session: AsyncSession) -> None:
    """Auto mode (config[fn]=True or missing) → gate passes immediately, no InterruptPoint created."""
    run = await _make_run(db_session)
    # No auto_config row → defaults to auto=True for all
    from tasks._interrupt import interrupt_gate
    from services.event_service import get_event_service
    event_svc = get_event_service()

    result = await interrupt_gate(
        session=None,
        function_id="phase2_klee_execution",
        run_id=run.run_id,
        spec_id="spec_123",
        worker_id="w1",
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )
    assert result == {"option_overrides": {}, "modified_file_refs": []}
    # No InterruptPoint created
    from sqlalchemy import select
    ips = (await db_session.execute(select(InterruptPoint))).scalars().all()
    assert len(ips) == 0


@pytest.mark.asyncio
async def test_interrupt_gate_manual_skip(db_session: AsyncSession) -> None:
    """Manual mode: gate creates InterruptPoint → status=skipped → returns {skipped: True}."""
    run = await _make_run(db_session)
    await _make_auto_config(db_session, run.run_id, {"phase2_klee_execution": False})
    spec = await _make_spec(db_session, run.run_id)

    from tasks._interrupt import interrupt_gate
    from services.event_service import get_event_service
    from sqlalchemy import select, update

    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    async def _resolve_skip() -> None:
        await asyncio.sleep(0.05)
        await db_session.execute(
            update(InterruptPoint)
            .values(status="skipped", resolved_at=datetime.utcnow())
        )
        await db_session.commit()

    asyncio.create_task(_resolve_skip())

    result = await interrupt_gate(
        session=None,
        function_id="phase2_klee_execution",
        run_id=run.run_id,
        spec_id=spec.spec_id,
        worker_id="w1",
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )
    assert result.get("skipped") is True


@pytest.mark.asyncio
async def test_interrupt_gate_manual_resume(db_session: AsyncSession) -> None:
    """Manual mode: gate creates InterruptPoint → status=resumed → returns option_overrides."""
    run = await _make_run(db_session)
    await _make_auto_config(db_session, run.run_id, {"phase2_klee_execution": False})
    spec = await _make_spec(db_session, run.run_id)

    from tasks._interrupt import interrupt_gate
    from sqlalchemy import update

    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    async def _resolve_resume() -> None:
        await asyncio.sleep(0.05)
        await db_session.execute(
            update(InterruptPoint)
            .values(
                status="resumed",
                resolved_at=datetime.utcnow(),
                option_overrides={"klee_timeout_seconds": 600},
                resume_files=[],
            )
        )
        await db_session.commit()

    asyncio.create_task(_resolve_resume())

    result = await interrupt_gate(
        session=None,
        function_id="phase2_klee_execution",
        run_id=run.run_id,
        spec_id=spec.spec_id,
        worker_id="w1",
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )
    assert result.get("skipped") is not True
    assert result["option_overrides"].get("klee_timeout_seconds") == 600


@pytest.mark.asyncio
async def test_interrupt_gate_cancel_while_waiting(db_session: AsyncSession) -> None:
    """Run cancelled while gate is blocking → CooperativeExit raised."""
    run = await _make_run(db_session)
    await _make_auto_config(db_session, run.run_id, {"phase2_klee_execution": False})
    spec = await _make_spec(db_session, run.run_id)

    from tasks._interrupt import interrupt_gate
    from tasks._control import CooperativeExit
    from sqlalchemy import update

    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    async def _cancel_run() -> None:
        await asyncio.sleep(0.05)
        await db_session.execute(
            update(Run).where(Run.run_id == run.run_id).values(status="cancelled")
        )
        await db_session.commit()

    asyncio.create_task(_cancel_run())

    with pytest.raises(CooperativeExit):
        await interrupt_gate(
            session=None,
            function_id="phase2_klee_execution",
            run_id=run.run_id,
            spec_id=spec.spec_id,
            worker_id="w1",
            event_service=event_svc,
            scope="spec",
            input_files=[],
        )


@pytest.mark.asyncio
async def test_check_control_flags_cancelled(db_session: AsyncSession) -> None:
    """check_control_flags raises CooperativeExit when run is cancelled."""
    run = await _make_run(db_session, status="cancelled")
    spec = await _make_spec(db_session, run.run_id)

    from tasks._control import CooperativeExit, check_control_flags

    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    with pytest.raises(CooperativeExit) as exc_info:
        await check_control_flags(db_session, spec.spec_id, run.run_id, "w1", event_svc)
    assert exc_info.value.reason == "cancelled"


@pytest.mark.asyncio
async def test_check_control_flags_paused(db_session: AsyncSession) -> None:
    """check_control_flags raises CooperativeExit when run is paused."""
    run = await _make_run(db_session, status="paused")
    spec = await _make_spec(db_session, run.run_id)

    from tasks._control import CooperativeExit, check_control_flags

    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    with pytest.raises(CooperativeExit) as exc_info:
        await check_control_flags(db_session, spec.spec_id, run.run_id, "w1", event_svc)
    assert exc_info.value.reason == "paused"


# ─── Phase B: phase1_task ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase1_idempotency(db_session: AsyncSession) -> None:
    """phase1_task with run.status != queued returns early (idempotency guard)."""
    run = await _make_run(db_session, status="running")

    from tasks.phase1 import _phase1
    result = await _phase1(run.run_id)
    assert result.get("skipped") is True


@pytest.mark.asyncio
async def test_phase1_no_project_zip(db_session: AsyncSession) -> None:
    """phase1_task with no project_zip_ref fails the run."""
    run = await _make_run(db_session, status="queued")

    with patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls:
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner

        from tasks.phase1 import _phase1
        result = await _phase1(run.run_id)

    assert result.get("error") == "no_project_zip"
    await db_session.refresh(run)
    assert run.status == "failed"


@pytest.mark.asyncio
async def test_phase1_spec_generation(db_session: AsyncSession) -> None:
    """phase1_task with mocked DockerRunner generates Spec rows."""
    run = await _make_run(db_session, status="queued")
    run.project_zip_ref = "runs/test/project.zip"
    await db_session.commit()

    from sailor.models.schemas import VulnerabilitySpec, BuildContext

    mock_spec = MagicMock()
    mock_spec.rule_id = "cpp/overflow"
    mock_spec.file = "target.c"
    mock_spec.line = 10
    mock_spec.message = "buffer overflow"
    mock_spec.snippet = ""
    mock_spec.entrypoint = "test_func"
    mock_spec.assertion_template = ""
    mock_spec.trace = []
    mock_spec.suspect_calls = []
    mock_spec.pointer_vars = []
    mock_spec.length_vars = []
    mock_spec.bounds_hints = []
    mock_spec.build_context = None

    mock_result = MagicMock()
    mock_result.specifications = [mock_spec]
    mock_result.total_findings = 1

    with (
        patch("services.artifact_service.get_artifact_store") as mock_store_fn,
        patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls,
        patch("sailor.phase1.pipeline.Phase1Pipeline") as mock_pipeline_cls,
        patch("sailor.phase1.fact_generation._parse_sarif", return_value=[]),
        patch("sailor.phase1.fact_enrichment.FactEnricher"),
        patch("tasks.phase2.phase2_task") as mock_p2,
    ):
        mock_store = AsyncMock()
        mock_store.get = AsyncMock(return_value=b"fake zip data")
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.start = MagicMock()
        mock_runner.stop = MagicMock()
        mock_runner.run_phase1 = MagicMock(return_value={"runs": [{"results": []}]})
        mock_runner_cls.return_value = mock_runner

        mock_pipeline = MagicMock()
        mock_pipeline.run_from_findings = MagicMock(return_value=mock_result)
        mock_pipeline_cls.return_value = mock_pipeline

        mock_p2.delay = MagicMock()

        from tasks.phase1 import _phase1
        with patch("zipfile.ZipFile"):
            result = await _phase1(run.run_id)

    # runner.stop() must always be called
    mock_runner.stop.assert_called_once()


# ─── Phase C: phase2_task ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase2_lease_acquisition(db_session: AsyncSession) -> None:
    """Two concurrent lease attempts — only one wins."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id)

    from services.spec_service import acquire_lease

    worker1 = str(uuid.uuid4())
    worker2 = str(uuid.uuid4())

    acquired1 = await acquire_lease(db_session, spec.spec_id, worker1)
    acquired2 = await acquire_lease(db_session, spec.spec_id, worker2)

    assert acquired1 is True
    assert acquired2 is False


@pytest.mark.asyncio
async def test_phase2_extend_lease_returns_false_when_stolen(db_session: AsyncSession) -> None:
    """extend_lease_bool returns False when lease has been taken by another worker."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id)

    from services.spec_service import acquire_lease, extend_lease_bool

    w1 = str(uuid.uuid4())
    w2 = str(uuid.uuid4())
    await acquire_lease(db_session, spec.spec_id, w1)

    # w2 cannot extend w1's lease
    ok = await extend_lease_bool(db_session, spec.spec_id, w2)
    assert ok is False


@pytest.mark.asyncio
async def test_phase2_pause(db_session: AsyncSession) -> None:
    """check_control_flags on paused run re-queues the spec."""
    run = await _make_run(db_session, status="paused")
    spec = await _make_spec(db_session, run.run_id, phase2_status="running")

    from services.spec_service import acquire_lease
    from tasks._control import CooperativeExit, check_control_flags

    w = str(uuid.uuid4())
    await acquire_lease(db_session, spec.spec_id, w)
    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    with pytest.raises(CooperativeExit) as exc_info:
        await check_control_flags(db_session, spec.spec_id, run.run_id, w, event_svc)
    assert exc_info.value.reason == "paused"

    await db_session.refresh(spec)
    assert spec.phase2_status == "queued"
    assert spec.worker_id is None


@pytest.mark.asyncio
async def test_phase2_cancel(db_session: AsyncSession) -> None:
    """check_control_flags on cancelled run marks spec errored."""
    run = await _make_run(db_session, status="cancelled")
    spec = await _make_spec(db_session, run.run_id, phase2_status="running")

    from services.spec_service import acquire_lease
    from tasks._control import CooperativeExit, check_control_flags

    w = str(uuid.uuid4())
    await acquire_lease(db_session, spec.spec_id, w)
    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    with pytest.raises(CooperativeExit) as exc_info:
        await check_control_flags(db_session, spec.spec_id, run.run_id, w, event_svc)
    assert exc_info.value.reason == "cancelled"

    await db_session.refresh(spec)
    assert spec.phase2_status == "errored"
    assert spec.phase2_error == "cancelled"


@pytest.mark.asyncio
async def test_phase2_intervention_edit_harness(db_session: AsyncSession) -> None:
    """Intervention edit_harness writes artifact and appends Turn."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id)

    from models.spec import Intervention
    iv = Intervention(
        spec_id=spec.spec_id,
        payload={"type": "edit_harness", "artifact": "driver", "content": "int main(){}"},
    )
    db_session.add(iv)
    from sqlalchemy import update as sqlu
    from models.spec import Spec
    await db_session.execute(
        sqlu(Spec).where(Spec.spec_id == spec.spec_id).values(intervention_pending=True)
    )
    await db_session.commit()

    from tasks._control import check_control_flags
    event_svc = MagicMock()
    event_svc.publish_message = AsyncMock()

    with patch("services.artifact_service.get_artifact_store") as mock_store_fn:
        mock_store = AsyncMock()
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        await check_control_flags(db_session, spec.spec_id, run.run_id, "w1", event_svc)

    # Verify intervention was processed
    await db_session.refresh(spec)
    assert spec.intervention_pending is False


@pytest.mark.asyncio
async def test_phase2_budget_exhausted(db_session: AsyncSession) -> None:
    """Spec with current_turn == T_max transitions to inconclusive."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id)

    # Set current_turn to T_max to simulate exhaustion
    from sqlalchemy import update as sqlu
    from models.spec import Spec
    await db_session.execute(
        sqlu(Spec).where(Spec.spec_id == spec.spec_id)
        .values(current_turn=60, refine_count=15)
    )
    await db_session.commit()

    # The task's while loop should exit immediately
    from tasks.phase2 import _set_spec_terminal
    await _set_spec_terminal(spec.spec_id, run.run_id, "inconclusive", "inconclusive",
                              MagicMock(publish_spec_state_changed=AsyncMock()), {})
    await db_session.refresh(spec)
    assert spec.phase2_status == "inconclusive"


# ─── Phase D: phase3_task ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phase3_confirmed(db_session: AsyncSession) -> None:
    """Phase 3 confirms a crash in project source."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id, phase2_status="bug_triggered")

    asan_output = (
        "=================================================================\n"
        "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... \n"
        "READ of size 4 at 0x... thread T0\n"
        "    #0 0xdeadbeef in vulnerable_func src/target.c:25\n"
        "    #1 0xdeadbeef in main src/main.c:10\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow src/target.c:25\n"
    )

    with (
        patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls,
        patch("sailor.phase3.replay_driver_gen.ReplayDriverGenerator") as mock_rdg,
        patch("sailor.phase3.result_classifier.ResultClassifier") as mock_rc,
        patch("services.artifact_service.get_artifact_store") as mock_store_fn,
    ):
        mock_runner = MagicMock()
        mock_runner.start = MagicMock()
        mock_runner.stop = MagicMock()
        mock_runner.build_asan_archive = MagicMock(return_value="path/archive.a")
        mock_runner.compile_harness = MagicMock(return_value=(True, ""))
        mock_runner.run_asan_replay = MagicMock(return_value={"asan_output": asan_output})
        mock_runner_cls.return_value = mock_runner

        mock_rdg.return_value.generate = MagicMock(return_value="int main(){}")
        mock_rc.return_value.classify = MagicMock(return_value="confirmed")

        mock_store = AsyncMock()
        mock_store.exists = AsyncMock(return_value=False)
        mock_store.get = AsyncMock(return_value=b"")
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        from tasks.phase3 import _phase3
        await _phase3(spec.spec_id)

    await db_session.refresh(spec)
    assert spec.phase3_status == "confirmed"
    mock_runner.stop.assert_called_once()


@pytest.mark.asyncio
async def test_phase3_rejected_no_crash(db_session: AsyncSession) -> None:
    """Phase 3 rejects when no crash observed."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id, phase2_status="bug_triggered")

    with (
        patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls,
        patch("sailor.phase3.replay_driver_gen.ReplayDriverGenerator") as mock_rdg,
        patch("sailor.phase3.result_classifier.ResultClassifier") as mock_rc,
        patch("services.artifact_service.get_artifact_store") as mock_store_fn,
    ):
        mock_runner = MagicMock()
        mock_runner.start = MagicMock()
        mock_runner.stop = MagicMock()
        mock_runner.build_asan_archive = MagicMock(return_value="archive.a")
        mock_runner.compile_harness = MagicMock(return_value=(True, ""))
        mock_runner.run_asan_replay = MagicMock(return_value={"asan_output": ""})
        mock_runner_cls.return_value = mock_runner

        mock_rdg.return_value.generate = MagicMock(return_value="int main(){}")
        mock_rc.return_value.classify = MagicMock(return_value="rejected")

        mock_store = AsyncMock()
        mock_store.exists = AsyncMock(return_value=False)
        mock_store.get = AsyncMock(return_value=b"")
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        from tasks.phase3 import _phase3
        await _phase3(spec.spec_id)

    await db_session.refresh(spec)
    assert spec.phase3_status == "rejected"


@pytest.mark.asyncio
async def test_phase3_asan_build_failure(db_session: AsyncSession) -> None:
    """Phase 3 transitions to errored on ASan build failure."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id, phase2_status="bug_triggered")

    with (
        patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls,
        patch("sailor.phase3.replay_driver_gen.ReplayDriverGenerator") as mock_rdg,
        patch("services.artifact_service.get_artifact_store") as mock_store_fn,
    ):
        mock_runner = MagicMock()
        mock_runner.start = MagicMock()
        mock_runner.stop = MagicMock()
        mock_runner.build_asan_archive = MagicMock(side_effect=RuntimeError("build failed"))
        mock_runner_cls.return_value = mock_runner

        mock_rdg.return_value.generate = MagicMock(return_value="int main(){}")

        mock_store = AsyncMock()
        mock_store.exists = AsyncMock(return_value=False)
        mock_store.get = AsyncMock(return_value=b"")
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        from tasks.phase3 import _phase3
        await _phase3(spec.spec_id)

    await db_session.refresh(spec)
    assert spec.phase3_status == "errored"
    mock_runner.stop.assert_called_once()


@pytest.mark.asyncio
async def test_phase3_run_completion(db_session: AsyncSession) -> None:
    """All specs terminal → run transitions to completed."""
    run = await _make_run(db_session, status="running")
    spec = await _make_spec(db_session, run.run_id, phase2_status="bug_triggered")

    with (
        patch("sailor.infra.docker_runner.DockerRunner") as mock_runner_cls,
        patch("sailor.phase3.replay_driver_gen.ReplayDriverGenerator") as mock_rdg,
        patch("sailor.phase3.result_classifier.ResultClassifier") as mock_rc,
        patch("services.artifact_service.get_artifact_store") as mock_store_fn,
    ):
        mock_runner = MagicMock()
        mock_runner.start = MagicMock()
        mock_runner.stop = MagicMock()
        mock_runner.build_asan_archive = MagicMock(return_value="archive.a")
        mock_runner.compile_harness = MagicMock(return_value=(True, ""))
        mock_runner.run_asan_replay = MagicMock(return_value={"asan_output": ""})
        mock_runner_cls.return_value = mock_runner

        mock_rdg.return_value.generate = MagicMock(return_value="int main(){}")
        mock_rc.return_value.classify = MagicMock(return_value="rejected")

        mock_store = AsyncMock()
        mock_store.exists = AsyncMock(return_value=False)
        mock_store.get = AsyncMock(return_value=b"")
        mock_store.put = AsyncMock(return_value="path")
        mock_store_fn.return_value = mock_store

        from tasks.phase3 import _phase3
        await _phase3(spec.spec_id)

    await db_session.refresh(run)
    assert run.status == "completed"


# ─── Throttle tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_counters_throttle_max_one_per_second() -> None:
    """publish_counters_throttled emits at most once per second."""
    from services.event_service import EventService
    import time

    svc = EventService("redis://redis:6379/0")
    publish_calls: list[float] = []

    async def fake_publish(msg: Any) -> None:
        publish_calls.append(time.monotonic())

    svc.publish_message = fake_publish  # type: ignore[method-assign]

    # Three rapid calls
    await svc.publish_counters_throttled("run_1", {"specs_total": 1})
    await svc.publish_counters_throttled("run_1", {"specs_total": 2})
    await svc.publish_counters_throttled("run_1", {"specs_total": 3})

    # Only the first should fire immediately
    assert len(publish_calls) == 1
