"""Control-flag check and intervention application for Celery workers.

Called at every turn boundary before executing any phase logic.
Order: cancel → paused → intervention_pending.
"""

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sailor.tasks.control")


class CooperativeExit(Exception):
    """Raised when a worker must stop cleanly (pause, cancel, or lease lost)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


async def check_control_flags(
    session: AsyncSession,
    spec_id: str,
    run_id: str,
    worker_id: str,
    event_service: Any,  # EventService — avoid circular import
) -> None:
    """Check run/spec control flags; raise CooperativeExit if worker must stop.

    Must be called before every turn and inside every interrupt-gate polling loop.
    Processing order: cancel → paused → intervention_pending.
    """
    from models.run import Run
    from models.spec import Spec

    run = await session.get(Run, run_id)
    if run is None:
        raise CooperativeExit("run_not_found")

    if run.status == "cancelled":
        await session.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id, Spec.worker_id == worker_id)
            .values(phase2_status="errored", phase2_error="cancelled",
                    worker_id=None, locked_until=None)
        )
        await session.commit()
        try:
            await _publish_spec_state_changed(run_id, spec_id, event_service)
        except Exception:
            pass
        raise CooperativeExit("cancelled")

    if run.status == "paused":
        await session.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id, Spec.worker_id == worker_id)
            .values(phase2_status="queued", worker_id=None, locked_until=None)
        )
        await session.commit()
        raise CooperativeExit("paused")

    # Intervention pending — process list in submission order
    from models.spec import Intervention
    spec = await session.get(Spec, spec_id)
    if spec and spec.intervention_pending:
        interventions = (
            await session.execute(
                select(Intervention)
                .where(Intervention.spec_id == spec_id, Intervention.applied == False)  # noqa: E712
                .order_by(Intervention.created_at)
            )
        ).scalars().all()

        for iv in interventions:
            await apply_intervention(session, spec_id, worker_id, iv.payload, event_service)
            await session.execute(
                update(Intervention)
                .where(Intervention.intervention_id == iv.intervention_id)
                .values(applied=True)
            )

        await session.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(intervention_pending=False)
        )
        await session.commit()
        try:
            await _publish_spec_intervention_applied(run_id, spec_id, event_service)
        except Exception:
            pass


async def apply_intervention(
    session: AsyncSession,
    spec_id: str,
    worker_id: str,
    payload: dict[str, Any],
    event_service: Any,
) -> None:
    """Dispatch an intervention payload to the appropriate handler."""
    intervention_type = payload.get("type")
    if intervention_type == "edit_harness":
        await _apply_edit_harness(session, spec_id, worker_id, payload)
    elif intervention_type == "force_outcome":
        await _apply_force_outcome(session, spec_id, payload, event_service)
    elif intervention_type == "edit_spec":
        await _apply_edit_spec(session, spec_id, payload)
    else:
        logger.warning("Unknown intervention type %r for spec %s", intervention_type, spec_id)


async def _apply_edit_harness(
    session: AsyncSession,
    spec_id: str,
    worker_id: str,
    payload: dict[str, Any],
) -> None:
    """Write new harness artifact draft and append an intervention turn."""
    from models.turn import Turn
    from services.artifact_service import get_artifact_store

    artifact = payload.get("artifact", "driver")
    new_content = payload.get("content", "")

    store = get_artifact_store()
    # Load spec to find run_id and version counter
    from models.spec import Spec
    spec = await session.get(Spec, spec_id)
    if not spec:
        return
    run_id = spec.run_id

    # Write to version-suffixed path
    version = (spec.turn_count_total or 0) + 1
    artifact_path = f"runs/{run_id}/phase2/{spec_id}/drafts/{artifact}.v{version}.c"
    await store.put(artifact_path, new_content.encode() if isinstance(new_content, str) else new_content)

    # Append intervention Turn
    now = datetime.utcnow()
    turn = Turn(
        spec_id=spec_id,
        turn_number=spec.current_turn,
        kind="intervention",
        summary=f"harness edited: {artifact}",
        payload_ref=artifact_path,
        started_at=now,
        ended_at=now,
    )
    session.add(turn)
    await session.commit()


async def _apply_force_outcome(
    session: AsyncSession,
    spec_id: str,
    payload: dict[str, Any],
    event_service: Any,
) -> None:
    """Force a terminal outcome for the spec."""
    from models.spec import Spec
    from models.turn import Turn

    action = payload.get("action", "mark_inconclusive")
    spec = await session.get(Spec, spec_id)
    if not spec:
        return
    run_id = spec.run_id

    now = datetime.utcnow()
    turn = Turn(
        spec_id=spec_id,
        turn_number=spec.current_turn,
        kind="intervention",
        summary=f"force_outcome: {action}",
        started_at=now,
        ended_at=now,
    )
    session.add(turn)

    if action in ("mark_inconclusive", "mark_likely_fp"):
        terminal_status = "inconclusive" if action == "mark_inconclusive" else "likely_false_positive"
        await session.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(phase2_status=terminal_status, phase2_outcome=terminal_status,
                    worker_id=None, locked_until=None)
        )
        await session.commit()
        raise CooperativeExit(f"force_outcome:{action}")

    elif action == "skip_to_phase3":
        # Store provided ktest as witness artifact (payload may contain ktest_ref)
        await session.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(phase2_status="bug_triggered", phase2_outcome="bug_triggered",
                    worker_id=None, locked_until=None)
        )
        await session.commit()
        from tasks.phase3 import phase3_task
        phase3_task.delay(spec_id)
        raise CooperativeExit("force_outcome:skip_to_phase3")


async def _apply_edit_spec(
    session: AsyncSession,
    spec_id: str,
    payload: dict[str, Any],
) -> None:
    """Replace spec fields and reset Phase 2 state; loop restarts from turn 0."""
    from models.spec import Spec
    from models.turn import Turn

    spec = await session.get(Spec, spec_id)
    if not spec:
        return

    # Append intervention Turn before reset
    now = datetime.utcnow()
    turn = Turn(
        spec_id=spec_id,
        turn_number=spec.current_turn,
        kind="intervention",
        summary="spec replaced",
        started_at=now,
        ended_at=now,
    )
    session.add(turn)

    # Reset Phase 2 state
    updates: dict[str, Any] = {
        "current_turn": 0,
        "turn_count_total": 0,
        "refine_count": 0,
        "phase2_status": "queued",
        "phase2_outcome": None,
        "phase2_error": None,
    }
    # Update spec fields from payload
    for field in ("rule_id", "message", "entrypoint", "assertion_template"):
        if field in payload:
            updates[field] = payload[field]

    await session.execute(
        update(Spec).where(Spec.spec_id == spec_id).values(**updates)
    )
    await session.commit()


async def _publish_spec_state_changed(run_id: str, spec_id: str, event_service: Any) -> None:
    """Publish spec_state_changed SSE — best-effort."""
    try:
        from datetime import timezone
        from shared.contracts.sailor_models import (
            SSEMessageSpecStateChanged,
            SpecStateChangedPayload,
        )
        from services.spec_service import get_spec
        from database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            spec_orm = await get_spec(db, spec_id)
        if spec_orm is None:
            return

        payload = SpecStateChangedPayload(spec=_orm_spec_to_model(spec_orm))
        msg = SSEMessageSpecStateChanged(
            topic=f"runs.{run_id}.specs",
            sequence=0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            kind="spec_state_changed",
            payload=payload,
        )
        await event_service.publish_message(msg)
        msg2 = SSEMessageSpecStateChanged(
            topic=f"runs.{run_id}.specs.{spec_id}",
            sequence=0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            kind="spec_state_changed",
            payload=payload,
        )
        await event_service.publish_message(msg2)
    except Exception as exc:
        logger.debug("SSE publish error (best-effort): %s", exc)


async def _publish_spec_intervention_applied(
    run_id: str, spec_id: str, event_service: Any
) -> None:
    """Publish spec_intervention_applied SSE — best-effort."""
    try:
        from shared.contracts.sailor_models import (
            SSEMessageSpecInterventionApplied,
            SpecInterventionAppliedPayload,
        )
        msg = SSEMessageSpecInterventionApplied(
            topic=f"runs.{run_id}.specs.{spec_id}",
            sequence=0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            kind="spec_intervention_applied",
            payload=SpecInterventionAppliedPayload(spec_id=spec_id),
        )
        await event_service.publish_message(msg)
    except Exception as exc:
        logger.debug("SSE publish error (best-effort): %s", exc)


def _orm_spec_to_model(spec_orm: Any) -> Any:
    """Convert ORM Spec to Pydantic Spec model (best-effort)."""
    from shared.contracts.sailor_models import Spec as SpecModel
    try:
        return SpecModel(
            spec_id=spec_orm.spec_id,
            run_id=spec_orm.run_id,
            rule_id=spec_orm.rule_id or "",
            file=spec_orm.file or "",
            line=spec_orm.line or 0,
            message=spec_orm.message or "",
            phase1_status=spec_orm.phase1_status or "emitted",
            phase2_status=spec_orm.phase2_status,
            phase3_status=spec_orm.phase3_status,
            current_turn=spec_orm.current_turn,
            turn_count_total=spec_orm.turn_count_total,
        )
    except Exception:
        return None
