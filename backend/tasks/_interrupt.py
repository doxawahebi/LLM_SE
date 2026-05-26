"""Interrupt gate implementation for pipeline function checkpoints.

Implements interactive_control_spec.md §4.3 for workers.
Uses PipelineFunctionId values from shared/contracts/sailor.schema.json (14 values).
"""

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sailor.tasks.interrupt")


def _deterministic_interrupt_id(run_id: str, spec_id: str, function_id: str) -> str:
    """Produce a deterministic ID for an interrupt point."""
    key = f"{run_id}:{spec_id}:{function_id}:interrupt"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


async def interrupt_gate(
    session: AsyncSession,
    function_id: str,
    run_id: str,
    spec_id: str | None,
    worker_id: str,
    event_service: Any,
    scope: str,
    input_files: list[dict[str, Any]],
    current_turn: int = 0,
) -> dict[str, Any]:
    """Check AutoConfig; if manual mode, create InterruptPoint and block until resolved.

    Returns:
        {"option_overrides": dict, "modified_file_refs": list}
        or {"option_overrides": {}, "modified_file_refs": [], "skipped": True}
    """
    from models.auto_config import AutoConfig
    from models.interrupt_point import InterruptPoint

    # Read AutoConfig — always use own session (callers pass session=None)
    async with _get_new_session() as cfg_session:
        auto_cfg_row = await cfg_session.scalar(
            select(AutoConfig).where(AutoConfig.run_id == run_id)
        )
        config: dict[str, Any] = {}
        if auto_cfg_row and auto_cfg_row.config:
            config = auto_cfg_row.config

    # Auto mode — gate passes immediately
    if config.get(function_id, True):
        return {"option_overrides": {}, "modified_file_refs": []}

    # Manual mode — create or load existing interrupt point
    interrupt_id = _deterministic_interrupt_id(run_id, spec_id or "", function_id)

    async with _get_new_session() as ip_session:
        existing = await ip_session.get(InterruptPoint, interrupt_id)

        if existing is None:
            ip = InterruptPoint(
                interrupt_id=interrupt_id,
                run_id=run_id,
                spec_id=spec_id,
                function_name=function_id,
                scope=scope,
                turn=current_turn,
                status="waiting",
                input_files=input_files,
                option_overrides={},
                created_at=datetime.utcnow(),
            )
            ip_session.add(ip)
            await ip_session.commit()
            await ip_session.refresh(ip)
            logger.info("Interrupt gate created: %s / %s / %s", run_id, spec_id, function_id)
            await _publish_interrupt_created(run_id, spec_id, ip, event_service)
        else:
            ip = existing
            # Already resolved from a prior attempt
            if ip.status == "resumed":
                return {
                    "option_overrides": ip.option_overrides or {},
                    "modified_file_refs": [f["artifact_ref"] for f in (ip.resume_files or [])],
                }
            if ip.status == "skipped":
                return {"option_overrides": {}, "modified_file_refs": [], "skipped": True}

    # Poll until resolved
    lease_extension_counter = 0
    while True:
        await asyncio.sleep(2)
        lease_extension_counter += 1

        # Extend lease every ~60s (30 iterations × 2s)
        if lease_extension_counter >= 30:
            lease_extension_counter = 0
            from services.spec_service import extend_lease_bool
            async with _get_new_session() as ext_session:
                if spec_id:
                    ok = await extend_lease_bool(ext_session, spec_id, worker_id)
                    if not ok:
                        from tasks._control import CooperativeExit
                        raise CooperativeExit("lease_lost_during_interrupt")

        # Check control flags
        from tasks._control import check_control_flags, CooperativeExit
        async with _get_new_session() as ctrl_session:
            try:
                await check_control_flags(
                    ctrl_session, spec_id or run_id, run_id, worker_id, event_service
                )
            except CooperativeExit:
                # Skip the interrupt on cancel/pause
                async with _get_new_session() as res_session:
                    await res_session.execute(
                        update(InterruptPoint)
                        .where(InterruptPoint.interrupt_id == interrupt_id)
                        .values(status="skipped", resolved_at=datetime.utcnow(),
                                resolved_by="system")
                    )
                    await res_session.commit()
                raise

        # Poll for resolution
        async with _get_new_session() as poll_session:
            ip_row = await poll_session.get(InterruptPoint, interrupt_id)
            if ip_row is None:
                break  # should not happen; treat as skipped
            if ip_row.status == "resumed":
                await _publish_interrupt_resolved(run_id, spec_id, ip_row, event_service)
                return {
                    "option_overrides": ip_row.option_overrides or {},
                    "modified_file_refs": [
                        f["artifact_ref"] for f in (ip_row.resume_files or [])
                    ],
                }
            if ip_row.status == "skipped":
                await _publish_interrupt_resolved(run_id, spec_id, ip_row, event_service)
                return {"option_overrides": {}, "modified_file_refs": [], "skipped": True}

    return {"option_overrides": {}, "modified_file_refs": [], "skipped": True}


def _get_new_session():
    """Return a new async session context manager."""
    from database import AsyncSessionLocal
    return AsyncSessionLocal()


async def _publish_interrupt_created(
    run_id: str,
    spec_id: str | None,
    ip: Any,
    event_service: Any,
) -> None:
    """Publish interrupt_created SSE on runs.<run_id> and runs.<run_id>.specs."""
    try:
        from shared.contracts.sailor_models import (
            InterruptCreatedPayload,
            InterruptPoint as IPModel,
            SSEMessageInterruptCreated,
        )

        ip_model = IPModel(
            interrupt_id=ip.interrupt_id,
            run_id=ip.run_id,
            spec_id=ip.spec_id,
            function_name=ip.function_name,
            scope=ip.scope,
            turn=ip.turn,
            status=ip.status,
            created_at=ip.created_at.isoformat() + "Z" if ip.created_at else datetime.utcnow().isoformat() + "Z",
            input_files=ip.input_files or [],
            option_overrides=ip.option_overrides or {},
        )
        payload = InterruptCreatedPayload(interrupt=ip_model)
        now = datetime.utcnow().isoformat() + "Z"

        for topic in [f"runs.{run_id}", f"runs.{run_id}.specs"]:
            msg = SSEMessageInterruptCreated(
                topic=topic,
                sequence=0,
                timestamp=now,
                kind="interrupt_created",
                payload=payload,
            )
            await event_service.publish_message(msg)
    except Exception as exc:
        logger.debug("SSE publish interrupt_created error (best-effort): %s", exc)


async def _publish_interrupt_resolved(
    run_id: str,
    spec_id: str | None,
    ip: Any,
    event_service: Any,
) -> None:
    """Publish interrupt_resolved SSE."""
    try:
        from shared.contracts.sailor_models import (
            InterruptResolvedPayload,
            InterruptPoint as IPModel,
            SSEMessageInterruptResolved,
        )

        ip_model = IPModel(
            interrupt_id=ip.interrupt_id,
            run_id=ip.run_id,
            spec_id=ip.spec_id,
            function_name=ip.function_name,
            scope=ip.scope,
            turn=ip.turn,
            status=ip.status,
            created_at=ip.created_at.isoformat() + "Z" if ip.created_at else datetime.utcnow().isoformat() + "Z",
            resolved_at=ip.resolved_at.isoformat() + "Z" if ip.resolved_at else None,
            resolved_by=ip.resolved_by,
            input_files=ip.input_files or [],
            option_overrides=ip.option_overrides or {},
        )
        payload = InterruptResolvedPayload(interrupt=ip_model)
        now = datetime.utcnow().isoformat() + "Z"

        for topic in [f"runs.{run_id}", f"runs.{run_id}.specs"]:
            msg = SSEMessageInterruptResolved(
                topic=topic,
                sequence=0,
                timestamp=now,
                kind="interrupt_resolved",
                payload=payload,
            )
            await event_service.publish_message(msg)
    except Exception as exc:
        logger.debug("SSE publish interrupt_resolved error (best-effort): %s", exc)
