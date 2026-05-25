"""Tests for intervention handling and optimistic concurrency."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from models.spec import Spec
from services.run_service import create_run
from services.spec_service import add_intervention, get_spec, pop_intervention


async def _create_spec(db: AsyncSession, run_id: str) -> Spec:
    spec = Spec(
        spec_id=str(uuid.uuid4()),
        run_id=run_id,
        rule_id="cpp/test",
        file="test.c",
        line=10,
    )
    db.add(spec)
    await db.commit()
    await db.refresh(spec)
    return spec


@pytest.mark.asyncio
async def test_add_and_pop_intervention(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="intervene-test")
    spec = await _create_spec(db_session, run.run_id)

    payload = {"type": "force_outcome", "outcome": "mark_inconclusive"}
    iv = await add_intervention(db_session, spec.spec_id, payload)
    assert iv.spec_id == spec.spec_id
    assert iv.applied is False

    # Spec should have intervention_pending = True
    fetched = await get_spec(db_session, spec.spec_id)
    assert fetched.intervention_pending is True

    # Pop the intervention
    popped = await pop_intervention(db_session, spec.spec_id)
    assert popped is not None
    assert popped.payload == payload

    # intervention_pending should now be False
    fetched = await get_spec(db_session, spec.spec_id)
    assert fetched.intervention_pending is False


@pytest.mark.asyncio
async def test_multiple_interventions_ordered(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="multi-intervene")
    spec = await _create_spec(db_session, run.run_id)

    p1 = {"type": "force_outcome", "outcome": "mark_inconclusive"}
    p2 = {"type": "force_outcome", "outcome": "mark_likely_fp"}
    await add_intervention(db_session, spec.spec_id, p1)
    await add_intervention(db_session, spec.spec_id, p2)

    first = await pop_intervention(db_session, spec.spec_id)
    assert first.payload == p1

    # intervention_pending still True (p2 remains)
    fetched = await get_spec(db_session, spec.spec_id)
    assert fetched.intervention_pending is True

    second = await pop_intervention(db_session, spec.spec_id)
    assert second.payload == p2

    fetched = await get_spec(db_session, spec.spec_id)
    assert fetched.intervention_pending is False
