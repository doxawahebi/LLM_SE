"""Tests for spec operations and lease management."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from models.spec import Spec
from services.run_service import create_run
from services.spec_service import acquire_lease, extend_lease, get_spec, release_lease


async def _create_spec(db: AsyncSession, run_id: str) -> Spec:
    spec = Spec(
        spec_id=str(uuid.uuid4()),
        run_id=run_id,
        rule_id="cpp/test",
        file="test.c",
        line=42,
    )
    db.add(spec)
    await db.commit()
    await db.refresh(spec)
    return spec


@pytest.mark.asyncio
async def test_lease_acquisition(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="lease-test")
    spec = await _create_spec(db_session, run.run_id)

    worker_id = str(uuid.uuid4())
    acquired = await acquire_lease(db_session, spec.spec_id, worker_id)
    assert acquired is True

    # Second worker cannot acquire same lease
    acquired2 = await acquire_lease(db_session, spec.spec_id, str(uuid.uuid4()))
    assert acquired2 is False


@pytest.mark.asyncio
async def test_lease_release(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="release-test")
    spec = await _create_spec(db_session, run.run_id)

    worker_id = str(uuid.uuid4())
    await acquire_lease(db_session, spec.spec_id, worker_id)
    await release_lease(db_session, spec.spec_id, worker_id)

    # After release, another worker can acquire
    acquired = await acquire_lease(db_session, spec.spec_id, str(uuid.uuid4()))
    assert acquired is True


@pytest.mark.asyncio
async def test_get_spec(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="get-spec-test")
    spec = await _create_spec(db_session, run.run_id)

    fetched = await get_spec(db_session, spec.spec_id)
    assert fetched is not None
    assert fetched.spec_id == spec.spec_id

    missing = await get_spec(db_session, "nonexistent")
    assert missing is None
