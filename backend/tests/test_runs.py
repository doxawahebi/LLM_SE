"""Tests for run state transitions."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from models.run import Run
from services.run_service import create_run, get_run, transition_run


@pytest.mark.asyncio
async def test_create_run(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="test-run")
    assert run.run_id is not None
    assert run.name == "test-run"
    assert run.status == "created"


@pytest.mark.asyncio
async def test_run_state_transitions(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="transition-test")
    run_id = run.run_id

    # created → queued
    updated = await transition_run(db_session, run_id, "queued", ["created"])
    assert updated is not None
    assert updated.status == "queued"

    # queued → running
    updated = await transition_run(db_session, run_id, "running", ["queued"])
    assert updated is not None

    # running → paused
    updated = await transition_run(db_session, run_id, "paused", ["running"])
    assert updated is not None

    # paused → running
    updated = await transition_run(db_session, run_id, "running", ["paused"])
    assert updated is not None

    # running → completed
    updated = await transition_run(db_session, run_id, "completed", ["running"])
    assert updated is not None
    assert updated.completed_at is not None


@pytest.mark.asyncio
async def test_invalid_transition_rejected(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="invalid-transition")
    run_id = run.run_id

    # Try to transition from created → completed (invalid)
    updated = await transition_run(db_session, run_id, "completed", ["running"])
    assert updated is None  # zero rows matched → rejected


@pytest.mark.asyncio
async def test_get_run(db_session: AsyncSession) -> None:
    run = await create_run(db_session, name="fetch-test")
    fetched = await get_run(db_session, run.run_id)
    assert fetched is not None
    assert fetched.run_id == run.run_id

    missing = await get_run(db_session, "nonexistent-id")
    assert missing is None
