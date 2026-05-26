"""Pytest fixtures for backend tests."""

import asyncio
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from database import get_db
from main import app

TEST_DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://sailor:sailor@postgres:5432/sailor",
)

# Tables to truncate (in dependency order so CASCADE isn't needed)
TRUNCATE_TABLES = [
    "interrupt_points", "auto_config",
    "interventions", "turns", "verdicts", "specs",
    "audit_events", "log_lines", "export_jobs", "idempotency_keys",
    "runs", "users",
]


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    """Fresh engine + session per test; truncate all tables after."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        yield session

    # Cleanup with a fresh connection to avoid state issues
    async with engine.connect() as conn:
        await conn.execute(text("SET session_replication_role = 'replica'"))
        for table in TRUNCATE_TABLES:
            await conn.execute(text(f"DELETE FROM {table}"))
        await conn.execute(text("SET session_replication_role = 'origin'"))
        await conn.commit()

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
