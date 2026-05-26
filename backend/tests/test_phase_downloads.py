"""Tests for phase-level download endpoints (presigned redirect)."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch

from models.run import Run
from models.spec import Spec
from models.user import User
from services.auth_service import create_access_token, hash_password
from services.run_service import create_run


async def _make_user(db: AsyncSession, role: str = "viewer") -> tuple[User, str]:
    u = User(username=f"u_{uuid.uuid4().hex[:8]}", hashed_password=hash_password("pw"), role=role)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u, create_access_token(u.user_id, u.role)


async def _make_spec(db: AsyncSession, run_id: str) -> Spec:
    spec = Spec(
        spec_id=str(uuid.uuid4()),
        run_id=run_id,
        rule_id="cpp/test",
        file="test.c",
        line=1,
    )
    db.add(spec)
    await db.commit()
    await db.refresh(spec)
    return spec


FAKE_PRESIGN_URL = "http://minio:9000/sailor-artifacts/fake?X-Amz-Signature=abc"


@pytest.mark.asyncio
async def test_phase1_artifact_redirect(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test")

    with patch(
        "api.phase_downloads._presign",
        new=AsyncMock(return_value=FAKE_PRESIGN_URL),
    ):
        resp = await client.get(
            f"/api/runs/{run.run_id}/phase1/artifacts/findings.sarif",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert resp.headers["location"] == FAKE_PRESIGN_URL


@pytest.mark.asyncio
async def test_phase1_tarball_redirect(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test2")

    with patch("api.phase_downloads._presign", new=AsyncMock(return_value=FAKE_PRESIGN_URL)):
        resp = await client.get(
            f"/api/runs/{run.run_id}/phase1/artifacts.tar.gz",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_phase2_artifact_redirect(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test3")
    spec = await _make_spec(db_session, run.run_id)

    with patch("api.phase_downloads._presign", new=AsyncMock(return_value=FAKE_PRESIGN_URL)):
        resp = await client.get(
            f"/api/runs/{run.run_id}/specs/{spec.spec_id}/phase2/artifacts/driver.c",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_phase3_artifact_redirect(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test4")
    spec = await _make_spec(db_session, run.run_id)

    with patch("api.phase_downloads._presign", new=AsyncMock(return_value=FAKE_PRESIGN_URL)):
        resp = await client.get(
            f"/api/runs/{run.run_id}/specs/{spec.spec_id}/phase3/artifacts/asan_report.txt",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_evidence_package_redirect(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test5")
    spec = await _make_spec(db_session, run.run_id)

    with patch("api.phase_downloads._presign", new=AsyncMock(return_value=FAKE_PRESIGN_URL)):
        resp = await client.get(
            f"/api/runs/{run.run_id}/specs/{spec.spec_id}/evidence.tar.gz",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_phase1_artifact_run_not_found(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    resp = await client.get(
        "/api/runs/nonexistent-run/phase1/artifacts/findings.sarif",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_phase2_artifact_spec_not_found(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    run = await create_run(db_session, name="dl-test6")
    resp = await client.get(
        f"/api/runs/{run.run_id}/specs/bad-spec-id/phase2/artifacts/driver.c",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
