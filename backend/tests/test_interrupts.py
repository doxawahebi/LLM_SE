"""Tests for interrupt panel state, file validation, and user registration."""

import base64
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from models.interrupt_point import InterruptPoint
from models.run import Run
from models.user import User
from services.auth_service import create_access_token, hash_password
from services.run_service import create_run


async def _make_user(db: AsyncSession, role: str = "admin") -> tuple[User, str]:
    u = User(username=f"u_{uuid.uuid4().hex[:8]}", hashed_password=hash_password("pw"), role=role)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    token = create_access_token(u.user_id, u.role)
    return u, token


async def _make_run(db: AsyncSession, user_id: str) -> Run:
    return await create_run(db, name="interrupt-test", created_by=user_id)


async def _make_interrupt(db: AsyncSession, run_id: str, spec_id: str | None = None) -> InterruptPoint:
    ip = InterruptPoint(
        run_id=run_id,
        spec_id=spec_id,
        function_name="phase2.klee_execution",
        phase=2,
        turn=5,
        status="waiting",
    )
    db.add(ip)
    await db.commit()
    await db.refresh(ip)
    return ip


# ─── Interrupt panel tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_interrupts_empty(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, "user")
    resp = await client.get(
        f"/api/runs/{run.run_id}/interrupts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_interrupts_returns_waiting(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, "user")
    ip = await _make_interrupt(db_session, run.run_id)
    resp = await client.get(
        f"/api/runs/{run.run_id}/interrupts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["interrupt_id"] == ip.interrupt_id
    assert data[0]["status"] == "waiting"


@pytest.mark.asyncio
async def test_interrupt_skip(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/skip",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "skipped"

    # Verify it no longer appears in waiting list
    list_resp = await client.get(
        f"/api/runs/{run.run_id}/interrupts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.json() == []


@pytest.mark.asyncio
async def test_interrupt_skip_idempotent_fails(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/skip",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/skip",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_interrupt_resume_with_modified_file(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    content = b"int main() { return 0; }"
    payload = {
        "modified_files": [
            {"name": "driver.c", "content_base64": base64.b64encode(content).decode()}
        ],
        "option_overrides": {"klee_timeout": 600},
    }
    resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/resume",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "resumed"


# ─── File validation tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_pdf_as_sarif_returns_error(client: AsyncClient) -> None:
    pdf_content = b"%PDF-1.4 fake pdf content"
    resp = await client.post(
        "/api/validate/file",
        json={
            "filename": "findings.sarif",
            "content_base64": base64.b64encode(pdf_content).decode(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["severity"] == "error"
    assert "pdf" in data["detected_format"].lower()


@pytest.mark.asyncio
async def test_validate_valid_sarif(client: AsyncClient) -> None:
    sarif = b'{"version":"2.1.0","runs":[{"results":[{"message":{"text":"x"},"locations":[]}]}]}'
    resp = await client.post(
        "/api/validate/file",
        json={
            "filename": "findings.sarif",
            "content_base64": base64.b64encode(sarif).decode(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_validate_sarif_missing_runs(client: AsyncClient) -> None:
    bad = b'{"version":"2.1.0","no_runs":[]}'
    resp = await client.post(
        "/api/validate/file",
        json={
            "filename": "findings.sarif",
            "content_base64": base64.b64encode(bad).decode(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["severity"] == "error"


@pytest.mark.asyncio
async def test_validate_ktest_bad_magic(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/validate/file",
        json={
            "filename": "witness.ktest",
            "content_base64": base64.b64encode(b"notaktest").decode(),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


@pytest.mark.asyncio
async def test_validate_ktest_good_magic(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/validate/file",
        json={
            "filename": "witness.ktest",
            "content_base64": base64.b64encode(b"KTESTxxx").decode(),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


# ─── User registration tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_first_registration_gets_admin(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "firstuser",
            "email": "first@example.com",
            "password": "securepassword123",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"
    assert data["username"] == "firstuser"


@pytest.mark.asyncio
async def test_second_registration_gets_viewer(client: AsyncClient) -> None:
    # First user
    await client.post(
        "/api/auth/register",
        json={"username": "admin_user", "email": "a@x.com", "password": "pass1"},
    )
    # Second user
    resp = await client.post(
        "/api/auth/register",
        json={"username": "viewer_user", "email": "v@x.com", "password": "pass2"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_duplicate_username_rejected(client: AsyncClient) -> None:
    await client.post(
        "/api/auth/register",
        json={"username": "dupuser", "email": "d@x.com", "password": "pass"},
    )
    resp = await client.post(
        "/api/auth/register",
        json={"username": "dupuser", "email": "d2@x.com", "password": "pass"},
    )
    assert resp.status_code == 400
