"""Tests for interrupt panel state, file validation, and user registration."""

import io
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
        function_name="phase2_klee_execution",  # flat snake_case PipelineFunctionId, no dots
        scope="spec",
        turn=5,
        status="waiting",
        input_files=[],
        option_overrides={},
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
    # No 'phase' field in response
    assert "phase" not in data[0]
    # Must have scope and function_name
    assert data[0]["function_name"] == "phase2_klee_execution"
    assert data[0]["scope"] == "spec"


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
    data = resp.json()
    assert data["interrupt"]["status"] == "skipped"

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
async def test_interrupt_resume_via_files_upload(client: AsyncClient, db_session: AsyncSession) -> None:
    """Resume flow: upload file first, then resume with artifact_ref."""
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    c_content = b"int main() { return 0; }"

    # Step 1: upload file via /files endpoint
    upload_resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/files",
        files={"file": ("driver.c", io.BytesIO(c_content), "text/plain")},
        data={"name": "driver.c"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert upload_resp.status_code == 200
    upload_data = upload_resp.json()
    assert "artifact_ref" in upload_data
    assert "validation" in upload_data
    artifact_ref = upload_data["artifact_ref"]

    # Step 2: resume with the artifact_ref
    resume_resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/resume",
        json={
            "modified_files": [{"name": "driver.c", "artifact_ref": artifact_ref}],
            "option_overrides": {"klee_timeout_seconds": 600},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resume_resp.status_code == 200
    assert resume_resp.json()["interrupt"]["status"] == "resumed"


@pytest.mark.asyncio
async def test_interrupt_resume_with_unknown_artifact_ref(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/resume",
        json={"modified_files": [{"name": "driver.c", "artifact_ref": "unknown/path/driver.c"}]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "unknown_artifact_ref"


@pytest.mark.asyncio
async def test_interrupt_resume_bulk_with_files_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    """apply_to_all_matching=true with non-empty modified_files must return 422."""
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)
    ip = await _make_interrupt(db_session, run.run_id)

    resp = await client.post(
        f"/api/runs/{run.run_id}/interrupts/{ip.interrupt_id}/resume",
        json={
            "apply_to_all_matching": True,
            "modified_files": [{"name": "driver.c", "artifact_ref": "some/ref"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "bulk_modify_with_files"


# ─── Auto-config tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auto_config_dotted_key_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    """PATCH auto-config with dotted key must return 422 code=invalid_function_name."""
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)

    resp = await client.patch(
        f"/api/runs/{run.run_id}/auto-config",
        json={"phase2.klee_execution": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["code"] == "invalid_function_name"


@pytest.mark.asyncio
async def test_auto_config_valid_patch(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _make_user(db_session, role="admin")
    run = await _make_run(db_session, user.user_id)

    resp = await client.patch(
        f"/api/runs/{run.run_id}/auto-config",
        json={"phase2_klee_execution": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["phase2_klee_execution"] is False


# ─── File validation tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_pdf_as_sarif_returns_error(client: AsyncClient) -> None:
    pdf_content = b"%PDF-1.4 fake pdf content"
    resp = await client.post(
        "/api/validate/file",
        files={"file": ("findings.sarif", io.BytesIO(pdf_content), "application/octet-stream")},
        data={"filename": "findings.sarif"},
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
        files={"file": ("findings.sarif", io.BytesIO(sarif), "application/json")},
        data={"filename": "findings.sarif"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_validate_sarif_missing_runs(client: AsyncClient) -> None:
    bad = b'{"version":"2.1.0","no_runs":[]}'
    resp = await client.post(
        "/api/validate/file",
        files={"file": ("findings.sarif", io.BytesIO(bad), "application/json")},
        data={"filename": "findings.sarif"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["severity"] == "error"
    # Must have issues list
    assert data["issues"] is not None
    assert any(i["rule"] == "sarif.missing_runs" for i in data["issues"])


@pytest.mark.asyncio
async def test_validate_ktest_bad_magic(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/validate/file",
        files={"file": ("witness.ktest", io.BytesIO(b"notaktest"), "application/octet-stream")},
        data={"filename": "witness.ktest"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


@pytest.mark.asyncio
async def test_validate_ktest_good_magic(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/validate/file",
        files={"file": ("witness.ktest", io.BytesIO(b"KTESTxxx"), "application/octet-stream")},
        data={"filename": "witness.ktest"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_validate_replay_driver_klee_call_rejected(client: AsyncClient) -> None:
    """replay_driver.c with klee_make_symbolic must return severity=error."""
    content = b'#include "klee/klee.h"\nvoid f() { klee_make_symbolic(x, 4, "x"); }'
    resp = await client.post(
        "/api/validate/file",
        files={"file": ("replay_driver.c", io.BytesIO(content), "text/plain")},
        data={"filename": "replay_driver.c"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["severity"] == "error"
    assert any(i.get("rule") == "replay_driver.klee_call_present" for i in (data.get("issues") or []))


# ─── User registration tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_first_registration_gets_admin(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "firstuser",
            "email": "first@example.com",
            "password": "SecurePass123!",  # ≥12 chars, uppercase, digit, symbol
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"
    assert data["username"] == "firstuser"


@pytest.mark.asyncio
async def test_second_registration_gets_viewer(client: AsyncClient) -> None:
    await client.post(
        "/api/auth/register",
        json={"username": "admin_user", "email": "a@x.com", "password": "AdminPass123!"},
    )
    resp = await client.post(
        "/api/auth/register",
        json={"username": "viewer_user", "email": "v@x.com", "password": "ViewerPass123!"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_duplicate_username_rejected(client: AsyncClient) -> None:
    await client.post(
        "/api/auth/register",
        json={"username": "dupuser", "email": "d@x.com", "password": "DupPass123!xyz"},
    )
    resp = await client.post(
        "/api/auth/register",
        json={"username": "dupuser", "email": "d2@x.com", "password": "DupPass456!xyz"},
    )
    assert resp.status_code == 400
