"""Auth endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import get_current_user
from models.user import User
from services.auth_service import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await authenticate_user(db, body.username, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(
        access_token=create_access_token(user.user_id, user.role),
        refresh_token=create_refresh_token(user.user_id),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    result = await db.execute(select(User).where(User.user_id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return TokenResponse(
        access_token=create_access_token(user.user_id, user.role),
        refresh_token=create_refresh_token(user.user_id),
    )


@router.post("/logout")
async def logout(user: User = Depends(get_current_user)) -> dict:
    # With Redis token blacklisting this would revoke the token; MVP just returns OK
    return {"status": "ok"}


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    display_name: str | None = None


class RegisterResponse(BaseModel):
    user_id: str
    username: str
    role: str


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> RegisterResponse:
    # Check username uniqueness
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    # First registered user gets admin role
    count_result = await db.execute(select(User))
    user_count = len(count_result.scalars().all())
    role = "admin" if user_count == 0 else "viewer"

    user = User(
        username=body.username,
        hashed_password=hash_password(body.password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return RegisterResponse(user_id=user.user_id, username=user.username, role=user.role)


# User management endpoints (admin only)
users_router = APIRouter(prefix="/api/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    password: str | None = None


@users_router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(__import__("middleware.auth", fromlist=["require_role"]).require_role("admin")),
) -> list[dict]:
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [{"user_id": u.user_id, "username": u.username, "role": u.role} for u in users]


@users_router.post("")
async def create_user(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(__import__("middleware.auth", fromlist=["require_role"]).require_role("admin")),
) -> dict:
    user = User(username=body.username, hashed_password=hash_password(body.password), role=body.role)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"user_id": user.user_id, "username": user.username, "role": user.role}


class RoleUpdateRequest(BaseModel):
    role: str


@users_router.post("/{user_id}/role")
async def update_user_role(
    user_id: str,
    body: RoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(__import__("middleware.auth", fromlist=["require_role"]).require_role("admin")),
) -> dict:
    valid_roles = {"viewer", "operator", "intervener", "admin"}
    if body.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
    result = await db.execute(select(User).where(User.user_id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = body.role
    await db.commit()
    return {"user_id": user_id, "role": body.role}


@users_router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(__import__("middleware.auth", fromlist=["require_role"]).require_role("admin")),
) -> None:
    if current_user.user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    result = await db.execute(select(User).where(User.user_id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(target)
    await db.commit()
