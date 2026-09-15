"""Authentication business logic: signup, login, and token refresh.

Route handlers delegate entirely to these functions — they contain no business
logic themselves.  Each function raises the appropriate ``HTTPException`` so
the caller gets a clean, consistent JSON error body.
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

from app.models.user import User 
from app.schemas.auth import LoginRequest, RefreshRequest, SignupRequest, TokenResponse 
from app.schemas.user import UserOut
from app.services import organization_service

from app.core.security import create_organization_access_token
from app.services.membership_service import get_active_membership


async def signup(data: SignupRequest, session: AsyncSession) -> UserOut:
    """Register a new user and create their first organization.

    Creates atomically:

    1. User
    2. Organization
    3. Owner role
    4. Active membership
    """

    result = await session.exec(
        select(User).where(User.email == data.email)
    )

    if result.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address is already registered",
        )

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
    )

    session.add(user)

    # Creates:
    # - Organization
    # - Owner role
    # - Active membership
    #
    # It deliberately does NOT commit.
    await organization_service.create_organization_for_user(
        name=data.organization_name,
        user=user,
        session=session,
    )

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Unable to create the account. "
                "The organization or email may already exist."
            ),
        )

    await session.refresh(user)

    return UserOut.model_validate(user)



async def login(data: LoginRequest, session: AsyncSession) -> TokenResponse:
    """Authenticate a user and issue an access + refresh token pair.

    Both credentials must be correct; intentionally the same error message is
    returned for a wrong email *and* a wrong password to prevent user enumeration.

    Raises:
        401 Unauthorized: if credentials are invalid.
    """
    result = await session.exec(select(User).where(User.email == data.email))
    user: User | None = result.first()

    if user is None or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )


async def refresh_access_token(
    data: RefreshRequest, session: AsyncSession
) -> TokenResponse:
    """Exchange a valid refresh token for a new access + refresh token pair.

    The ``type`` claim inside the JWT is checked explicitly — an *access* token
    cannot be used here, preventing token confusion attacks.

    Raises:
        401 Unauthorized: if the token is invalid, expired, or the wrong type.
    """
    payload = decode_token(data.refresh_token)

    if payload.get("type") != TOKEN_TYPE_REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — a refresh token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str: str | None = payload.get("sub")
    try:
        user_id = uuid.UUID(user_id_str) if user_id_str else None
    except (TypeError, ValueError):
        user_id = None

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token subject",
        )

    result = await session.exec(select(User).where(User.id == user_id))
    user: User | None = result.first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User belonging to this token no longer exists",
        )

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )

async def create_organization_access_token_for_user(
    *,
    user: User,
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> str:
    """Create an organization-scoped access token for an active member."""

    membership = await get_active_membership(
        user=user,
        organization_id=organization_id,
        session=session,
    )

    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this organization",
        )

    return create_organization_access_token(
        subject=str(user.id),
        organization_id=str(organization_id),
    )


async def refresh_access_token(
    data: RefreshRequest,
    session: AsyncSession,
) -> TokenResponse:
    payload = decode_token(data.refresh_token)

    if payload.get("type") != TOKEN_TYPE_REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = payload.get("sub")

    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = uuid.UUID(subject)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await session.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    organization_id_value = payload.get("org_id")

    if organization_id_value is None:
        access_token = create_access_token(str(user.id))
        new_refresh_token = create_refresh_token(str(user.id))
        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
        )

    try:
        organization_id = uuid.UUID(organization_id_value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid organization context",
            headers={"WWW-Authenticate": "Bearer"},
        )

    membership = await get_active_membership(
        user=user,
        organization_id=organization_id,
        session=session,
    )

    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You no longer have access to this organization",
        )

    access_token = create_organization_access_token(
        subject=str(user.id),
        organization_id=str(organization_id),
    )

    new_refresh_token = create_refresh_token(
        subject=str(user.id),
        organization_id=str(organization_id),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )