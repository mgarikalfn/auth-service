"""Authentication business logic: signup, login, and token refresh.

Route handlers delegate entirely to these functions — they contain no business
logic themselves. Each function raises the appropriate ``HTTPException`` so
the caller gets a clean, consistent JSON error body.
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.services import email_verification_service


from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_organization_access_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import LoginRequest, SignupRequest, TokenResponse
from app.schemas.user import UserOut
from app.services import organization_service
from app.services.membership_service import get_active_membership
from app.services.password_reset_service import create_password_reset_token, hash_password_reset_token
from app.services.refresh_token_service import (
    ensure_refresh_token_active,
    get_refresh_token_session,
    issue_refresh_token_session,
    revoke_refresh_token,
    revoke_refresh_token_family,
)


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

    await organization_service.create_organization_for_user(
        name=data.organization_name,
        user=user,
        session=session,
    )

    await email_verification_service.send_verification_email(user=user,session=session)
    
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

    Persists the refresh token session to the database.
    """
    result = await session.exec(select(User).where(User.email == data.email))
    user: User | None = result.first()

    if user is None or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Issue persistent refresh token session
    refresh_token = await issue_refresh_token_session(
        user_id=user.id,
        organization_id=None,
        session=session,
    )

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_token,
        token_type="bearer",
    )


async def refresh_access_token(
    *,
    refresh_token: str,
    session: AsyncSession,
) -> tuple[str, str, uuid.UUID | None]:
    """Rotate the refresh token and issue a new access token."""
    payload = decode_token(refresh_token)

    if payload.get("type") != TOKEN_TYPE_REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = payload.get("sub")
    jti = payload.get("jti")

    if not subject or not jti:
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

    stored_token = await get_refresh_token_session(
        token=refresh_token,
        session=session,
    )

    if stored_token.jti != jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reuse detection: if already revoked, revoke whole token family
    if stored_token.revoked_at is not None:
        await revoke_refresh_token_family(
            family_id=stored_token.family_id,
            session=session,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected",
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
        access_token = create_access_token(
            subject=str(user.id),
        )

        new_refresh_token = await issue_refresh_token_session(
            user_id=user.id,
            organization_id=None,
            session=session,
            family_id=stored_token.family_id,
        )

        new_payload = decode_token(new_refresh_token)

        await revoke_refresh_token(
            refresh_token=stored_token,
            replaced_by_jti=new_payload["jti"],
            session=session,
        )

        return access_token, new_refresh_token, None

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

    new_refresh_token = await issue_refresh_token_session(
        user_id=user.id,
        organization_id=organization_id,
        session=session,
        family_id=stored_token.family_id,
    )

    new_payload = decode_token(new_refresh_token)

    await revoke_refresh_token(
        refresh_token=stored_token,
        replaced_by_jti=new_payload["jti"],
        session=session,
    )

    return access_token, new_refresh_token, organization_id
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

def test_hash_password_reset_token_is_deterministic():
    token = "reset-token"

    assert hash_password_reset_token(token) == (
        hash_password_reset_token(token)
    )

def test_create_password_reset_token_is_random():
    first = create_password_reset_token()
    second = create_password_reset_token()

    assert first != second
    assert len(first) >= 32