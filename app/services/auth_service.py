"""Authentication business logic: signup, login, and token refresh.

Route handlers delegate entirely to these functions — they contain no business
logic themselves.  Each function raises the appropriate ``HTTPException`` so
the caller gets a clean, consistent JSON error body.
"""

import re
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
from app.models.membership import Membership,MembershipStatus 
from app.models.organization import Organization 
from app.models.role import Role 
from app.models.user import User 
from app.schemas.auth import LoginRequest, RefreshRequest, SignupRequest, TokenResponse 
from app.schemas.user import UserOut

def _generate_slug(name : str) -> str:
    """Generate a URl-safe organization slug from its name."""

    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+","-",slug)
    slug = slug.strip("-")

    if not slug:
        slug = "organization"

    #organization.slug has max_length=100.
    return slug[:100]

async def _generate_unique_slug(name:str , session:AsyncSession)-> str:
    """Generate an organization slug that does not currently exist"""
    base_slug = _generate_slug(name)

    result = await session.exec(
        select(Organization).where(Organization.slug == base_slug)
    )

    if result.first() is None:
        return base_slug
    #Add a short UUID suffix if the generated slug already exists . 
    suffix = uuid.uuid4().hex[:8]

    #keep the total length <= 100.
    max_base_length = 100 - len(suffix) -1

    return f"{base_slug[:max_base_length]}-{suffix}"

async def signup(data: SignupRequest, session: AsyncSession) -> UserOut:
    """Register a new user and create there first organization.

    the signup operation creates four related records:
    1. user 
    2. organization
    3. owner role
    4. active membership
    all record are commited in a single database transaction

    Raises:
        409 Conflict: if *data.email* is already taken.
    """
    result = await session.exec(select(User).where(User.email == data.email))
    if result.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address is already registered",
        )
    organization_slug = await _generate_unique_slug(data.organization_name,session)
    
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
    )

    organization = Organization(name = data.organization_name,slug = organization_slug)

    owner_role = Role(organization_id=organization.id,name="Owner",description="Full access to the organization",is_system=True)

    membership = Membership(user_id=user.id,organization_id=organization.id,role_id=owner_role.id,status=MembershipStatus.ACTIVE)


    session.add(user)
    session.add(organization)
    session.add(owner_role)
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()

        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail="Unable to create the account . the organization or email already exists. ")
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
