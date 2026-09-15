import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import create_refresh_token_with_jti
from app.models.refresh_token import RefreshToken


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_refresh_token_session(
    *,
    token: str,
    user_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    expires_at: datetime,
    jti: str,
    family_id: uuid.UUID,
    session: AsyncSession,
) -> RefreshToken:
    refresh_token = RefreshToken(
        jti=jti,
        family_id=family_id,
        user_id=user_id,
        organization_id=organization_id,
        token_hash=hash_refresh_token(token),
        expires_at=expires_at,
    )

    session.add(refresh_token)
    await session.flush()

    return refresh_token


async def get_refresh_token_session(
    *,
    token: str,
    session: AsyncSession,
) -> RefreshToken:
    token_hash = hash_refresh_token(token)

    result = await session.exec(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
    )

    refresh_token = result.first()

    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return refresh_token


def ensure_refresh_token_active(
    refresh_token: RefreshToken,
) -> None:
    """Check if the refresh token is active (synchronous check).

    Token reuse revocation handling is performed prior to this call in
    the calling auth service when needed.
    """
    now = datetime.now(timezone.utc)

    expires_at = refresh_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if refresh_token.revoked_at is not None:
        if refresh_token.replaced_by_jti is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected",
                headers={"WWW-Authenticate": "Bearer"},
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def revoke_refresh_token(
    *,
    refresh_token: RefreshToken,
    replaced_by_jti: str | None,
    session: AsyncSession,
) -> None:
    refresh_token.revoked_at = datetime.now(timezone.utc)
    refresh_token.replaced_by_jti = replaced_by_jti

    session.add(refresh_token)
    await session.flush()


async def issue_refresh_token_session(
    *,
    user_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    session: AsyncSession,
    family_id: uuid.UUID | None = None,
) -> str:
    if family_id is None:
        family_id = uuid.uuid4()

    organization_id_value = (
        str(organization_id)
        if organization_id is not None
        else None
    )

    token, jti, expires_at = create_refresh_token_with_jti(
        subject=str(user_id),
        organization_id=organization_id_value,
    )

    await create_refresh_token_session(
        token=token,
        user_id=user_id,
        organization_id=organization_id,
        expires_at=expires_at,
        jti=jti,
        family_id=family_id,
        session=session,
    )

    return token


async def revoke_token_family(
    *,
    family_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
    )

    tokens = result.scalars().all()
    now = datetime.now(timezone.utc)

    for token in tokens:
        token.revoked_at = now

    await session.flush()