import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.refresh_token import RefreshToken
from app.models.user import User, UserStatus


async def revoke_all_user_sessions(
    *,
    user_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    result = await session.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
    )

    now = datetime.now(timezone.utc)

    for refresh_token in result.all():
        refresh_token.revoked_at = now
        session.add(refresh_token)

    await session.flush()


async def suspend_user(
    *,
    user: User,
    session: AsyncSession,
) -> User:
    if user.status == UserStatus.DEACTIVATED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deactivated users cannot be suspended",
        )

    user.status = UserStatus.SUSPENDED
    session.add(user)

    await revoke_all_user_sessions(
        user_id=user.id,
        session=session,
    )

    await session.flush()

    return user


async def deactivate_user(
    *,
    user: User,
    session: AsyncSession,
) -> User:
    user.status = UserStatus.DEACTIVATED
    session.add(user)

    await revoke_all_user_sessions(
        user_id=user.id,
        session=session,
    )

    await session.flush()

    return user


async def reactivate_user(
    *,
    user: User,
    session: AsyncSession,
) -> User:
    if user.status == UserStatus.ACTIVE:
        return user

    user.status = UserStatus.ACTIVE
    session.add(user)

    await session.flush()

    return user