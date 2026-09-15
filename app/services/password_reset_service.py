import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.models.password_reset_token import PasswordResetToken


def hash_password_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_password_reset_token() -> str:
    return secrets.token_urlsafe(48)


async def create_password_reset_record(
    *,
    user_id: uuid.UUID,
    raw_token: str,
    session: AsyncSession,
) -> PasswordResetToken:
    now = datetime.now(timezone.utc)

    reset_record = PasswordResetToken(
        user_id=user_id,
        token_hash=hash_password_reset_token(raw_token),
        expires_at=now + timedelta(
            minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES
        ),
    )

    session.add(reset_record)
    await session.flush()

    return reset_record


async def get_password_reset_record(
    *,
    raw_token: str,
    session: AsyncSession,
) -> PasswordResetToken:
    token_hash = hash_password_reset_token(raw_token)

    result = await session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash
        )
    )

    record = result.first()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    return record


def ensure_password_reset_token_active(
    record: PasswordResetToken,
) -> None:
    now = datetime.now(timezone.utc)

    expires_at = record.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if record.used_at is not None or expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )


async def mark_password_reset_token_used(
    *,
    record: PasswordResetToken,
    session: AsyncSession,
) -> None:
    record.used_at = datetime.now(timezone.utc)
    session.add(record)
    await session.flush()