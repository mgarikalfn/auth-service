import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.services.email_service import EmailMessage, get_email_service
from app.templates.password_reset_email import build_password_reset_email


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

async def request_password_reset(
    *,
    email: str,
    session: AsyncSession,
) -> None:
    normalized_email = email.strip().lower()

    result = await session.exec(
        select(User).where(User.email == normalized_email)
    )

    user = result.first()

    # Do not reveal whether the account exists.
    if user is None:
        return

    raw_token = create_password_reset_token()

    record = await create_password_reset_record(
        user_id=user.id,
        raw_token=raw_token,
        session=session,
    )

    reset_url = (
        f"{settings.APP_URL}/reset-password"
        f"?token={raw_token}"
    )

    subject, html, text = build_password_reset_email(
        reset_url=reset_url,
        expires_at=record.expires_at,
    )

    email_service = get_email_service()

    await email_service.send(
        EmailMessage(
            to=user.email,
            subject=subject,
            html=html,
            text=text,
        )
    )

async def reset_password(
    *,
    raw_token: str,
    new_password: str,
    session: AsyncSession,
) -> None:
    record = await get_password_reset_record(
        raw_token=raw_token,
        session=session,
    )

    ensure_password_reset_token_active(record)

    user = await session.get(User, record.user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    user.hashed_password = hash_password(new_password)

    session.add(user)

    await mark_password_reset_token_used(
        record=record,
        session=session,
    )

    result = await session.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
        )
    )

    active_tokens = result.all()

    now = datetime.now(timezone.utc)

    for refresh_token in active_tokens:
        refresh_token.revoked_at = now
        session.add(refresh_token)

    await session.flush()