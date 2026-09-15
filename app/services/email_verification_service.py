import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.services.email_service import EmailMessage, get_email_service
from app.templates.email_verification_email import (
    build_email_verification_email,
)


def hash_email_verification_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_email_verification_token() -> str:
    return secrets.token_urlsafe(48)


async def create_email_verification_record(
    *,
    user_id: uuid.UUID,
    raw_token: str,
    session: AsyncSession,
) -> EmailVerificationToken:
    now = datetime.now(timezone.utc)

    verification_record = EmailVerificationToken(
        user_id=user_id,
        token_hash=hash_email_verification_token(
            raw_token
        ),
        expires_at=now
        + timedelta(
            minutes=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES
        ),
    )

    session.add(verification_record)
    await session.flush()

    return verification_record


async def get_email_verification_record(
    *,
    raw_token: str,
    session: AsyncSession,
) -> EmailVerificationToken:
    token_hash = hash_email_verification_token(
        raw_token
    )

    result = await session.exec(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash
            == token_hash
        )
    )

    record = result.first()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token",
        )

    return record


def ensure_email_verification_token_active(
    record: EmailVerificationToken,
) -> None:
    now = datetime.now(timezone.utc)

    expires_at = record.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if record.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token",
        )

    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token",
        )


async def mark_email_verification_token_used(
    *,
    record: EmailVerificationToken,
    session: AsyncSession,
) -> None:
    record.used_at = datetime.now(timezone.utc)

    session.add(record)

    await session.flush()


async def send_verification_email(
    *,
    user: User,
    session: AsyncSession,
) -> None:
    raw_token = create_email_verification_token()

    record = await create_email_verification_record(
        user_id=user.id,
        raw_token=raw_token,
        session=session,
    )

    verification_url = (
        f"{settings.APP_URL}/verify-email"
        f"?token={raw_token}"
    )

    subject, html, text = build_email_verification_email(
        verification_url=verification_url,
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


async def verify_email(
    *,
    raw_token: str,
    session: AsyncSession,
) -> User:
    record = await get_email_verification_record(
        raw_token=raw_token,
        session=session,
    )

    ensure_email_verification_token_active(record)

    user = await session.get(
        User,
        record.user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token",
        )

    if user.email_verified_at is None:
        user.email_verified_at = datetime.now(
            timezone.utc
        )
        session.add(user)

    await mark_email_verification_token_used(
        record=record,
        session=session,
    )

    await session.flush()

    return user