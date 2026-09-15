"""Security utilities: JWT creation / decoding and password hashing.

All JWT operations are centralised here so that changes to the signing key,
algorithm, or token structure have a single blast radius.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from fastapi import HTTPException, status
from jose import JWTError, jwt

import hashlib
import secrets

from app.core.config import settings

# ── Token type sentinels ──────────────────────────────────────────────────────

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"


# ── Public API ────────────────────────────────────────────────────────────────


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*.  Never store plain-text passwords."""
    pwd_bytes = plain.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches the bcrypt *hashed* value."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(subject: str) -> str:
    """Mint a short-lived JWT access token for *subject* (user UUID string)."""
    return _create_token(
        subject=subject,
        token_type=TOKEN_TYPE_ACCESS,
        expire_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(
    subject: str,
    organization_id: str | None = None,
) -> str:
    return _create_token(
        subject=subject,
        token_type=TOKEN_TYPE_REFRESH,
        expire_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        organization_id=organization_id,
    )

def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify *token*.

    Raises ``401 Unauthorized`` on any failure (expired, tampered, wrong
    algorithm, etc.) so callers never need to handle ``JWTError`` directly.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Private helpers ───────────────────────────────────────────────────────────


def _create_token(
    subject: str,
    token_type: str,
    expire_delta: timedelta,
    organization_id: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)

    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expire_delta,
        "jti": uuid.uuid4().hex,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }

    if organization_id is not None:
        payload["org_id"] = organization_id

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

def create_invitation_token() -> str:
    """Generate a cryptographically secure invitation token."""
    return secrets.token_urlsafe(48)


def hash_invitation_token(token: str) -> str:
    """Hash an invitation token before storing it in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_organization_access_token(
    subject: str,
    organization_id: str,
) -> str:
    return _create_token(
        subject=subject,
        token_type=TOKEN_TYPE_ACCESS,
        expire_delta=timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        ),
        organization_id=organization_id,
    )