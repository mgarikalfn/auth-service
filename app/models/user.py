"""SQLModel table definition for the User entity."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class UserRole(str, Enum):
    """Roles that control access to protected endpoints."""

    user = "user"
    admin = "admin"


class User(SQLModel, table=True):
    """Persisted user record.

    Passwords are *never* stored in plain text — only the bcrypt hash produced
    by :func:`app.core.security.hash_password` is written to this column.
    """

    __tablename__ = "users"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    email: str = Field(unique=True, index=True, nullable=False)
    hashed_password: str = Field(nullable=False)
    role: UserRole = Field(default=UserRole.user, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    email_verified_at: datetime | None = Field(
        default=None,
        nullable=True,
    )