import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel


class UserRole(str, Enum):
    user = "user"
    admin = "admin"


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )

    email: str = Field(
        unique=True,
        index=True,
        nullable=False,
    )

    hashed_password: str = Field(
        nullable=False,
    )

    role: UserRole = Field(
        default=UserRole.user,
        nullable=False,
    )

    status: UserStatus = Field(
        default=UserStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    email_verified_at: datetime | None = Field(
        default=None,
        nullable=True,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )