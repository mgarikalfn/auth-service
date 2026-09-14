"""Organization invitation model."""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel


class InvitationStatus(str, Enum):
    """Lifecycle states for organization invitations."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class Invitation(SQLModel, table=True):
    """Invitation sent to a user to join an organization."""

    __tablename__ = "invitations"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )

    organization_id: uuid.UUID = Field(
        foreign_key="organizations.id",
        index=True,
        nullable=False,
    )

    role_id: uuid.UUID = Field(
        foreign_key="roles.id",
        index=True,
        nullable=False,
    )

    invited_by_user_id: uuid.UUID = Field(
        foreign_key="users.id",
        index=True,
        nullable=False,
    )

    invited_email: str = Field(
        index=True,
        nullable=False,
        max_length=320,
    )

    token_hash: str = Field(
        unique=True,
        index=True,
        nullable=False,
        max_length=64,
    )

    status: InvitationStatus = Field(
        default=InvitationStatus.PENDING,
        nullable=False,
    )

    expires_at: datetime = Field(nullable=False)

    accepted_by_user_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="users.id",
        index=True,
        nullable=True,
    )

    accepted_at: datetime | None = Field(
        default=None,
        nullable=True,
    )

    cancelled_at: datetime | None = Field(
        default=None,
        nullable=True,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )