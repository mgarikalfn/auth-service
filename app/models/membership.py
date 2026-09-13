
"""Organization membership model."""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel


class MembershipStatus(str, Enum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"


class Membership(SQLModel, table=True):
    """Connects a user to an organization with an assigned role."""

    __tablename__ = "memberships"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    user_id: uuid.UUID = Field(
        foreign_key="users.id",
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
    status: MembershipStatus = Field(
        default=MembershipStatus.ACTIVE,
        nullable=False,
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )