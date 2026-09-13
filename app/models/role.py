
"""Organization-scoped role model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel


class Role(SQLModel, table=True):
    """A role belonging to one organization."""

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_role_organization_name",
        ),
    )

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
    name: str = Field(nullable=False, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    is_system: bool = Field(default=False, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )