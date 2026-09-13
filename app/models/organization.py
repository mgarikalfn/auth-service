
"""Organization model for multi-tenant identity management."""

import uuid
from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class Organization(SQLModel, table=True):
    """A tenant/company/workspace in the identity platform."""

    __tablename__ = "organizations"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    name: str = Field(nullable=False, max_length=255)
    slug: str = Field(unique=True, index=True, nullable=False, max_length=100)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )