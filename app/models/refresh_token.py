import uuid
from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )

    jti: str = Field(
        unique=True,
        index=True,
        nullable=False,
        max_length=64,
    )

    user_id: uuid.UUID = Field(
        foreign_key="users.id",
        index=True,
        nullable=False,
    )

    organization_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="organizations.id",
        index=True,
        nullable=True,
    )

    token_hash: str = Field(
        unique=True,
        index=True,
        nullable=False,
        max_length=64,
    )

    expires_at: datetime = Field(nullable=False)

    revoked_at: datetime | None = Field(
        default=None,
        nullable=True,
    )

    replaced_by_jti: str | None = Field(
        default=None,
        index=True,
        max_length=64,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )