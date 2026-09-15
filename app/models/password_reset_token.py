import uuid
from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class PasswordResetToken(SQLModel, table=True):
    __tablename__ = "password_reset_tokens"

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

    token_hash: str = Field(
        unique=True,
        index=True,
        nullable=False,
        max_length=64,
    )

    expires_at: datetime = Field(nullable=False)

    used_at: datetime | None = Field(
        default=None,
        nullable=True,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )