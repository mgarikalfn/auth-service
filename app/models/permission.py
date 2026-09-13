
"""Permission and role-permission models."""

import uuid

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel


class Permission(SQLModel, table=True):
    """A reusable permission definition."""

    __tablename__ = "permissions"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    key: str = Field(unique=True, index=True, nullable=False, max_length=150)
    description: str | None = Field(default=None, max_length=500)


class RolePermission(SQLModel, table=True):
    """Many-to-many association between roles and permissions."""

    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint(
            "role_id",
            "permission_id",
            name="uq_role_permission",
        ),
    )

    role_id: uuid.UUID = Field(
        foreign_key="roles.id",
        primary_key=True,
    )
    permission_id: uuid.UUID = Field(
        foreign_key="permissions.id",
        primary_key=True,
    )