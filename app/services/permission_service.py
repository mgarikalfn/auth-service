"""Permission business logic."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.permission import Permission, RolePermission


async def get_role_permissions(
    role_id: uuid.UUID,
    session: AsyncSession,
) -> list[Permission]:
    """Return all permissions assigned to a role."""

    statement = (
        select(Permission)
        .join(
            RolePermission,
            RolePermission.permission_id == Permission.id,
        )
        .where(RolePermission.role_id == role_id)
        .order_by(Permission.key)
    )

    result = await session.exec(statement)
    return list(result.all())


async def role_has_permission(
    role_id: uuid.UUID,
    permission_key: str,
    session: AsyncSession,
) -> bool:
    """Check whether a role has a specific permission."""

    statement = (
        select(Permission.id)
        .join(
            RolePermission,
            RolePermission.permission_id == Permission.id,
        )
        .where(
            RolePermission.role_id == role_id,
            Permission.key == permission_key,
        )
    )

    result = await session.exec(statement)
    return result.first() is not None