"""Permission business logic."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.permissions import SYSTEM_PERMISSIONS
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

async def ensure_system_permissions(
    session: AsyncSession,
) -> dict[str, Permission]:
    """Ensure all system permissions exist and return them by key."""

    result = await session.exec(select(Permission))
    existing_permissions = {
        permission.key: permission
        for permission in result.all()
    }

    permissions_by_key: dict[str, Permission] = {}

    for definition in SYSTEM_PERMISSIONS:
        permission = existing_permissions.get(definition.key)

        if permission is None:
            permission = Permission(
                key=definition.key,
                description=definition.description,
            )
            session.add(permission)

        permissions_by_key[definition.key] = permission

    await session.flush()

    return permissions_by_key

async def assign_permissions_to_role(
    role_id: uuid.UUID,
    permission_ids: list[uuid.UUID],
    session: AsyncSession,
) -> None:
    """Assign permissions to a role."""

    for permission_id in permission_ids:
        session.add(
            RolePermission(
                role_id=role_id,
                permission_id=permission_id,
            )
        )

async def assign_default_owner_permissions(
    role_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    """Assign all system permissions to an Owner role."""

    permissions = await ensure_system_permissions(session)

    await assign_permissions_to_role(
        role_id=role_id,
        permission_ids=[
            permission.id
            for permission in permissions.values()
        ],
        session=session,
    )