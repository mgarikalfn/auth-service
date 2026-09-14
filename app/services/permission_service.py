"""Permission business logic."""

import uuid

from fastapi import HTTPException,status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.permissions import SYSTEM_PERMISSIONS
from app.models.permission import Permission, RolePermission
from app.models.role import Role


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

async def get_system_permissions(
    session: AsyncSession,
) -> list[Permission]:
    """Return all available system permissions."""

    statement = (
        select(Permission)
        .order_by(Permission.key)
    )

    result = await session.exec(statement)

    return list(result.all())


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


async def set_role_permissions(
    role: Role,
    permission_ids: list[uuid.UUID],
    session: AsyncSession,
) -> list[Permission]:
    """Replace the permissions assigned to a role."""

    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System roles cannot have their permissions modified",
        )

    unique_permission_ids = list(dict.fromkeys(permission_ids))

    if unique_permission_ids:
        statement = select(Permission).where(
            Permission.id.in_(unique_permission_ids)
        )

        result = await session.exec(statement)
        permissions = list(result.all())

        if len(permissions) != len(unique_permission_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more permissions do not exist",
            )
    else:
        permissions = []

    existing_statement = select(RolePermission).where(
        RolePermission.role_id == role.id
    )

    existing_result = await session.exec(existing_statement)

    for role_permission in existing_result.all():
        await session.delete(role_permission)

    for permission in permissions:
        session.add(
            RolePermission(
                role_id=role.id,
                permission_id=permission.id,
            )
        )

    await session.commit()

    return permissions