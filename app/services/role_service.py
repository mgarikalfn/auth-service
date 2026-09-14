"""Role business logic."""

import uuid

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.permission import Permission, RolePermission
from app.models.role import Role
from app.schemas.role import RoleCreate, RoleUpdate


SYSTEM_ROLE_NAMES = {
    "owner",
}

async def get_organization_roles(
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> list[Role]:
    """Return all roles belonging to an organization."""

    statement = (
        select(Role)
        .where(Role.organization_id == organization_id)
        .order_by(Role.created_at)
    )

    result = await session.exec(statement)

    return list(result.all())


async def get_role(
    role_id: uuid.UUID,
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> Role | None:
    """Get a role only if it belongs to the organization."""

    statement = select(Role).where(
        Role.id == role_id,
        Role.organization_id == organization_id,
    )

    result = await session.exec(statement)

    return result.first()


async def _validate_permission_ids(
    permission_ids: list[uuid.UUID],
    session: AsyncSession,
) -> list[Permission]:
    """Ensure all requested permissions exist."""

    if not permission_ids:
        return []

    unique_ids = list(dict.fromkeys(permission_ids))

    statement = select(Permission).where(
        Permission.id.in_(unique_ids)
    )

    result = await session.exec(statement)
    permissions = list(result.all())

    if len(permissions) != len(unique_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more permissions do not exist",
        )

    return permissions


async def _set_role_permissions(
    role_id: uuid.UUID,
    permission_ids: list[uuid.UUID],
    session: AsyncSession,
) -> None:
    """Replace all permissions assigned to a role."""

    existing_statement = select(RolePermission).where(
        RolePermission.role_id == role_id
    )

    result = await session.exec(existing_statement)

    for role_permission in result.all():
        await session.delete(role_permission)

    unique_ids = list(dict.fromkeys(permission_ids))

    for permission_id in unique_ids:
        session.add(
            RolePermission(
                role_id=role_id,
                permission_id=permission_id,
            )
        )


async def create_role(
    organization_id: uuid.UUID,
    data: RoleCreate,
    session: AsyncSession,
) -> Role:
    """Create a custom role within an organization."""

    permissions = await _validate_permission_ids(
        data.permission_ids,
        session,
    )

    normalized_name = data.name.strip().lower()

    if normalized_name in SYSTEM_ROLE_NAMES:
        raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="This role name is reserved",
    )
    role = Role(
        organization_id=organization_id,
        name=data.name,
        description=data.description,
        is_system=False,
    )

    session.add(role)
    await session.flush()

    for permission in permissions:
        session.add(
            RolePermission(
                role_id=role.id,
                permission_id=permission.id,
            )
        )

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A role with this name already exists in this organization",
        )

    await session.refresh(role)

    return role


async def update_role(
    role: Role,
    data: RoleUpdate,
    session: AsyncSession,
) -> Role:
    """Update a custom organization role."""

    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System roles cannot be modified",
        )

    if data.name is not None:
        role.name = data.name

    if data.description is not None:
        role.description = data.description

    if data.permission_ids is not None:
        await _validate_permission_ids(
            data.permission_ids,
            session,
        )

        await _set_role_permissions(
            role_id=role.id,
            permission_ids=data.permission_ids,
            session=session,
        )

    session.add(role)

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A role with this name already exists in this organization",
        )

    await session.refresh(role)

    return role


async def delete_role(
    role: Role,
    session: AsyncSession,
) -> None:
    """Delete a custom organization role."""

    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System roles cannot be deleted",
        )

    await session.delete(role)
    await session.commit()