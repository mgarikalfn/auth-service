"""Dependencies for organization-scoped authorization."""

import uuid
from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.models.membership import Membership
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.services.membership_service import get_active_membership
from app.services.permission_service import (
    get_role_permissions,
    role_has_permission,
)


async def get_current_membership(
    organization_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Membership:
    membership = await get_active_membership(
        user=current_user,
        organization_id=organization_id,
        session=session,
    )

    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this organization",
        )

    return membership


async def get_current_role(
    membership: Membership = Depends(get_current_membership),
    session: AsyncSession = Depends(get_session),
) -> Role:
    statement = select(Role).where(
        Role.id == membership.role_id,
        Role.organization_id == membership.organization_id,
    )

    result = await session.exec(statement)
    role = result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The membership has an invalid organization role",
        )

    return role


async def get_current_permissions(
    current_role: Role = Depends(get_current_role),
    session: AsyncSession = Depends(get_session),
) -> list[Permission]:
    """Resolve permissions for the current organization role."""

    return await get_role_permissions(
        role_id=current_role.id,
        session=session,
    )


def require_organization_role(role_name: str) -> Callable:
    async def _role_checker(
        current_role: Role = Depends(get_current_role),
    ) -> Role:
        if current_role.name != role_name:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"'{role_name}' role required",
            )

        return current_role

    return _role_checker


def require_permission(permission_key: str) -> Callable:
    """Require the current organization role to have a permission."""

    async def _permission_checker(
        current_role: Role = Depends(get_current_role),
        session: AsyncSession = Depends(get_session),
    ) -> Role:
        has_permission = await role_has_permission(
            role_id=current_role.id,
            permission_key=permission_key,
            session=session,
        )

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: '{permission_key}'",
            )

        return current_role

    return _permission_checker