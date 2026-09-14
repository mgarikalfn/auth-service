"""Organization role routes."""

import uuid

from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.organization import (
    get_current_membership,
    require_permission,
)
from app.models.membership import Membership
from app.models.role import Role
from app.schemas.permission import PermissionOut, RolePermissionsUpdate
from app.schemas.role import RoleCreate, RoleOut, RoleUpdate
from app.services import permission_service, role_service

router = APIRouter(
    prefix="/organizations/{organization_id}/roles",
    tags=["Organization Roles"],
)


@router.get(
    "",
    response_model=list[RoleOut],
    summary="List organization roles",
)
async def list_roles(
    organization_id: uuid.UUID,
    membership: Membership = Depends(get_current_membership),
    session: AsyncSession = Depends(get_session),
) -> list[RoleOut]:
    roles = await role_service.get_organization_roles(
        organization_id=membership.organization_id,
        session=session,
    )

    return [
        RoleOut.model_validate(role)
        for role in roles
    ]


@router.post(
    "",
    response_model=RoleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization role",
)
async def create_role(
    organization_id: uuid.UUID,
    data: RoleCreate,
    _: Role = Depends(require_permission("roles.create")),
    session: AsyncSession = Depends(get_session),
) -> RoleOut:
    role = await role_service.create_role(
        organization_id=organization_id,
        data=data,
        session=session,
    )

    return RoleOut.model_validate(role)


@router.patch(
    "/{role_id}",
    response_model=RoleOut,
    summary="Update an organization role",
)
async def update_role(
    organization_id: uuid.UUID,
    role_id: uuid.UUID,
    data: RoleUpdate,
    _: Role = Depends(require_permission("roles.update")),
    session: AsyncSession = Depends(get_session),
) -> RoleOut:
    role = await role_service.get_role(
        role_id=role_id,
        organization_id=organization_id,
        session=session,
    )

    if role is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=404,
            detail="Role not found",
        )

    role = await role_service.update_role(
        role=role,
        data=data,
        session=session,
    )

    return RoleOut.model_validate(role)


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an organization role",
)
async def delete_role(
    organization_id: uuid.UUID,
    role_id: uuid.UUID,
    _: Role = Depends(require_permission("roles.delete")),
    session: AsyncSession = Depends(get_session),
) -> None:
    role = await role_service.get_role(
        role_id=role_id,
        organization_id=organization_id,
        session=session,
    )

    if role is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=404,
            detail="Role not found",
        )

    await role_service.delete_role(
        role=role,
        session=session,
    )

@router.get(
    "/{role_id}/permissions",
    response_model=list[PermissionOut],
    summary="Get permissions assigned to a role",
)
async def get_role_permissions(
    organization_id: uuid.UUID,
    role_id: uuid.UUID,
    _: Role = Depends(require_permission("roles.read")),
    session: AsyncSession = Depends(get_session),
) -> list[PermissionOut]:
    role = await role_service.get_role(
        role_id=role_id,
        organization_id=organization_id,
        session=session,
    )

    if role is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=404,
            detail="Role not found",
        )

    permissions = await permission_service.get_role_permissions(
        role_id=role.id,
        session=session,
    )

    return [
        PermissionOut.model_validate(permission)
        for permission in permissions
    ]

@router.put(
    "/{role_id}/permissions",
    response_model=list[PermissionOut],
    summary="Replace permissions assigned to a role",
)
async def update_role_permissions(
    organization_id: uuid.UUID,
    role_id: uuid.UUID,
    data: RolePermissionsUpdate,
    _: Role = Depends(require_permission("roles.update")),
    session: AsyncSession = Depends(get_session),
) -> list[PermissionOut]:
    role = await role_service.get_role(
        role_id=role_id,
        organization_id=organization_id,
        session=session,
    )

    if role is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=404,
            detail="Role not found",
        )

    permissions = await permission_service.set_role_permissions(
        role=role,
        permission_ids=data.permission_ids,
        session=session,
    )

    return [
        PermissionOut.model_validate(permission)
        for permission in permissions
    ]