"""Organization membership routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.organization import (
    get_current_membership,
    require_permission,
)
from app.models.membership import Membership, MembershipStatus
from app.models.role import Role
from app.schemas.membership import (
    MembershipRoleUpdate,
    MembershipStatusUpdate,
    MembershipWithDetailsOut,
)
from app.services import membership_service

router = APIRouter(
    prefix="/organizations/{organization_id}/members",
    tags=["Organization Members"],
)


@router.get(
    "",
    response_model=list[MembershipWithDetailsOut],
    summary="List organization members",
)
async def list_members(
    organization_id: uuid.UUID,
    membership: Membership = Depends(get_current_membership),
    session: AsyncSession = Depends(get_session),
) -> list[MembershipWithDetailsOut]:
    return await membership_service.get_organization_members_with_details(
        organization_id=membership.organization_id,
        session=session,
    )

@router.patch(
    "/{membership_id}/role",
    response_model=MembershipWithDetailsOut,
    summary="Change a member's role",
)
async def update_member_role(
    organization_id: uuid.UUID,
    membership_id: uuid.UUID,
    data: MembershipRoleUpdate,
    _: Role = Depends(require_permission("members.update")),
    session: AsyncSession = Depends(get_session),
) -> MembershipWithDetailsOut:
    membership = await membership_service.get_membership(
        membership_id=membership_id,
        organization_id=organization_id,
        session=session,
    )

    if membership is None:
        raise HTTPException(
            status_code=404,
            detail="Membership not found",
        )

    await membership_service.ensure_membership_can_be_modified(
        membership=membership,
        session=session,
    )

    await membership_service.change_membership_role(
        membership=membership,
        role_id=data.role_id,
        session=session,
    )

    members = await membership_service.get_organization_members_with_details(
        organization_id=organization_id,
        session=session,
    )

    return next(
        member
        for member in members
        if member.id == membership.id
    )

@router.patch(
    "/{membership_id}/status",
    response_model=MembershipWithDetailsOut,
    summary="Change a member's status",
)
async def update_member_status(
    organization_id: uuid.UUID,
    membership_id: uuid.UUID,
    data: MembershipStatusUpdate,
    _: Role = Depends(require_permission("members.update")),
    session: AsyncSession = Depends(get_session),
) -> MembershipWithDetailsOut:
    membership = await membership_service.get_membership(
        membership_id=membership_id,
        organization_id=organization_id,
        session=session,
    )

    if membership is None:
        raise HTTPException(
            status_code=404,
            detail="Membership not found",
        )

    await membership_service.ensure_membership_can_be_modified(
        membership=membership,
        session=session,
    )

    await membership_service.change_membership_status(
        membership=membership,
        new_status=data.status,
        session=session,
    )

    members = await membership_service.get_organization_members_with_details(
        organization_id=organization_id,
        session=session,
    )

    return next(
        member
        for member in members
        if member.id == membership.id
    )
