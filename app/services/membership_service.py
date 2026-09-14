
"""Membership business logic."""

import uuid

from fastapi import HTTPException , status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.membership import Membership, MembershipStatus
from app.models.role import Role
from app.models.user import User
from app.schemas.membership import MembershipWithDetailsOut


async def get_active_membership(
    user: User,
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> Membership | None:
    """Return the user's active membership in an organization."""

    statement = select(Membership).where(
        Membership.user_id == user.id,
        Membership.organization_id == organization_id,
        Membership.status == MembershipStatus.ACTIVE,
    )

    result = await session.exec(statement)

    return result.first()

async def get_organization_members(
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> list[Membership]:
    """Return all memberships for an organization."""

    statement = (
        select(Membership)
        .where(
            Membership.organization_id == organization_id,
        )
        .order_by(Membership.created_at)
    )

    result = await session.exec(statement)

    return list(result.all())

async def get_membership(
    membership_id: uuid.UUID,
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> Membership | None:
    """Get a membership only within the specified organization."""

    statement = select(Membership).where(
        Membership.id == membership_id,
        Membership.organization_id == organization_id,
    )

    result = await session.exec(statement)

    return result.first()

async def change_membership_role(
    membership: Membership,
    role_id: uuid.UUID,
    session: AsyncSession,
) -> Membership:
    """Change a member's role within the same organization."""

    role_statement = select(Role).where(
        Role.id == role_id,
        Role.organization_id == membership.organization_id,
    )

    role_result = await session.exec(role_statement)
    role = role_result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The selected role does not belong to this organization",
        )

    membership.role_id = role.id

    session.add(membership)
    await session.commit()
    await session.refresh(membership)

    return membership

async def change_membership_status(
    membership: Membership,
    new_status: MembershipStatus,
    session: AsyncSession,
) -> Membership:
    """Change membership status using valid lifecycle transitions."""

    if membership.status == MembershipStatus.INVITED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invited memberships are managed by the invitation workflow",
        )

    if membership.status == new_status:
        return membership

    valid_transitions = {
        MembershipStatus.ACTIVE: {
            MembershipStatus.SUSPENDED,
        },
        MembershipStatus.SUSPENDED: {
            MembershipStatus.ACTIVE,
        },
    }

    allowed_statuses = valid_transitions.get(
        membership.status,
        set(),
    )

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot change membership from "
                f"'{membership.status.value}' to "
                f"'{new_status.value}'"
            ),
        )

    membership.status = new_status

    session.add(membership)

    await session.commit()
    await session.refresh(membership)

    return membership


async def ensure_membership_can_be_modified(
    membership: Membership,
    session: AsyncSession,
) -> None:
    """Prevent destructive changes to system-role memberships."""

    role_statement = select(Role).where(
        Role.id == membership.role_id,
        Role.organization_id == membership.organization_id,
    )

    result = await session.exec(role_statement)
    role = result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Membership has an invalid role",
        )

    if role.is_system and role.name.lower() == "owner":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The organization owner membership cannot be modified",
        )

async def get_organization_members_with_details(
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> list[MembershipWithDetailsOut]:
    statement = (
        select(
            Membership.id,
            Membership.user_id,
            Membership.organization_id,
            Membership.role_id,
            Role.name,
            User.email,
            Membership.status,
            Membership.created_at,
        )
        .join(
            Role,
            Role.id == Membership.role_id,
        )
        .join(
            User,
            User.id == Membership.user_id,
        )
        .where(
            Membership.organization_id == organization_id,
        )
        .order_by(Membership.created_at)
    )

    result = await session.exec(statement)

    return [
        MembershipWithDetailsOut(
            id=row.id,
            user_id=row.user_id,
            organization_id=row.organization_id,
            role_id=row.role_id,
            role_name=row.name,
            user_email=row.email,
            status=row.status,
            created_at=row.created_at,
        )
        for row in result.all()
    ]