
"""Membership business logic."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.membership import Membership, MembershipStatus
from app.models.user import User


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

