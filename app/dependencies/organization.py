
"""Dependencies for organization-scoped authorization."""

import uuid

from fastapi import Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.models.membership import Membership
from app.models.user import User
from app.services.membership_service import get_active_membership


async def get_current_membership(
    organization_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Membership:
    """Resolve the current user's active membership in an organization.

    Raises:
        403 Forbidden: if the user does not belong to the organization.
    """

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

