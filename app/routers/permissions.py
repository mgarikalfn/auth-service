"""Permission catalog routes."""

import uuid

from fastapi import APIRouter, Depends
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.organization import get_current_membership
from app.models.membership import Membership
from app.schemas.permission import PermissionOut
from app.services import permission_service

router = APIRouter(
    prefix="/organizations/{organization_id}/permissions",
    tags=["Organization Permissions"],
)


@router.get(
    "",
    response_model=list[PermissionOut],
    summary="List available permissions",
)
async def list_permissions(
    organization_id: uuid.UUID,
    membership: Membership = Depends(get_current_membership),
    session: AsyncSession = Depends(get_session),
) -> list[PermissionOut]:
    permissions = await permission_service.get_system_permissions(
        session=session,
    )

    return [
        PermissionOut.model_validate(permission)
        for permission in permissions
    ]