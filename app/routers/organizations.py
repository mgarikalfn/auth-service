
"""Organization management routes."""

from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationOut
from app.services import organization_service

router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
)


@router.post(
    "",
    response_model=OrganizationOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization",
)
async def create_organization(
    data: OrganizationCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrganizationOut:
    """Create an organization and make the current user its owner."""

    return await organization_service.create_organization(
        data,
        current_user,
        session,
    )


@router.get(
    "",
    response_model=list[OrganizationOut],
    summary="List my organizations",
)
async def list_organizations(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[OrganizationOut]:
    """Return all active organizations belonging to the current user."""

    return await organization_service.get_user_organizations(
        current_user,
        session,
    )

