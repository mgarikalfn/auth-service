
"""Organization management routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.dependencies.organization import get_current_membership, get_current_role
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationOut
from app.schemas.role import RoleOut
from app.services import organization_service

router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
)

@router.get("/{organization_id}",response_model=OrganizationOut,summary="Get an organization")

async def get_organization(organization_id:UUID,membership:Membership = Depends(get_current_membership),session:AsyncSession = Depends(get_session)) -> OrganizationOut:
    """Get an organization the current user belongs to"""

    organization = await session.get(Organization,membership.organization_id)

    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Organization not found")
    return OrganizationOut.model_validate(organization)


@router.get(
    "/{organization_id}/my-role",
    response_model=RoleOut,
    summary="Get my role in an organization",
)
async def get_my_role(
    role: Role = Depends(get_current_role),
) -> RoleOut:
    """Return the current user's role in the organization."""

    return RoleOut.model_validate(role)


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

