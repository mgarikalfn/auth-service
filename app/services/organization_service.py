
"""Organization business logic."""

import re
import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.membership import Membership, MembershipStatus
from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationOut


def _generate_slug(name: str) -> str:
    """Generate a URL-safe slug from an organization name."""

    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")

    if not slug:
        slug = "organization"

    return slug[:100]


async def _generate_unique_slug(
    name: str,
    session: AsyncSession,
) -> str:
    """Generate a unique organization slug."""

    base_slug = _generate_slug(name)

    result = await session.exec(
        select(Organization).where(
            Organization.slug == base_slug
        )
    )

    if result.first() is None:
        return base_slug

    while True:
        suffix = uuid.uuid4().hex[:8]
        max_base_length = 100 - len(suffix) - 1

        candidate = f"{base_slug[:max_base_length]}-{suffix}"

        result = await session.exec(
            select(Organization).where(
                Organization.slug == candidate
            )
        )

        if result.first() is None:
            return candidate


async def create_organization_for_user(
    name: str,
    user: User,
    session: AsyncSession,
) -> Organization:
    """Create an organization and its initial owner membership.

    This is the single source of truth for organization creation.

    Creates atomically:

    1. Organization
    2. Owner role
    3. Active membership for the user

    The caller controls the transaction commit.
    """

    slug = await _generate_unique_slug(
        name,
        session,
    )

    organization = Organization(
        name=name.strip(),
        slug=slug,
    )

    owner_role = Role(
        organization_id=organization.id,
        name="Owner",
        description="Full access to the organization",
        is_system=True,
    )

    membership = Membership(
        user_id=user.id,
        organization_id=organization.id,
        role_id=owner_role.id,
        status=MembershipStatus.ACTIVE,
    )

    session.add(organization)
    session.add(owner_role)
    session.add(membership)

    return organization


async def create_organization(
    data: OrganizationCreate,
    current_user: User,
    session: AsyncSession,
) -> OrganizationOut:
    """Create an organization for the current user."""

    organization = await create_organization_for_user(

        name=data.name,
        user=current_user,
        session=session,
    )

    await session.commit()
    await session.refresh(organization)

    return OrganizationOut.model_validate(organization)


async def get_user_organizations(
    current_user: User,
    session: AsyncSession,
) -> list[OrganizationOut]:
    """Return organizations the current user belongs to."""

    statement = (
        select(Organization)
        .join(
            Membership,
            Membership.organization_id == Organization.id,
        )
        .where(
            Membership.user_id == current_user.id,
            Membership.status == MembershipStatus.ACTIVE,
        )
        .order_by(Organization.created_at)
    )

    result = await session.exec(statement)

    return [
        OrganizationOut.model_validate(organization)
        for organization in result.all()
    ]

