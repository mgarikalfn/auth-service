import uuid

import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import create_access_token
from app.models.invitation import Invitation, InvitationStatus
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User
from app.services.invitation_service import (
    create_invitation,
)

from app.models.permission import Permission, RolePermission

@pytest.mark.asyncio
async def test_create_invitation(
    client: AsyncClient,
    session: AsyncSession,
):
    # Create inviter
    inviter = User(
        email="inviter@example.com",
        hashed_password="hashed-password",
    )
    session.add(inviter)
    await session.flush()

    # Create organization
    organization = Organization(
        name="Test Organization",
        slug=f"test-organization-{uuid.uuid4().hex[:8]}",
    )
    session.add(organization)
    await session.flush()

    # Create role
    # Create role
    role = Role(
        organization_id=organization.id,
        name="Manager",
        description="Test manager role",
        is_system=False,
    )
    session.add(role)
    await session.flush()

# Create required permission
    permission = Permission(
        key="members.create",
        description="Create organization members",
    )
    session.add(permission)
    await session.flush()

# Assign permission to role
    role_permission = RolePermission(
        role_id=role.id,
        permission_id=permission.id,
    )
    session.add(role_permission)
    await session.flush()

    # Create inviter membership
    membership = Membership(
        user_id=inviter.id,
        organization_id=organization.id,
        role_id=role.id,
    )
    session.add(membership)

    await session.commit()

    # Create access token
    access_token = create_access_token(str(inviter.id))

    response = await client.post(
        f"/organizations/{organization.id}/invitations",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "invited_email": "newuser@example.com",
            "role_id": str(role.id),
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["invited_email"] == "newuser@example.com"
    assert data["status"] == "pending"
    assert data["organization_id"] == str(organization.id)
    assert data["role_id"] == str(role.id)


@pytest.mark.asyncio
async def test_accept_invitation_creates_user_and_membership(
    client: AsyncClient,
    session: AsyncSession,
):
    # Create organization
    organization = Organization(
        name="Invitation Organization",
        slug=f"invitation-org-{uuid.uuid4().hex[:8]}",
    )
    session.add(organization)
    await session.flush()

    # Create role
    role = Role(
        organization_id=organization.id,
        name="Employee",
        description="Test employee role",
        is_system=False,
    )
    session.add(role)
    await session.flush()

    # Create inviter
    inviter = User(
        email=f"inviter-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="hashed-password",
    )
    session.add(inviter)
    await session.flush()

    # Create invitation directly so we can retain the raw token
    invitation, raw_token = await create_invitation(
        organization_id=organization.id,
        invited_by_user_id=inviter.id,
        invited_email="newuser@example.com",
        role_id=role.id,
        session=session,
    )

    await session.commit()

    response = await client.post(
        "/invitations/accept",
        json={
            "token": raw_token,
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "Invitation accepted successfully"
    assert data["user_id"]
    assert data["organization_id"] == str(organization.id)
    assert data["membership_id"]
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "bearer"

    # Verify user was created
    user_statement = select(User).where(
        User.email == "newuser@example.com"
    )
    user_result = await session.exec(user_statement)
    user = user_result.first()

    assert user is not None
    assert str(user.id) == data["user_id"]

    # Verify membership was created
    membership_statement = select(Membership).where(
        Membership.user_id == user.id,
        Membership.organization_id == organization.id,
    )
    membership_result = await session.exec(membership_statement)
    membership = membership_result.first()

    assert membership is not None
    assert membership.role_id == role.id

    # Verify invitation was accepted
    await session.refresh(invitation)

    assert invitation.status == InvitationStatus.ACCEPTED
    assert invitation.accepted_by_user_id == user.id
    assert invitation.accepted_at is not None


@pytest.mark.asyncio
async def test_cannot_accept_invitation_twice(
    client: AsyncClient,
    session: AsyncSession,
):
    organization = Organization(
        name="Double Accept Organization",
        slug=f"double-accept-{uuid.uuid4().hex[:8]}",
    )
    session.add(organization)
    await session.flush()

    role = Role(
        organization_id=organization.id,
        name="Employee",
        description="Test employee role",
        is_system=False,
    )
    session.add(role)
    await session.flush()

    inviter = User(
        email=f"inviter-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="hashed-password",
    )
    session.add(inviter)
    await session.flush()

    invitation, raw_token = await create_invitation(
        organization_id=organization.id,
        invited_by_user_id=inviter.id,
        invited_email=f"double-{uuid.uuid4().hex[:8]}@example.com",
        role_id=role.id,
        session=session,
    )

    await session.commit()

    first_response = await client.post(
        "/invitations/accept",
        json={
            "token": raw_token,
            "password": "StrongPassword123!",
        },
    )

    assert first_response.status_code == 200

    second_response = await client.post(
        "/invitations/accept",
        json={
            "token": raw_token,
            "password": "AnotherPassword123!",
        },
    )

    assert second_response.status_code == 400