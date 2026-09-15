"""Business logic for organization invitations."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.password_policy import validate_password
from app.core.security import (
    create_invitation_token,
    create_organization_access_token,
    hash_invitation_token,
)
from app.models.invitation import Invitation, InvitationStatus
from app.models.membership import Membership, MembershipStatus
from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User
from app.schemas.invitation import PublicInvitationOut

from app.core.security import (
    create_access_token,
    create_invitation_token,
    create_refresh_token,
    hash_invitation_token,
    hash_password,
)
from app.models.organization import Organization
def _ensure_utc(value: datetime) -> datetime:
    """Treat naive database datetimes as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


async def create_invitation(
    *,
    organization_id: uuid.UUID,
    invited_by_user_id: uuid.UUID,
    invited_email: str,
    role_id: uuid.UUID,
    session: AsyncSession,
) -> tuple[Invitation, str]:
    """Create an invitation and return it with the raw token."""

    normalized_email = invited_email.strip().lower()

    role_statement = select(Role).where(
        Role.id == role_id,
        Role.organization_id == organization_id,
    )
    role_result = await session.exec(role_statement)
    role = role_result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The selected role does not belong to this organization",
        )

    user_statement = select(User).where(User.email == normalized_email)
    user_result = await session.exec(user_statement)
    existing_user = user_result.first()

    if existing_user is not None:
        membership_statement = select(Membership).where(
            Membership.user_id == existing_user.id,
            Membership.organization_id == organization_id,
        )
        membership_result = await session.exec(membership_statement)
        existing_membership = membership_result.first()

        if existing_membership is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This user already belongs to the organization",
            )

    pending_statement = select(Invitation).where(
        Invitation.organization_id == organization_id,
        Invitation.invited_email == normalized_email,
        Invitation.status == InvitationStatus.PENDING,
    )
    pending_result = await session.exec(pending_statement)

    if pending_result.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending invitation already exists for this email",
        )

    raw_token = create_invitation_token()
    token_hash = hash_invitation_token(raw_token)

    invitation = Invitation(
        organization_id=organization_id,
        role_id=role_id,
        invited_by_user_id=invited_by_user_id,
        invited_email=normalized_email,
        token_hash=token_hash,
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.utc)
        + timedelta(hours=settings.INVITATION_EXPIRE_HOURS),
    )

    session.add(invitation)
    await session.flush()
    await session.refresh(invitation)

    return invitation, raw_token


async def get_invitation_by_token(
    *,
    token: str,
    session: AsyncSession,
) -> Invitation | None:
    """Find an invitation using a raw token."""

    token_hash = hash_invitation_token(token)

    statement = select(Invitation).where(
        Invitation.token_hash == token_hash,
    )
    result = await session.exec(statement)
    invitation = result.first()

    if invitation is None:
        return None

    now = datetime.now(timezone.utc)
    expires_at = _ensure_utc(invitation.expires_at)

    if (
    invitation.status == InvitationStatus.PENDING
    and expires_at <= now
    ):
        invitation.status = InvitationStatus.EXPIRED
        await session.commit()
        await session.refresh(invitation)

    return invitation


async def cancel_invitation(
    *,
    invitation: Invitation,
    organization_id: uuid.UUID,
    session: AsyncSession,
) -> Invitation:
    """Cancel a pending invitation belonging to an organization."""

    if invitation.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    if invitation.status != InvitationStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only pending invitations can be cancelled",
        )

    invitation.status = InvitationStatus.CANCELLED
    invitation.cancelled_at = datetime.now(timezone.utc)

    session.add(invitation)
    await session.commit()
    await session.refresh(invitation)

    return invitation

async def get_public_invitation(
    *,
    invitation: Invitation,
    session: AsyncSession,
) -> PublicInvitationOut:
    """Build safe public invitation information."""

    organization_statement = select(Organization).where(
        Organization.id == invitation.organization_id,
    )
    organization_result = await session.exec(organization_statement)
    organization = organization_result.first()

    role_statement = select(Role).where(
        Role.id == invitation.role_id,
        Role.organization_id == invitation.organization_id,
    )
    role_result = await session.exec(role_statement)
    role = role_result.first()

    if organization is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation details are unavailable",
        )

    return PublicInvitationOut(
        id=invitation.id,
        organization_id=invitation.organization_id,
        organization_name=organization.name,
        role_id=invitation.role_id,
        role_name=role.name,
        invited_email=invitation.invited_email,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
    )

async def accept_invitation(
    *,
    token: str,
    password: str | None,
    current_user: User | None,
    session: AsyncSession,
) -> tuple[User, Membership, Invitation, str, str]:
    """Accept an invitation and create an active organization membership."""

    invitation = await get_invitation_by_token(
        token=token,
        session=session,
    )

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    if invitation.status != InvitationStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invitation is {invitation.status.value}",
        )

    now = datetime.now(timezone.utc)

    if _ensure_utc(invitation.expires_at) <= now:
        invitation.status = InvitationStatus.EXPIRED
        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This invitation has expired",
        )

    invited_email = invitation.invited_email.strip().lower()

    if current_user is not None:
        if current_user.email.strip().lower() != invited_email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This invitation belongs to a different email address",
            )

        user = current_user

    else:
        if password is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A password is required when creating a new account",
            )

        user_statement = select(User).where(User.email == invited_email)
        user_result = await session.exec(user_statement)
        user = user_result.first()

        if user is None:
            validate_password(password);
            user = User(
                email=invited_email,
                hashed_password=hash_password(password),
            )
            session.add(user)
            await session.flush()

        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="An account already exists for this email. Log in first, then accept the invitation.",
            )

    membership_statement = select(Membership).where(
        Membership.user_id == user.id,
        Membership.organization_id == invitation.organization_id,
    )
    membership_result = await session.exec(membership_statement)
    membership = membership_result.first()

    if membership is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This user already belongs to the organization",
        )

    membership = Membership(
        user_id=user.id,
        organization_id=invitation.organization_id,
        role_id=invitation.role_id,
        status=MembershipStatus.ACTIVE,
    )
    session.add(membership)
    await session.flush()

    invitation.status = InvitationStatus.ACCEPTED
    invitation.accepted_by_user_id = user.id
    invitation.accepted_at = now

    session.add(invitation)

    await session.commit()
    await session.refresh(user)
    await session.refresh(membership)
    await session.refresh(invitation)

    access_token = create_organization_access_token(subject=str(user.id),organization_id=str(invitation.organization_id))
    refresh_token = create_refresh_token(subject=str(user.id),organization_id=str(invitation.organization_id))

    return (
        user,
        membership,
        invitation,
        access_token,
        refresh_token,
    )