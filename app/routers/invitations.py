"""Invitation API routes."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.security import TOKEN_TYPE_ACCESS, decode_token
from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.dependencies.organization import (
    get_current_membership,
    require_permission,
)
from app.models.invitation import Invitation
from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User
from app.schemas.invitation import (
    InvitationAccept,
    InvitationAcceptOut,
    InvitationCreate,
    InvitationOut,
    PublicInvitationOut,
)
from app.services.email_service import (
    EmailMessage,
    get_email_service,
)
from app.services.invitation_service import (
    accept_invitation,
    cancel_invitation,
    create_invitation,
    get_invitation_by_token,
    get_public_invitation,
)
from app.services.membership_service import resend_invitation
from app.templates.invitation_email import build_invitation_email


router = APIRouter(
    tags=["Invitations"],
)

optional_bearer = HTTPBearer(auto_error=False)


async def get_optional_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(optional_bearer),
    ],
    session: AsyncSession = Depends(get_session),
) -> User | None:
    """Return the authenticated user when a valid access token is provided."""

    if credentials is None:
        return None

    payload = decode_token(credentials.credentials)

    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    result = await session.exec(
        select(User).where(User.id == parsed_user_id)
    )
    user = result.first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


@router.post(
    "/organizations/{organization_id}/invitations",
    response_model=InvitationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization_invitation(
    organization_id: uuid.UUID,
    data: InvitationCreate,
    current_user: User = Depends(get_current_user),
    _: Role = Depends(require_permission("members.create")),
    session: AsyncSession = Depends(get_session),
) -> Invitation:
    """Create an invitation and send it by email."""

    invitation, raw_token = await create_invitation(
        organization_id=organization_id,
        invited_by_user_id=current_user.id,
        invited_email=data.invited_email,
        role_id=data.role_id,
        session=session,
    )

    organization_result = await session.exec(
        select(Organization).where(
            Organization.id == invitation.organization_id
        )
    )
    organization = organization_result.first()

    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invitation organization could not be loaded",
        )

    role_result = await session.exec(
        select(Role).where(
            Role.id == invitation.role_id,
            Role.organization_id == invitation.organization_id,
        )
    )
    role = role_result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invitation role could not be loaded",
        )

    invitation_url = (
        f"{settings.APP_URL}/invitations/accept"
        f"?token={raw_token}"
    )

    subject, html, text = build_invitation_email(
        organization_name=organization.name,
        role_name=role.name,
        invitation_url=invitation_url,
        expires_at=invitation.expires_at.isoformat(),
    )

    email_service = get_email_service()

    await email_service.send(
        EmailMessage(
            to=invitation.invited_email,
            subject=subject,
            html=html,
            text=text,
        )
    )

    await session.commit()
    await session.refresh(invitation)

    return invitation

@router.get(
    "/invitations/public",
    response_model=PublicInvitationOut,
)
async def get_public_invitation_details(
    token: str = Query(..., min_length=32, max_length=128),
    session: AsyncSession = Depends(get_session),
) -> PublicInvitationOut:
    """Return public invitation details using the raw invitation token."""

    invitation = await get_invitation_by_token(
        token=token,
        session=session,
    )

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    return await get_public_invitation(
        invitation=invitation,
        session=session,
    )


@router.post(
    "/organizations/{organization_id}/invitations/{invitation_id}/cancel",
    response_model=InvitationOut,
)
async def cancel_organization_invitation(
    organization_id: uuid.UUID,
    invitation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    current_membership=Depends(get_current_membership),
    _: Role = Depends(require_permission("members.update")),
    session: AsyncSession = Depends(get_session),
) -> Invitation:
    """Cancel a pending organization invitation."""

    result = await session.exec(
        select(Invitation).where(
            Invitation.id == invitation_id,
            Invitation.organization_id == organization_id,
        )
    )
    invitation = result.first()

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    return await cancel_invitation(
        invitation=invitation,
        organization_id=organization_id,
        session=session,
    )


@router.post(
    "/invitations/accept",
    response_model=InvitationAcceptOut,
)
async def accept_organization_invitation(
    data: InvitationAccept,
    current_user: User | None = Depends(get_optional_current_user),
    session: AsyncSession = Depends(get_session),
) -> InvitationAcceptOut:
    """Accept an invitation and create or activate organization membership."""

    (
        user,
        membership,
        invitation,
        access_token,
        refresh_token,
    ) = await accept_invitation(
        token=data.token,
        password=data.password,
        current_user=current_user,
        session=session,
    )

    return InvitationAcceptOut(
        message="Invitation accepted successfully",
        user_id=user.id,
        organization_id=membership.organization_id,
        membership_id=membership.id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )

@router.post(
    "/organizations/{organization_id}/invitations/{invitation_id}/resend",
    response_model=InvitationOut,
)
async def resend_organization_invitation(
    organization_id: uuid.UUID,
    invitation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    _: Role = Depends(require_permission("members.create")),
    session: AsyncSession = Depends(get_session),
) -> Invitation:
    """Resend an organization invitation."""

    result = await session.exec(
        select(Invitation).where(
            Invitation.id == invitation_id,
            Invitation.organization_id == organization_id,
        )
    )
    invitation = result.first()

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    invitation, raw_token = await resend_invitation(
        invitation=invitation,
        session=session,
    )

    organization_result = await session.exec(
        select(Organization).where(
            Organization.id == invitation.organization_id,
        )
    )
    organization = organization_result.first()

    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invitation organization could not be loaded",
        )

    role_result = await session.exec(
        select(Role).where(
            Role.id == invitation.role_id,
            Role.organization_id == invitation.organization_id,
        )
    )
    role = role_result.first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invitation role could not be loaded",
        )

    invitation_url = (
        f"{settings.APP_URL}/invitations/accept"
        f"?token={raw_token}"
    )

    subject, html, text = build_invitation_email(
        organization_name=organization.name,
        role_name=role.name,
        invitation_url=invitation_url,
        expires_at=invitation.expires_at.isoformat(),
    )

    email_service = get_email_service()

    await email_service.send(
        EmailMessage(
            to=invitation.invited_email,
            subject=subject,
            html=html,
            text=text,
        )
    )

    await session.commit()
    await session.refresh(invitation)

    return invitation