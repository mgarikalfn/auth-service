"""Endpoints for organization invitations."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.dependencies.organization import require_permission
from app.models.invitation import Invitation
from app.models.user import User
from app.schemas.invitation import (
    InvitationCreate,
    InvitationOut,
    PublicInvitationOut,
)
from app.services.invitation_service import (
    cancel_invitation,
    create_invitation,
    get_invitation_by_token,
    get_public_invitation,
)

from app.dependencies.auth import get_current_user
from app.schemas.invitation import (
    InvitationAccept,
    InvitationAcceptOut,
)
from app.services.invitation_service import accept_invitation

from fastapi.security import HTTPBearer
from jose import JWTError
from app.core.security import decode_token
from app.services.user_service import get_user_by_id

optional_bearer = HTTPBearer(auto_error=False)


async def get_optional_current_user(
    credentials=Depends(optional_bearer),
    session: AsyncSession = Depends(get_session),
) -> User | None:
    """Return the authenticated user, or None for public requests."""

    if credentials is None:
        return None

    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required",
        )

    subject = payload.get("sub")

    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )

    try:
        user_id = uuid.UUID(subject)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token subject",
        ) from exc

    return await get_user_by_id(
        user_id=user_id,
        session=session,
    )


router = APIRouter(tags=["Invitations"])


@router.post(
    "/organizations/{organization_id}/invitations",
    response_model=InvitationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization_invitation(
    organization_id: uuid.UUID,
    payload: InvitationCreate,
    current_user: User = Depends(get_current_user),
    _: object = Depends(require_permission("members.create")),
    session: AsyncSession = Depends(get_session),
) -> Invitation:
    """Create an invitation for an organization member."""

    invitation, raw_token = await create_invitation(
        organization_id=organization_id,
        invited_by_user_id=current_user.id,
        invited_email=str(payload.invited_email),
        role_id=payload.role_id,
        session=session,
    )

    await session.commit()
    await session.refresh(invitation)

    # Temporary development behavior.
    # Replace this with email delivery in the next step.
    print(
        "Organization invitation link:",
        f"{settings.APP_URL}/invitations/accept?token={raw_token}",
    )

    return invitation


@router.get(
    "/invitations/public",
    response_model=PublicInvitationOut,
)
async def read_public_invitation(
    token: str = Query(..., min_length=32, max_length=128),
    session: AsyncSession = Depends(get_session),
) -> PublicInvitationOut:
    """View safe invitation details using the raw invitation token."""

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
    _: object = Depends(require_permission("members.update")),
    session: AsyncSession = Depends(get_session),
) -> Invitation:
    """Cancel an organization invitation."""

    statement = select(Invitation).where(
    Invitation.id == invitation_id,
    Invitation.organization_id == organization_id,
)

    result = await session.exec(statement)
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
    payload: InvitationAccept,
    current_user: User | None = Depends(get_optional_current_user),
    session: AsyncSession = Depends(get_session),
) -> InvitationAcceptOut:
    """Accept an invitation as an existing or new user."""

    (
        user,
        membership,
        invitation,
        access_token,
        refresh_token,
    ) = await accept_invitation(
        token=payload.token,
        password=payload.password,
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
    )

