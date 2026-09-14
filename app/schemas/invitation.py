"""Schemas for organization invitations."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.invitation import InvitationStatus


class InvitationCreate(BaseModel):
    invited_email: EmailStr
    role_id: uuid.UUID


class InvitationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    role_id: uuid.UUID
    invited_by_user_id: uuid.UUID
    invited_email: str
    status: InvitationStatus
    expires_at: datetime
    accepted_by_user_id: uuid.UUID | None
    accepted_at: datetime | None
    cancelled_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PublicInvitationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    role_id: uuid.UUID
    role_name: str
    invited_email: str
    status: InvitationStatus
    expires_at: datetime
    created_at: datetime


class InvitationAccept(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    password: str | None = Field(
        default=None,
        min_length=8,
        max_length=128,
    )


class InvitationAcceptOut(BaseModel):
    message: str
    user_id: uuid.UUID
    organization_id: uuid.UUID
    membership_id: uuid.UUID
    access_token: str
    refresh_token: str
    token_type: str = "bearer"