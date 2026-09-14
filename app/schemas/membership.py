"""Pydantic schemas for organization memberships."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.membership import MembershipStatus


class MembershipOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role_id: uuid.UUID
    status: MembershipStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class MembershipWithDetailsOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str
    user_email: str
    status: MembershipStatus
    created_at: datetime


class MembershipRoleUpdate(BaseModel):
    role_id: uuid.UUID


class MembershipStatusUpdate(BaseModel):
    status: MembershipStatus