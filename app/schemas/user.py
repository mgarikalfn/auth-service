"""Pydantic v2 schemas for user-facing representations.

``UserOut`` deliberately omits ``hashed_password`` so it can never be leaked
through any response body.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models.user import UserRole


class UserOut(BaseModel):
    """Safe public representation of a User — no sensitive fields."""

    id: uuid.UUID
    email: EmailStr
    role: UserRole
    created_at: datetime

    model_config = {"from_attributes": True}
