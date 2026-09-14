
"""Pydantic schemas for organization roles."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class RoleOut(BaseModel):
    """Safe organization role representation."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    is_system: bool
    created_at: datetime

    model_config = {"from_attributes": True}
