"""Pydantic schemas for permissions."""

import uuid

from pydantic import BaseModel


class PermissionOut(BaseModel):
    id: uuid.UUID
    key: str
    description: str | None

    model_config = {"from_attributes": True}