"""Pydantic schemas for organization roles."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    permission_ids: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Role name cannot be blank")

        return value


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError("Role name cannot be blank")

        return value
class RoleOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    is_system: bool
    created_at: datetime
    model_config = {"from_attributes": True}