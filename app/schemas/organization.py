"""Pydantic v2 schemas for organization endpoints."""
import uuid 
from datetime import datetime

from pydantic import BaseModel,Field, field_validator

class OrganizationCreate(BaseModel):
    """Payload for creating an organization."""

    name:str = Field(min_length=2 , max_length=255)

    @field_validator("name")
    @classmethod
    def validate_name(cls,value:str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("organization name cannot be blank")
        return value

class OrganizationOut(BaseModel):
    """Safe organization representation returned by the API."""
    id:uuid.UUID
    name:str
    slug:str
    created_at:datetime

    model_config={"from_attributes":True}