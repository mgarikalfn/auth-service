"""Pydantic v2 schemas for authentication endpoints."""

from pydantic import BaseModel, EmailStr, field_validator,Field


class SignupRequest(BaseModel):
    """Payload for ``POST /auth/signup``."""

    email: EmailStr
    password: str
    organization_name:str = Field(min_length=2 , max_length=255)
    
    @field_validator("password")
    @classmethod
    def password_min_length(cls, value: str) -> str:
        """Reject passwords shorter than 8 characters at the schema layer."""
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return value

    @field_validator("organization_name")
    @classmethod
    def organization_name_not_blank(cls , value:str) -> str:
        """Reject organization names containing only whitespace"""

        value =value.strip()

        if not value:
            raise ValueError("organization name cannot be blank")
        return value


class LoginRequest(BaseModel):
    """Payload for ``POST /auth/login``."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Returned by ``/auth/login`` and ``/auth/refresh``."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Payload for ``POST /auth/refresh``."""

    refresh_token: str

class OrganizationTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    organization_id: uuid.UUID