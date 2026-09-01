"""Pydantic v2 schemas for authentication endpoints."""

from pydantic import BaseModel, EmailStr, field_validator


class SignupRequest(BaseModel):
    """Payload for ``POST /auth/signup``."""

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, value: str) -> str:
        """Reject passwords shorter than 8 characters at the schema layer."""
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
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
