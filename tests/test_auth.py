"""Tests for authentication endpoints: signup, login, and token refresh."""

import pytest
from httpx import AsyncClient

SIGNUP = "/auth/signup"
LOGIN = "/auth/login"
REFRESH = "/auth/refresh"

_USER = {"email": "auth_test@example.com", "password": "strongpassword1"}


# ── Signup ────────────────────────────────────────────────────────────────────


async def test_signup_success(client: AsyncClient) -> None:
    """A valid signup returns 201 with the user's public profile."""
    response = await client.post(SIGNUP, json=_USER)

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == _USER["email"]
    assert body["role"] == "user"
    assert "hashed_password" not in body


async def test_signup_duplicate_email_returns_409(client: AsyncClient) -> None:
    """Registering the same email twice returns 409 Conflict."""
    await client.post(SIGNUP, json=_USER)
    response = await client.post(SIGNUP, json=_USER)

    assert response.status_code == 409
    assert "already registered" in response.json()["detail"]


async def test_signup_short_password_returns_422(client: AsyncClient) -> None:
    """Passwords shorter than 8 characters are rejected at the schema layer."""
    response = await client.post(
        SIGNUP, json={"email": "short@example.com", "password": "abc123"}
    )
    assert response.status_code == 422


async def test_signup_invalid_email_returns_422(client: AsyncClient) -> None:
    """Non-email strings for the email field are rejected."""
    response = await client.post(
        SIGNUP, json={"email": "not-an-email", "password": "strongpassword1"}
    )
    assert response.status_code == 422


# ── Login ─────────────────────────────────────────────────────────────────────


async def test_login_success_returns_token_pair(client: AsyncClient) -> None:
    """A correct login returns both an access token and a refresh token."""
    await client.post(SIGNUP, json=_USER)
    response = await client.post(LOGIN, json=_USER)

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    # Tokens must be non-empty strings
    assert len(body["access_token"]) > 0
    assert len(body["refresh_token"]) > 0


async def test_login_wrong_password_returns_401(client: AsyncClient) -> None:
    """A wrong password returns 401 with the same generic message."""
    await client.post(SIGNUP, json=_USER)
    response = await client.post(
        LOGIN, json={"email": _USER["email"], "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


async def test_login_nonexistent_user_returns_401(client: AsyncClient) -> None:
    """A login attempt for a non-existent user returns 401 (not 404) to prevent
    user enumeration."""
    response = await client.post(
        LOGIN, json={"email": "nobody@example.com", "password": "somepassword1"}
    )
    assert response.status_code == 401


# ── Refresh ───────────────────────────────────────────────────────────────────


async def test_refresh_with_valid_refresh_token_succeeds(client: AsyncClient) -> None:
    """A valid refresh token yields a new access token."""
    await client.post(SIGNUP, json=_USER)
    tokens = (await client.post(LOGIN, json=_USER)).json()

    response = await client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    # The new access token should differ from the original
    assert body["access_token"] != tokens["access_token"]


async def test_refresh_with_access_token_is_rejected(client: AsyncClient) -> None:
    """Using an access token where a refresh token is expected returns 401."""
    await client.post(SIGNUP, json=_USER)
    tokens = (await client.post(LOGIN, json=_USER)).json()

    response = await client.post(REFRESH, json={"refresh_token": tokens["access_token"]})
    assert response.status_code == 401


async def test_refresh_with_garbage_token_returns_401(client: AsyncClient) -> None:
    """A completely invalid string returns 401."""
    response = await client.post(REFRESH, json={"refresh_token": "this.is.garbage"})
    assert response.status_code == 401
