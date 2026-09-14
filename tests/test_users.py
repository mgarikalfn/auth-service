"""Tests for the ``GET /users/me`` protected endpoint."""

import pytest
from httpx import AsyncClient

SIGNUP = "/auth/signup"
LOGIN = "/auth/login"
ME = "/users/me"

_USER = {
    "email": "auth_test@example.com", 
    "password": "strongpassword1",
    "organization_name": "Test Org"
}

async def _get_access_token(client: AsyncClient) -> str:
    """Helper: signup + login and return the access token."""
    await client.post(SIGNUP, json=_USER)
    tokens = (await client.post(LOGIN, json=_USER)).json()
    return tokens["access_token"]


# ── Authenticated access ──────────────────────────────────────────────────────


async def test_get_me_with_valid_token_returns_profile(client: AsyncClient) -> None:
    """A valid access token returns the authenticated user's profile."""
    token = await _get_access_token(client)
    response = await client.get(ME, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == _USER["email"]
    assert body["role"] == "user"
    assert "hashed_password" not in body


# ── Unauthenticated access ────────────────────────────────────────────────────


async def test_get_me_without_token_returns_401(client: AsyncClient) -> None:
    """A request with no Authorization header returns 401."""
    response = await client.get(ME)
    assert response.status_code == 401


async def test_get_me_with_invalid_token_returns_401(client: AsyncClient) -> None:
    """A request with a malformed / tampered token returns 401."""
    response = await client.get(ME, headers={"Authorization": "Bearer bad.token.value"})
    assert response.status_code == 401


async def test_get_me_with_refresh_token_returns_401(client: AsyncClient) -> None:
    """A refresh token submitted to a protected route returns 401 (wrong type)."""
    await client.post(SIGNUP, json=_USER)
    tokens = (await client.post(LOGIN, json=_USER)).json()
    refresh = tokens["refresh_token"]

    response = await client.get(ME, headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 401
