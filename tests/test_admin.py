"""Tests for the admin-only ``GET /admin/users`` endpoint (RBAC).

These tests verify three distinct outcomes:
1. Admin users can successfully list all users.
2. Regular users receive 403 Forbidden.
3. Unauthenticated requests receive 401 Unauthorized.

The ``session`` fixture is injected alongside ``client`` so tests can directly
elevate a user's role in the database (simulating an out-of-band admin grant).
"""

import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.user import User, UserRole

SIGNUP = "/auth/signup"
LOGIN = "/auth/login"
ADMIN_USERS = "/admin/users"

_ADMIN_CREDS = {
    "email": "admin_rbac@example.com", 
    "password": "adminpassword1",
    "organization_name": "Admin Org"
}

_USER_CREDS = {
    "email": "user_rbac@example.com", 
    "password": "userpassword1",
    "organization_name": "User Org"
}


async def _elevate_to_admin(session: AsyncSession, email: str) -> None:
    """Directly update a user's role to admin in the test database."""
    result = await session.exec(select(User).where(User.email == email))
    user: User = result.one()
    user.role = UserRole.admin
    session.add(user)
    await session.commit()
    await session.refresh(user)


async def _signup_and_login(client: AsyncClient, creds: dict) -> str:
    """Helper: register a user and return their access token."""
    await client.post(SIGNUP, json=creds)
    tokens = (await client.post(LOGIN, json=creds)).json()
    return tokens["access_token"]


# ── RBAC scenarios ────────────────────────────────────────────────────────────


async def test_admin_can_list_all_users(
    client: AsyncClient, session: AsyncSession
) -> None:
    """An admin user receives 200 and a list of user objects."""
    token = await _signup_and_login(client, _ADMIN_CREDS)
    await _elevate_to_admin(session, _ADMIN_CREDS["email"])

    response = await client.get(
        ADMIN_USERS, headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    # Confirm no hashed passwords leak through
    for user_obj in body:
        assert "hashed_password" not in user_obj


async def test_regular_user_gets_403(client: AsyncClient) -> None:
    """A regular (non-admin) user is forbidden from the admin endpoint."""
    token = await _signup_and_login(client, _USER_CREDS)

    response = await client.get(
        ADMIN_USERS, headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


async def test_unauthenticated_request_gets_401(client: AsyncClient) -> None:
    """An unauthenticated request to the admin endpoint returns 401, not 403."""
    response = await client.get(ADMIN_USERS)
    assert response.status_code == 401
