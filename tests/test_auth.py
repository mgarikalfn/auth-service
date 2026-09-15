"""Tests for authentication endpoints: signup, login, and token refresh."""

from datetime import datetime, timedelta, timezone
import uuid
from fastapi import HTTPException
import pytest
from httpx import AsyncClient

from app.core.security import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_organization_access_token,
    create_refresh_token,
    decode_access_token,
    decode_token,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.services import organization_service
from app.services.membership_service import get_active_membership
from app.services.refresh_token_service import create_refresh_token_session, ensure_refresh_token_active, get_refresh_token_session, hash_refresh_token, issue_refresh_token_session, revoke_refresh_token

SIGNUP = "/auth/signup"
LOGIN = "/auth/login"
REFRESH = "/auth/refresh"

_USER = {
    "email": "auth_test@example.com", 
    "password": "strongpassword1",
    "organization_name": "Test Org"
}

# ── Signup ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signup_success(client: AsyncClient) -> None:
    """A valid signup returns 201 with the user's public profile."""
    response = await client.post(SIGNUP, json=_USER)

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == _USER["email"]
    assert body["role"] == "user"
    assert "hashed_password" not in body


@pytest.mark.asyncio
async def test_signup_duplicate_email_returns_409(client: AsyncClient) -> None:
    """Registering the same email twice returns 409 Conflict."""
    await client.post(SIGNUP, json=_USER)
    response = await client.post(SIGNUP, json=_USER)

    assert response.status_code == 409
    assert "already registered" in response.json()["detail"]


@pytest.mark.asyncio
async def test_signup_short_password_returns_422(client: AsyncClient) -> None:
    """Passwords shorter than 8 characters are rejected at the schema layer."""
    response = await client.post(
        SIGNUP, json={"email": "short@example.com", "password": "abc123"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_signup_invalid_email_returns_422(client: AsyncClient) -> None:
    """Non-email strings for the email field are rejected."""
    response = await client.post(
        SIGNUP, json={"email": "not-an-email", "password": "strongpassword1"}
    )
    assert response.status_code == 422


# ── Login ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(client: AsyncClient) -> None:
    """A wrong password returns 401 with the same generic message."""
    await client.post(SIGNUP, json=_USER)
    response = await client.post(
        LOGIN, json={"email": _USER["email"], "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_nonexistent_user_returns_401(client: AsyncClient) -> None:
    """A login attempt for a non-existent user returns 401 (not 404) to prevent
    user enumeration."""
    response = await client.post(
        LOGIN, json={"email": "nobody@example.com", "password": "somepassword1"}
    )
    assert response.status_code == 401


# ── Refresh ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_refresh_with_access_token_is_rejected(client: AsyncClient) -> None:
    """Using an access token where a refresh token is expected returns 401."""
    await client.post(SIGNUP, json=_USER)
    tokens = (await client.post(LOGIN, json=_USER)).json()

    response = await client.post(REFRESH, json={"refresh_token": tokens["access_token"]})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_garbage_token_returns_401(client: AsyncClient) -> None:
    """A completely invalid string returns 401."""
    response = await client.post(REFRESH, json={"refresh_token": "this.is.garbage"})
    assert response.status_code == 401


# ── Organization Token Generation Tests ───────────────────────────────────────


def test_create_organization_tokens():
    """Verify organization access and refresh tokens contain org_id claim."""
    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())

    access_token = create_organization_access_token(
        subject=user_id,
        organization_id=org_id,
    )
    refresh_token = create_refresh_token(
        subject=user_id,
        organization_id=org_id,
    )

    access_payload = decode_token(access_token)
    refresh_payload = decode_token(refresh_token)

    assert access_payload["sub"] == user_id
    assert access_payload["org_id"] == org_id
    assert refresh_payload["sub"] == user_id
    assert refresh_payload["org_id"] == org_id


def test_create_refresh_token_without_organization():
    """Verify refresh tokens generated without an organization do not include org_id."""
    user_id = uuid.uuid4()

    token = create_refresh_token(subject=str(user_id))
    payload = decode_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["type"] == TOKEN_TYPE_REFRESH
    assert "org_id" not in payload

def test_decode_access_token():
    user_id = uuid.uuid4()

    token = create_access_token(str(user_id))

    payload = decode_access_token(token)

    assert payload.sub == user_id
    assert payload.type == TOKEN_TYPE_ACCESS
    assert payload.org_id is None

def test_decode_organization_access_token():
    user_id = uuid.uuid4()
    organization_id = uuid.uuid4()

    token = create_organization_access_token(
        subject=str(user_id),
        organization_id=str(organization_id),
    )

    payload = decode_access_token(token)

    assert payload.sub == user_id
    assert payload.org_id == organization_id
    assert payload.type == TOKEN_TYPE_ACCESS


def test_decode_access_token_rejects_refresh_token():
    user_id = uuid.uuid4()

    token = create_refresh_token(str(user_id))

    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)

    assert exc_info.value.status_code == 401

def test_hash_refresh_token_is_deterministic():
    token = "test-refresh-token"

    assert hash_refresh_token(token) == hash_refresh_token(token)

def test_hash_refresh_token_produces_different_hashes():
    assert hash_refresh_token("token-a") != hash_refresh_token("token-b")


async def test_create_and_get_refresh_token_session(
    session,
):
    user_id = uuid.uuid4()
    token = "test-refresh-token"
    jti = uuid.uuid4().hex
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    created = await create_refresh_token_session(
        token=token,
        user_id=user_id,
        organization_id=None,
        expires_at=expires_at,
        jti=jti,
        session=session,
    )

    found = await get_refresh_token_session(
        token=token,
        session=session,
    )

    assert found.id == created.id
    assert found.user_id == user_id
    assert found.jti == jti
    assert found.token_hash == hash_refresh_token(token)


async def test_revoke_refresh_token(
    session,
):
    refresh_token = RefreshToken(
        jti=uuid.uuid4().hex,
        user_id=uuid.uuid4(),
        token_hash=hash_refresh_token("token"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )

    session.add(refresh_token)
    await session.flush()

    await revoke_refresh_token(
        refresh_token=refresh_token,
        replaced_by_jti="new-jti",
        session=session,
    )

    assert refresh_token.revoked_at is not None
    assert refresh_token.replaced_by_jti == "new-jti"


def test_ensure_refresh_token_active_rejects_revoked():
    refresh_token = RefreshToken(
        jti=uuid.uuid4().hex,
        user_id=uuid.uuid4(),
        token_hash="hash",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked_at=datetime.now(timezone.utc),
    )

    with pytest.raises(HTTPException) as exc_info:
        ensure_refresh_token_active(refresh_token)

    assert exc_info.value.status_code == 401

async def test_issue_refresh_token_session(
    session,
):
    user_id = uuid.uuid4()
    organization_id = uuid.uuid4()

    token = await issue_refresh_token_session(
        user_id=user_id,
        organization_id=organization_id,
        session=session,
    )

    assert token

    payload = decode_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["org_id"] == str(organization_id)
    assert payload["type"] == TOKEN_TYPE_REFRESH

    stored = await get_refresh_token_session(
        token=token,
        session=session,
    )

    assert stored.user_id == user_id
    assert stored.organization_id == organization_id
    assert stored.jti == payload["jti"]

async def test_refresh_rotates_refresh_token(
    client,
    session,
):
    # 1. Create and persist a test user
    user = User(
        email="testuser@example.com",
        hashed_password="hashed_password_here",
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    # 2. Issue persistent refresh token session
    refresh_token = await issue_refresh_token_session(
        user_id=user.id,
        organization_id=None,
        session=session,
    )
    await session.commit()

    # 3. Call the refresh endpoint
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["access_token"]
    assert data["refresh_token"]
    assert data["refresh_token"] != refresh_token

async def test_old_refresh_token_is_rejected_after_rotation(
    client,
    session,
):
    # 1. Setup user & issue token
    user = User(email="old_token@example.com", hashed_password="hashed_password")
    session.add(user)
    await session.commit()
    await session.refresh(user)

    refresh_token = await issue_refresh_token_session(
        user_id=user.id,
        organization_id=None,
        session=session,
    )
    await session.commit()

    # 2. First refresh succeeds and rotates the token
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    new_refresh_token = response.json()["refresh_token"]

    # 3. Old token MUST be rejected
    old_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert old_response.status_code == 401

    # 4. New token MUST work
    new_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert new_response.status_code == 200


async def test_refresh_preserves_organization_context(
    client,
    session,
):
    # 1. Setup user
    user = User(email="org_token@example.com", hashed_password="hashed_password")
    session.add(user)
    await session.commit()
    await session.refresh(user)

    # 2. Create organization and capture the returned entity/id
    org = await organization_service.create_organization_for_user(
        name="Test Org",
        user=user,
        session=session,
    )
    await session.commit()
    await session.refresh(org)

    organization_id = org.id

    # 3. Issue refresh token with the actual organization_id
    refresh_token = await issue_refresh_token_session(
        user_id=user.id,
        organization_id=organization_id,
        session=session,
    )
    await session.commit()

    # 4. Refresh and verify org_id persists
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200

    data = response.json()
    assert data["organization_id"] == str(organization_id)

    payload = decode_token(data["access_token"])
    assert payload["org_id"] == str(organization_id)