"""Reusable FastAPI dependency callables for authentication and authorisation.

Usage in a route:
    # Any authenticated user:
    user: User = Depends(get_current_user)

    # Admin-only route:
    _: User = Depends(require_role(UserRole.admin))
"""

import uuid
from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import TOKEN_TYPE_ACCESS, decode_token
from app.db.session import get_session
from app.models.user import User, UserRole
from app.services.user_service import get_user_by_id

# auto_error=False so we can return a clean 401 instead of FastAPI's default 403
# for a missing Authorization header.
_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Extract the Bearer token, verify it, and return the owning ``User``.

    Raises:
        401 Unauthorized: if the header is absent, the token is invalid/expired,
            or the token is not an *access* token.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated — provide a Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)

    # Reject refresh tokens used where access tokens are expected.
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — an access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject: str | None = payload.get("sub")
    try:
        user_id = uuid.UUID(subject)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token subject",
        )

    user = await get_user_by_id(user_id, session)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The user belonging to this token no longer exists",
        )
    return user


def require_role(role: UserRole) -> Callable:
    """Return a FastAPI dependency that enforces *role* on the current user.

    The returned dependency first calls ``get_current_user`` (authentication),
    then checks the role (authorisation) — giving separate 401 vs 403 responses.

    Example::

        @router.get("/admin/users")
        async def list_users(_: User = Depends(require_role(UserRole.admin))):
            ...
    """

    async def _role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied — '{role.value}' role required",
            )
        return current_user

    return _role_checker
