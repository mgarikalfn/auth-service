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

from app.core.security import TOKEN_TYPE_ACCESS, decode_access_token, decode_token
from app.db.session import get_session
from app.models.user import User, UserRole, UserStatus
from app.services.user_service import get_user_by_id

# auto_error=False so we can return a clean 401 instead of FastAPI's default 403
# for a missing Authorization header.
bearer_scheme = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
    session: AsyncSession = Depends(get_session),
) -> User:
    payload = decode_access_token(
        credentials.credentials
    )

    try:
        user_id = uuid.UUID(str(payload.sub))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await session.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active",
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
