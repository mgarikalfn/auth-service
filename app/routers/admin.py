"""Admin-only routes demonstrating RBAC beyond simple authentication."""

from fastapi import APIRouter, Depends
from sqlmodel.ext.asyncio.session import AsyncSession

from app.db.session import get_session
from app.dependencies.auth import require_role
from app.models.user import User, UserRole
from app.schemas.user import UserOut
from app.services import user_service

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get(
    "/users",
    response_model=list[UserOut],
    summary="List all registered users (admin only)",
)
async def list_users(
    session: AsyncSession = Depends(get_session),
    # The dependency authenticates *and* authorises; the user object is unused here.
    _admin: User = Depends(require_role(UserRole.admin)),
) -> list[UserOut]:
    """Return every registered user.

    - **401** if no valid access token is provided.
    - **403** if the authenticated user does not have the `admin` role.
    """
    return await user_service.get_all_users(session)
