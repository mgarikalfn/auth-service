"""User profile routes."""

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.user import UserOut

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user profile",
)
async def get_me(current_user: User = Depends(get_current_user)) -> UserOut:
    """Return the profile of the currently authenticated user.

    Requires a valid **access** token in the `Authorization: Bearer` header.
    """
    return UserOut.model_validate(current_user)
