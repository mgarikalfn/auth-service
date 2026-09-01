"""User query helpers used by both public and admin endpoints."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.user import User
from app.schemas.user import UserOut


async def get_user_by_id(user_id: uuid.UUID, session: AsyncSession) -> User | None:
    """Return the ``User`` row for *user_id*, or ``None`` if not found."""
    result = await session.exec(select(User).where(User.id == user_id))
    return result.first()


async def get_all_users(session: AsyncSession) -> list[UserOut]:
    """Return every registered user as safe ``UserOut`` objects.

    Intended for admin-only consumption — no passwords are included.
    """
    result = await session.exec(select(User))
    return [UserOut.model_validate(u) for u in result.all()]
