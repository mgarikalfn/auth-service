from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.models.user import User


def _now() -> datetime:
    return datetime.now(timezone.utc)


def is_user_locked(user: User) -> bool:
    if user.locked_until is None:
        return False

    locked_until = user.locked_until

    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(
            tzinfo=timezone.utc
        )

    return locked_until > _now()


def record_failed_login(user: User) -> None:
    user.failed_login_attempts += 1

    if (
        user.failed_login_attempts
        >= settings.LOGIN_MAX_FAILED_ATTEMPTS
    ):
        user.locked_until = (
            _now()
            + timedelta(
                minutes=settings.LOGIN_LOCKOUT_MINUTES
            )
        )


def record_successful_login(user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None