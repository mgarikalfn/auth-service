import re

from fastapi import HTTPException, status


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128


def validate_password(password: str) -> None:
    if not (
        PASSWORD_MIN_LENGTH
        <= len(password)
        <= PASSWORD_MAX_LENGTH
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must contain between "
                "8 and 128 characters"
            ),
        )

    if password != password.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must not begin or end "
                "with whitespace"
            ),
        )

    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must contain at least "
                "one uppercase letter"
            ),
        )

    if not re.search(r"[a-z]", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must contain at least "
                "one lowercase letter"
            ),
        )

    if not re.search(r"\d", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must contain at least "
                "one number"
            ),
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Password must contain at least "
                "one special character"
            ),
        )