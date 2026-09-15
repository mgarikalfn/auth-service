import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core.config import settings
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    create_organization_access_token,
    decode_token,
)
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core.config import settings
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    create_organization_access_token,
    decode_token,
)

def test_organization_access_token_contains_org_id():
    user_id = str(uuid.uuid4())
    organization_id = str(uuid.uuid4())

    token = create_organization_access_token(
        subject=user_id,
        organization_id=organization_id,
    )

    payload = decode_token(token)

    assert payload["sub"] == user_id
    assert payload["org_id"] == organization_id
    assert payload["type"] == TOKEN_TYPE_ACCESS
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["aud"] == settings.JWT_AUDIENCE


def test_token_with_wrong_audience_is_rejected():
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": TOKEN_TYPE_ACCESS,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "jti": uuid.uuid4().hex,
            "iss": settings.JWT_ISSUER,
            "aud": "wrong-service",
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    with pytest.raises(HTTPException) as exc_info:
        decode_token(token)

    assert exc_info.value.status_code == 401

