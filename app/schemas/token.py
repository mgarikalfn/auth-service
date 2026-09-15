import uuid

from pydantic import BaseModel


class AccessTokenPayload(BaseModel):
    sub: uuid.UUID
    type: str
    org_id: uuid.UUID | None = None
    jti: str
    iat: int
    exp: int
    iss: str
    aud: str