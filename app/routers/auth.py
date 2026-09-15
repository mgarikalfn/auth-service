"""Authentication routes: signup, login (rate-limited), and token refresh."""

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.limiter import limiter
from app.core.security import decode_access_token
from app.db.session import get_session
from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.auth import LoginRequest, OrganizationTokenOut, PasswordResetConfirm, PasswordResetConfirmOut, PasswordResetRequest, PasswordResetRequestOut, RefreshRequest, RefreshTokenOut, RefreshTokenRequest, SignupRequest, TokenResponse
from app.schemas.token import VerifyTokenOut
from app.schemas.user import UserOut
from app.services import auth_service, password_reset_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    response_model=UserOut,
    status_code=201,
    summary="Register a new account",
)
async def signup(
    data: SignupRequest,
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    """Create a new user account.

    - Email must be unique (409 if already registered).
    - Password must be ≥ 8 characters (422 on validation failure).
    - The returned object never contains the hashed password.
    """
    return await auth_service.signup(data, session)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Obtain access + refresh tokens",
)
@limiter.limit("5/minute")
async def login(
    request: Request,
    data: LoginRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Authenticate with email + password and receive a token pair.

    - **Access token**: short-lived (~15 min), use as `Authorization: Bearer <token>`.
    - **Refresh token**: long-lived (~7 days), use only with `POST /auth/refresh`.
    - Rate limited to **5 requests / minute per IP** to block brute-force attacks.
    """
    return await auth_service.login(data, session)


@router.post(
    "/refresh",
    response_model=RefreshTokenOut,
)
async def refresh_token(
    data: RefreshTokenRequest,
    session: AsyncSession = Depends(get_session),
) -> RefreshTokenOut:
    access_token, refresh_token, organization_id = (
        await auth_service.refresh_access_token(
            refresh_token=data.refresh_token,
            session=session,
        )
    )

    await session.commit()

    return RefreshTokenOut(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        organization_id=organization_id,
    )
@router.post(
    "/organizations/{organization_id}/token",
    response_model=OrganizationTokenOut,
)
async def create_organization_token(
    organization_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrganizationTokenOut:
    """Issue an access token scoped to an organization."""

    access_token = await auth_service.create_organization_access_token_for_user(
        user=current_user,
        organization_id=organization_id,
        session=session,
    )

    return OrganizationTokenOut(
        access_token=access_token,
        token_type="bearer",
        organization_id=organization_id,
    )

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh an access token",
)
async def refresh(
    data: RefreshRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    # Pass keyword arguments explicitly
    access_token, new_refresh_token, _ = await auth_service.refresh_access_token(
        refresh_token=data.refresh_token,
        session=session,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )

@router.get(
    "/verify",
    response_model=VerifyTokenOut,
)
async def verify_access_token(
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(
        HTTPBearer()
    ),
) -> VerifyTokenOut:
    payload = decode_access_token(credentials.credentials)

    return VerifyTokenOut(
        valid=True,
        user_id=current_user.id,
        organization_id=payload.org_id,
    )

@router.post(
    "/password-reset/request",
    response_model=PasswordResetRequestOut,
)
async def request_password_reset(
    data: PasswordResetRequest,
    session: AsyncSession = Depends(get_session),
) -> PasswordResetRequestOut:
    await password_reset_service.request_password_reset(
        email=data.email,
        session=session,
    )

    await session.commit()

    return PasswordResetRequestOut(
        message=(
            "If an account exists for this email, "
            "a password reset link has been sent."
        )
    )

@router.post(
    "/password-reset/confirm",
    response_model=PasswordResetConfirmOut,
)
async def confirm_password_reset(
    data: PasswordResetConfirm,
    session: AsyncSession = Depends(get_session),
) -> PasswordResetConfirmOut:
    await password_reset_service.reset_password(
        raw_token=data.token,
        new_password=data.new_password,
        session=session,
    )

    await session.commit()

    return PasswordResetConfirmOut(
        message="Password has been reset successfully.",
    )

