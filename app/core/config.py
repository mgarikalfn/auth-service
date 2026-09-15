"""Application configuration via Pydantic BaseSettings.

Values are read from environment variables or a `.env` file in the working
directory.  Defaults are safe for local development; override via environment
for staging / production.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ── Application ───────────────────────────────────────────────────────────
    APP_NAME: str = "JWT Auth Service"
    DEBUG: bool = False

    # ── Database ──────────────────────────────────────────────────────────────
    # Default: SQLite for local dev.  Set to a postgresql+asyncpg:// URL for prod.
    DATABASE_URL: str = "sqlite+aiosqlite:///./dev.db"

    # ── JWT ───────────────────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_in_production"
    ALGORITHM: str = "HS256"

    JWT_ISSUER: str = "auth-service"
    JWT_AUDIENCE: str = "saas-api"
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

        # ── Invitations ───────────────────────────────────────────────────────────
    INVITATION_EXPIRE_HOURS: int = 72
    APP_URL: str = "http://localhost:8000"

    # Email Configuration
    EMAIL_PROVIDER: str = "console"  # Use "resend" in production / .env
    RESEND_API_KEY: str | None = None
    EMAIL_FROM: str = "onboarding@resend.dev"
    EMAIL_FROM_NAME: str = "Auth Service"
    #password
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30
    EMAIL_VERIFICATION_EXPIRE_MINUTES: int = 60
@lru_cache
def get_settings() -> Settings:
    """Return the singleton Settings instance (cached after first call)."""
    return Settings()

    
# Module-level convenience alias so other modules can do `from app.core.config import settings`.
settings: Settings = get_settings()

