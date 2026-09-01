"""Async SQLAlchemy engine and per-request session dependency."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings

# The engine is created once at module-import time and shared across the process.
# For SQLite: echo=DEBUG shows SQL in the console.
# For Postgres: swap DATABASE_URL; asyncpg is already in requirements.txt.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

_AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session per request.

    The session is automatically closed (and rolled back on error) when the
    request finishes, regardless of whether it committed.
    """
    async with _AsyncSessionLocal() as session:
        yield session
