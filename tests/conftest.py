"""Shared pytest fixtures for the JWT auth service test suite.

Design decisions
----------------
* A **fresh in-memory SQLite database** is created for every test function via
  ``StaticPool``, which forces aiosqlite to reuse the same connection (and
  therefore the same in-memory DB) across all sessions within a test.
* The ``get_session`` FastAPI dependency is overridden to inject the test
  session, so no real database file is ever created.
* The slowapi rate-limiter storage is cleared before every test so that the
  login rate limit does not bleed between tests.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# Import models so their metadata is registered before create_all.
import app.models.user  # noqa: F401
from app.core.limiter import limiter
from app.db.session import get_session
from app.main import app


# ── Database fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def engine():
    """Create a clean in-memory SQLite engine for a single test."""
    _engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield _engine
    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await _engine.dispose()


@pytest_asyncio.fixture()
async def session(engine) -> AsyncSession:
    """Yield an open ``AsyncSession`` bound to the test engine."""
    _session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with _session_factory() as _session:
        yield _session


# ── HTTP client fixture ───────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def client(session: AsyncSession) -> AsyncClient:
    """Yield an ``AsyncClient`` wired to the FastAPI app with the test DB.

    The ``get_session`` dependency is overridden so all route handlers use the
    same in-memory session as the test itself.
    """

    async def _override_get_session():
        yield session

    app.dependency_overrides[get_session] = _override_get_session

    # Clear rate-limit counters so login tests don't interfere with each other.
    # The internal storage API varies across slowapi/limits versions; we try the
    # most common method and silently skip if unavailable.
    try:
        limiter.reset()
    except Exception:
        pass
    try:
        limiter._storage.reset()
    except Exception:
        pass

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as _client:
        yield _client

    app.dependency_overrides.clear()
