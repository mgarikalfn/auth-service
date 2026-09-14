"""Application factory and entry point.

Run locally with::

    uvicorn app.main:app --reload

The OpenAPI docs are available at http://localhost:8000/docs (Swagger UI)
and http://localhost:8000/redoc (ReDoc) — never disabled.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter
from app.db.init_db import create_db_and_tables
from app.routers import auth, users, admin,organizations


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Run startup and shutdown logic around the application's lifetime."""
    # Startup: create tables if they don't exist yet.
    await create_db_and_tables()
    yield
    # Shutdown: nothing to clean up for SQLite; a real app might drain a pool.


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Production-style JWT authentication microservice with RBAC, "
        "refresh tokens, and rate limiting."
    ),
    version="1.0.0",
    lifespan=lifespan,
    # OpenAPI docs are intentionally kept enabled (never set openapi_url=None).
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach rate limiter and register its exception handler.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(organizations.router)

# ── Misc endpoints ────────────────────────────────────────────────────────────


@app.get("/health", tags=["Health"], summary="Service health check")
async def health_check() -> dict[str, str]:
    """Liveness probe — returns 200 OK when the service is up."""
    return {"status": "ok", "service": settings.APP_NAME}
