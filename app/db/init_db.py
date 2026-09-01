"""Database initialisation — called once at application startup."""

from sqlmodel import SQLModel

from app.db.session import engine

# Import all models so their metadata is registered before create_all runs.
import app.models.user  # noqa: F401


async def create_db_and_tables() -> None:
    """Create all database tables that don't already exist.

    Safe to call on every startup — SQLModel uses ``CREATE TABLE IF NOT EXISTS``
    semantics so existing data is never touched.
    """
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
