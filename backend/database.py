"""Database connection, session factory and FastAPI session dependency.

Nothing here connects to PostgreSQL at import time. The engine is created
lazily the first time it is needed. The schema is managed by Alembic
migrations, never by Base.metadata.create_all().
"""

import logging
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, MetaData, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import mask_database_url, settings

logger = logging.getLogger("leaktrace.database")

# Predictable constraint names make Alembic migrations easier to write and review.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when database access is needed but DATABASE_URL is not set."""


def require_postgresql_url(url: str) -> None:
    if not url.startswith("postgresql+psycopg://"):
        raise DatabaseNotConfiguredError(
            "DATABASE_URL must use the PostgreSQL Psycopg 3 driver "
            "(postgresql+psycopg://...). Got: " + mask_database_url(url)
        )


def build_engine(url: str) -> Engine:
    """Create a PostgreSQL engine with the configured pool settings."""
    require_postgresql_url(url)
    return create_engine(
        url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_recycle=settings.db_pool_recycle_seconds,
        pool_pre_ping=True,
        # Fail fast rather than outlast the email Worker's 10-second request timeout.
        connect_args={"connect_timeout": 8},
    )


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Return the application engine, creating it on first use."""
    if not settings.database_url:
        raise DatabaseNotConfiguredError(
            "DATABASE_URL is not set. Example format: "
            "postgresql+psycopg://USER:PASSWORD@localhost:5432/leaktrace"
        )
    logger.info("Creating database engine for %s", mask_database_url(settings.database_url))
    return build_engine(settings.database_url)


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a session and always closes it.

    Tests can replace it with app.dependency_overrides[get_db].
    """
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def check_database_connection(engine: Engine | None = None) -> bool:
    """Return True if a simple query succeeds. Never raises or logs credentials."""
    try:
        engine = engine or get_engine()
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning("Database connection check failed: %s", type(exc).__name__)
        return False
