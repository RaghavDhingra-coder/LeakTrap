"""Shared PostgreSQL fixtures for integration tests.

The engine fixture skips unless TEST_DATABASE_URL points to a disposable
database whose name contains "test". Setup drops and recreates the LeakTrace
tables there via Alembic, so never point it at development or production data.
"""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from backend.database import build_engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


@pytest.fixture(autouse=True)
def mock_public_domain_evidence(monkeypatch):
    """Ingestion tests never contact public DNS, websites, or Gemini."""
    from backend.services import domain_evidence
    from backend.services import gemini

    def collect(domain: str):
        return ({"domain": domain, "checked_at": "2026-10-27T00:00:00+00:00",
                 "dns": {"records": [{"type": "A", "data": "93.184.216.34"}]},
                 "website": {"title": "", "organization_claims": []}, "source_urls": []}, 86400)

    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)
    monkeypatch.setattr(gemini, "enrich_cached_evidence", lambda _session, _evidence: {"status": "not_configured"})


def assert_safe_test_database(url: str) -> None:
    database_name = make_url(url).database or ""
    if "test" not in database_name:
        pytest.exit(f"Refusing to run: test database name {database_name!r} must contain 'test'.")
    if url == os.getenv("DATABASE_URL"):
        pytest.exit("Refusing to run: TEST_DATABASE_URL must differ from DATABASE_URL.")


def alembic_config(connection) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    assert_safe_test_database(TEST_DATABASE_URL)

    engine = build_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        config = alembic_config(connection)
        command.downgrade(config, "base")
        command.upgrade(config, "head")
    yield engine
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back after each test."""
    with engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        yield session
        session.close()
        transaction.rollback()
