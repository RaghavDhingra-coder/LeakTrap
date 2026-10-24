"""Public ingest deployment: app mode, startup validation, readiness and the
Docker build context. No database needed."""

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from backend.config import configuration_problems, get_settings
from backend.main import app
from backend.routes import health

ROOT = Path(__file__).resolve().parent.parent
GOOD = {"DATABASE_URL": "postgresql+psycopg://u:p@db.invalid/leaktrace", "LEAKTRACE_INGEST_SECRET": "s" * 40,
        "LEAKTRACE_ALIAS_DOMAIN": "leaktrap.xyz", "LEAKTRACE_ENV": "production", "LEAKTRACE_APP_MODE": "ingest"}
STARTS = "import backend.main; print('started')"


def run_app(env: dict, code: str = STARTS) -> subprocess.CompletedProcess:
    # A fresh interpreter, so settings are read from exactly this environment
    # (the real environment and .env are excluded: dotenv never overrides).
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("LEAKTRACE_", "DATABASE_URL", "DB_"))}
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**clean, **env, "PYTHONDONTWRITEBYTECODE": "1"},
                          capture_output=True, text=True, timeout=60)


def test_ingest_mode_serves_only_health_and_ingestion() -> None:
    probe = ("from fastapi.testclient import TestClient; from backend.main import app; "
             "c = TestClient(app, client=('127.0.0.1', 1)); "
             "paths = ['/', '/health', '/dashboard', '/auth/me', '/signups', '/extension/whoami', '/consent-receipts', "
             "'/docs', '/redoc', '/openapi.json']; "
             "print([c.get(p).status_code for p in paths], c.post('/ingest/email', json={}).status_code, "
             "c.post('/auth/login', json={}).status_code, c.post('/matcher/check', json={}).status_code)")
    result = run_app(GOOD, probe)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "[200, 200, 404, 404, 404, 404, 404, 404, 404, 404] 401 404 404"
    # Account, session and dashboard code is not even loaded.
    loaded = run_app(GOOD, "import sys, backend.main; print(sorted(m for m in sys.modules if m.startswith('backend.routes')))")
    assert loaded.stdout.strip().splitlines()[-1] == "['backend.routes', 'backend.routes.common', 'backend.routes.health', 'backend.routes.ingest']"
    assert "backend.services.auth" not in run_app(GOOD, "import sys, backend.main; print(list(sys.modules))").stdout
    assert "LEAKTRACE_SECRET_KEY" not in result.stderr


def test_full_mode_still_serves_everything() -> None:
    probe = ("from fastapi.testclient import TestClient; from backend.main import app; c = TestClient(app); "
             "print(sorted(c.get('/openapi.json').json()['paths'])[:3], len(c.get('/openapi.json').json()['paths']))")
    result = run_app({**GOOD, "LEAKTRACE_APP_MODE": "full", "LEAKTRACE_SECRET_KEY": "k" * 40}, probe)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.split()[-1]) >= 30


@pytest.mark.parametrize(("change", "problem"), [
    ({"LEAKTRACE_INGEST_SECRET": "short"}, "LEAKTRACE_INGEST_SECRET"),
    ({"LEAKTRACE_INGEST_SECRET": ""}, "LEAKTRACE_INGEST_SECRET"),
    ({"DATABASE_URL": ""}, "DATABASE_URL is not set"),
    ({"DATABASE_URL": "postgres://u:p@db.invalid/x"}, "postgresql+psycopg"),
    ({"LEAKTRACE_ALIAS_DOMAIN": ""}, "LEAKTRACE_ALIAS_DOMAIN"),
    ({"LEAKTRACE_APP_MODE": "public"}, "LEAKTRACE_APP_MODE"),
])
def test_production_refuses_to_start_with_unusable_configuration(change, problem) -> None:
    result = run_app({**GOOD, **change})
    assert result.returncode != 0
    assert problem in result.stderr
    for value in ("s" * 40, "u:p@"):  # secrets are never echoed
        assert value not in result.stderr


def test_development_only_warns() -> None:
    result = run_app({**GOOD, "LEAKTRACE_ENV": "development", "LEAKTRACE_INGEST_SECRET": ""})
    assert result.returncode == 0 and "started" in result.stdout, result.stderr
    assert "Configuration: LEAKTRACE_INGEST_SECRET" in result.stderr


def test_full_mode_outside_development_needs_secret_key(monkeypatch) -> None:
    for key, value in {**GOOD, "LEAKTRACE_APP_MODE": "full"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("LEAKTRACE_SECRET_KEY", raising=False)
    assert configuration_problems(get_settings()) == ["LEAKTRACE_SECRET_KEY is not set"]
    settings = replace(get_settings(), secret_key="k" * 40)
    assert configuration_problems(settings) == []


class FakeEngine:
    def __init__(self, fail: bool):
        self.fail = fail

    def connect(self):
        if self.fail:
            raise OperationalError("SELECT 1", {}, Exception("password=hunter2 host=db.invalid"))
        engine = self

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, statement):
                engine.executed = str(statement)

        return Connection()


@pytest.mark.parametrize("fail", [False, True])
def test_readiness_checks_the_database_without_revealing_details(monkeypatch, caplog, fail) -> None:
    engine = FakeEngine(fail)
    monkeypatch.setattr(health, "get_engine", lambda: engine)
    response = TestClient(app).get("/health/ready")
    if fail:
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "database": "unavailable"}
        assert "hunter2" not in caplog.text and "OperationalError" in caplog.text
    else:
        assert response.json() == {"status": "ok", "database": "ok"} and engine.executed == "SELECT 1"


def test_liveness_never_touches_the_database(monkeypatch) -> None:
    monkeypatch.setattr(health, "get_engine", lambda: pytest.fail("database used"))
    assert TestClient(app).get("/health").json() == {"status": "ok", "message": "LeakTrace running"}


def test_docker_build_context_excludes_secrets_and_runs_ingest_only() -> None:
    ignore = [l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines() if l.strip() and not l.startswith("#")]
    assert ignore[0] == "*" and "**/.env" in ignore and "**/.env.*" in ignore
    allowed = [line for line in ignore if line.startswith("!")]
    assert allowed == ["!backend/", "!requirements-runtime.txt"]
    dockerfile = (ROOT / "Dockerfile").read_text()
    for line in ("LEAKTRACE_ENV=production", "LEAKTRACE_APP_MODE=ingest", "USER leaktrace", "requirements-runtime.txt"):
        assert line in dockerfile
    assert "alembic upgrade" not in dockerfile and "--proxy-headers" not in dockerfile.split("CMD")[-1]
    assert not list((ROOT / "backend").rglob(".env*"))


def test_render_blueprint_keeps_secrets_out_of_the_file() -> None:
    blueprint = (ROOT / "render.yaml").read_text()
    for key in ("DATABASE_URL", "LEAKTRACE_INGEST_SECRET"):
        block = blueprint.split(f"key: {key}", 1)[1].split("- key:", 1)[0]
        assert "sync: false" in block and "value:" not in block
    assert "healthCheckPath: /health" in blueprint and "autoDeploy: false" in blueprint
    assert "@" not in blueprint and "neon.tech" not in blueprint  # no connection string or credentials


def test_runtime_requirements_are_pinned_and_included_in_dev_requirements() -> None:
    runtime = [l for l in (ROOT / "requirements-runtime.txt").read_text().splitlines() if l and not l.startswith("#")]
    assert runtime and all("==" in l for l in runtime)
    assert "-r requirements-runtime.txt" in (ROOT / "requirements.txt").read_text()
    assert not any(l.startswith(("pytest", "httpx")) for l in runtime)
