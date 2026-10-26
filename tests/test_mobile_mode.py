"""Mobile deployment mode: only the health checks and /mobile/v1 are served,
nothing else is loaded, and unsafe configurations refuse to start.

Each check runs backend.main in a fresh interpreter with exactly the given
environment (see tests.test_deployment.run_app). The last test runs the real
mobile-mode app against the isolated PostgreSQL test database.
"""

import json
import os

import pytest

from tests.test_deployment import run_app

MOBILE = {"DATABASE_URL": "postgresql+psycopg://u:p@db.invalid/leaktrace", "LEAKTRACE_SECRET_KEY": "k" * 40,
          "LEAKTRACE_ALIAS_DOMAIN": "leaktrap.xyz", "LEAKTRACE_ENV": "production", "LEAKTRACE_APP_MODE": "mobile",
          "LEAKTRACE_DASHBOARD_ENABLED": "false"}
STARTS = "import backend.main; print('started')"

SERVED_PATHS = {"/", "/health", "/health/ready"}
EXCLUDED = [
    ("GET", "/dashboard"), ("GET", "/dashboard/api/signups"), ("GET", "/dashboard/api/timeline"),
    ("GET", "/dashboard/api/sms/investigations"), ("POST", "/dashboard/api/sms/analyze"), ("GET", "/auth/me"),
    ("POST", "/auth/login"), ("POST", "/auth/register"), ("POST", "/auth/logout"), ("DELETE", "/account"),
    ("GET", "/signups"), ("POST", "/signups"), ("GET", "/extension/whoami"), ("GET", "/extension/sessions"),
    ("POST", "/extension/pairings"), ("POST", "/extension/pairings/approve"), ("POST", "/extension/pairings/1/token"),
    ("POST", "/ingest/email"), ("GET", "/consent-receipts"), ("POST", "/matcher/check"), ("POST", "/autofill/lookup"),
    ("GET", "/mobile/devices"), ("DELETE", "/mobile/devices/1"), ("POST", "/mobile/pairings/preview"),
    ("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"), ("GET", "/mobile/v1/does-not-exist"),
]
NEEDS_TOKEN = [
    ("GET", "/mobile/v1/me"), ("POST", "/mobile/v1/logout"), ("GET", "/mobile/v1/websites"), ("GET", "/mobile/v1/websites/1"),
    ("GET", "/mobile/v1/emails"), ("GET", "/mobile/v1/emails/1"), ("GET", "/mobile/v1/timeline"),
    ("POST", "/mobile/v1/sms/analyze"), ("GET", "/mobile/v1/sms/investigations"), ("POST", "/mobile/v1/sms/investigations"),
    ("GET", "/mobile/v1/sms/investigations/1"), ("POST", "/mobile/v1/sms/investigations/1/actions"),
    ("DELETE", "/mobile/v1/sms/investigations/1"),
]


# Every served path, including those of included routers (wrapped by FastAPI).
ROUTE_PATHS = """
def route_paths(app):
    paths = set()
    for route in app.routes:
        router = getattr(route, "original_router", None)
        paths.update(r.path for r in router.routes) if router is not None else paths.add(route.path)
    return sorted(paths)
"""


def probe(code: str, env: dict | None = None) -> dict:
    result = run_app(env or MOBILE, "import json\n" + code)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_mobile_mode_serves_only_health_and_the_mobile_api() -> None:
    out = probe(f"""
from fastapi.testclient import TestClient
from backend.main import app
c = TestClient(app, client=("127.0.0.1", 1))
{ROUTE_PATHS}
paths = route_paths(app)
excluded = {{m + " " + p: c.request(m, p, json={{}}).status_code for m, p in {EXCLUDED!r}}}
needs_token = {{m + " " + p: c.request(m, p, json={{}}).status_code for m, p in {NEEDS_TOKEN!r}}}
missing = c.get("/mobile/v1/does-not-exist")
print(json.dumps({{"paths": paths, "excluded": excluded, "needs_token": needs_token,
    "root": c.get("/").status_code, "health": c.get("/health").status_code, "ready": c.get("/health/ready").status_code,
    "pairing_validation": c.post("/mobile/v1/pairings", json={{}}).status_code,
    "missing_headers": [missing.headers.get("cache-control"), missing.headers.get("x-content-type-options")]}}))
""")
    assert all(p in SERVED_PATHS or p.startswith("/mobile/v1/") for p in out["paths"]), out["paths"]
    assert SERVED_PATHS <= set(out["paths"]) and "/mobile/v1/pairings" in out["paths"]
    assert {k: v for k, v in out["excluded"].items() if v != 404} == {}
    assert {k: v for k, v in out["needs_token"].items() if v != 401} == {}
    assert (out["root"], out["health"], out["ready"]) == (200, 200, 503)  # ready: the fake database is unreachable
    assert out["pairing_validation"] == 422
    assert out["missing_headers"] == ["no-store", "nosniff"]


def test_mobile_mode_loads_no_other_router() -> None:
    out = probe("import sys, backend.main; print(json.dumps(sorted(m for m in sys.modules if m.startswith('backend.'))))")
    routes = [m for m in out if m.startswith("backend.routes")]
    assert routes == ["backend.routes", "backend.routes.common", "backend.routes.dashboard_views",
                      "backend.routes.health", "backend.routes.mobile", "backend.routes.sms_shared"]
    for module in ("backend.routes.auth", "backend.routes.dashboard", "backend.routes.sms", "backend.routes.extension",
                   "backend.routes.ingest", "backend.routes.mobile_devices", "backend.routes.signups"):
        assert module not in out


def test_mobile_mode_accepts_standard_postgresql_url_without_enabling_dashboard() -> None:
    env = {**MOBILE, "DATABASE_URL": "postgresql://u:p@db.invalid/leaktrace"}
    out = probe(f"""
import json, sys
from backend.config import settings
from backend.main import app
{ROUTE_PATHS}
paths = set(route_paths(app))
print(json.dumps({{
    "psycopg_url": settings.database_url.startswith("postgresql+psycopg://"),
    "dashboard_routes": sorted(p for p in paths if p.startswith("/dashboard")),
    "auth_loaded": "backend.routes.auth" in sys.modules,
    "mobile_route": "/mobile/v1/me" in paths,
}}))
""", env)
    assert out == {
        "psycopg_url": True,
        "dashboard_routes": [],
        "auth_loaded": False,
        "mobile_route": True,
    }


def test_mobile_mode_rejects_non_postgresql_database_url_without_echoing_credentials() -> None:
    secret = "mysql-user:mysql-password@db.invalid"
    result = run_app({**MOBILE, "DATABASE_URL": f"mysql://{secret}/leaktrace"})
    assert result.returncode != 0
    assert "DATABASE_URL must start with postgresql+psycopg://" in result.stderr
    assert secret not in result.stderr


def test_full_mode_still_serves_the_dashboard_device_routes() -> None:
    env = {**MOBILE, "LEAKTRACE_APP_MODE": "full"}
    out = probe("""
from backend.main import app
""" + ROUTE_PATHS + """
print(json.dumps(route_paths(app)))
""", env)
    for path in ("/mobile/devices", "/mobile/devices/{device_id}", "/mobile/pairings/preview", "/mobile/v1/me",
                 "/dashboard/api/signups", "/extension/pairings", "/ingest/email", "/auth/login"):
        assert path in out, path


@pytest.mark.parametrize(("change", "problem"), [
    ({"LEAKTRACE_INGEST_SECRET": "s" * 40}, "LEAKTRACE_INGEST_SECRET must not be set in mobile mode"),
    ({"LEAKTRACE_DASHBOARD_ENABLED": "true"}, "LEAKTRACE_DASHBOARD_ENABLED must be false in mobile mode"),
    ({"LEAKTRACE_SECRET_KEY": ""}, "LEAKTRACE_SECRET_KEY must be at least 32 characters"),
    ({"LEAKTRACE_SECRET_KEY": "k" * 31}, "LEAKTRACE_SECRET_KEY must be at least 32 characters"),
    ({"DATABASE_URL": ""}, "DATABASE_URL is not set"),
    ({"LEAKTRACE_ALIAS_DOMAIN": ""}, "LEAKTRACE_ALIAS_DOMAIN is not set"),
    ({"LEAKTRACE_TRUSTED_PROXY_HOPS": "4"}, "LEAKTRACE_TRUSTED_PROXY_HOPS must be an integer from 0 to 3"),
    ({"LEAKTRACE_TRUSTED_PROXY_HOPS": "-1"}, "LEAKTRACE_TRUSTED_PROXY_HOPS"),
    ({"LEAKTRACE_TRUSTED_PROXY_HOPS": "one"}, "LEAKTRACE_TRUSTED_PROXY_HOPS"),
    ({"LEAKTRACE_TRUSTED_PROXY_HOPS": "1.5"}, "LEAKTRACE_TRUSTED_PROXY_HOPS"),
    ({"LEAKTRACE_PROXY_DIAGNOSTICS": "true"}, "LEAKTRACE_PROXY_DIAGNOSTICS must not be enabled in production"),
    # Mobile mode is refused even in development.
    ({"LEAKTRACE_ENV": "development", "LEAKTRACE_INGEST_SECRET": "s" * 40}, "LEAKTRACE_INGEST_SECRET"),
])
def test_unsafe_mobile_configurations_refuse_to_start(change, problem) -> None:
    result = run_app({**MOBILE, **change})
    assert result.returncode != 0
    assert problem in result.stderr and "started" not in result.stdout
    for secret in ("s" * 40, "k" * 31):
        assert secret not in result.stderr  # problems name variables, never values


@pytest.mark.parametrize("hops", ["0", "1", "2", "3", ""])
def test_valid_mobile_configurations_start(hops) -> None:
    result = run_app({**MOBILE, "LEAKTRACE_TRUSTED_PROXY_HOPS": hops})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("started")


def test_proxy_diagnostics_only_outside_production() -> None:
    staging = {**MOBILE, "LEAKTRACE_ENV": "staging", "LEAKTRACE_PROXY_DIAGNOSTICS": "true"}
    out = probe("""
import logging
from fastapi.testclient import TestClient
from backend.main import app
records = []
handler = logging.Handler(); handler.emit = lambda r: records.append(r.getMessage())
logging.getLogger("leaktrace.proxy").addHandler(handler)
c = TestClient(app, client=("10.0.0.9", 1))
c.get("/health", headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.5"})
c.get("/mobile/v1/me", headers={"X-LeakTrace-Proxy-Diagnostic": "1", "X-Forwarded-For": "198.51.100.2"})
marked = c.get("/health", headers={"X-LeakTrace-Proxy-Diagnostic": "1", "X-Forwarded-For": "198.51.100.3, 203.0.113.5"})
print(json.dumps({"records": records, "status": marked.status_code, "body": marked.json()}))
""", staging)
    assert out["status"] == 200 and out["body"] == {"status": "ok", "message": "LeakTrace running"}
    [line] = out["records"]  # only the marked /health request is logged
    assert "198.51.100.3, 203.0.113.5" in line and "1: '203.0.113.5'" in line
    # Off by default: nothing is logged.
    off = probe("""
import logging
from fastapi.testclient import TestClient
from backend.main import app
records = []
handler = logging.Handler(); handler.emit = lambda r: records.append(r.getMessage())
logging.getLogger("leaktrace.proxy").addHandler(handler)
TestClient(app).get("/health", headers={"X-LeakTrace-Proxy-Diagnostic": "1", "X-Forwarded-For": "198.51.100.3"})
print(json.dumps(records))
""")
    assert off == []


# ---------- the real mobile-mode app against the test database ----------

END_TO_END = r"""
import hashlib, json, os, secrets
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.database import build_engine, get_db
from backend.main import app
from backend.models import Signup, User
from backend.services import auth as auth_service, pairing

engine = build_engine(os.environ["DATABASE_URL"])
connection = engine.connect()
transaction = connection.begin()
db = Session(bind=connection, join_transaction_mode="create_savepoint")
app.dependency_overrides[get_db] = lambda: db
try:
    alice = User(email="alice@example.com", password_hash="x", email_verified_at=auth_service.now())
    bob = User(email="bob@example.com", password_hash="x", email_verified_at=auth_service.now())
    db.add_all([alice, bob]); db.flush()
    shop = Signup(user_id=alice.id, site_name="Example Shop", site_domain="shop.example.com")
    forum = Signup(user_id=bob.id, site_name="Bob Forum")
    db.add_all([shop, forum]); db.commit()
    web = auth_service.create_session(db, alice.id, "web").token
    ext = auth_service.create_session(db, alice.id, "extension", "signups:create").token
    narrow = auth_service.create_session(db, alice.id, "mobile", "account:read").token
    db.commit()
    c = TestClient(app)
    out = {}

    secret = secrets.token_urlsafe(32)
    started = c.post("/mobile/v1/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
                                                   "device_label": "Pixel"}).json()
    out["pending"] = c.post(f"/mobile/v1/pairings/{started['pairing_id']}/token", json={"secret": secret}).status_code
    pairing.approve(db, alice.id, started["code"], "mobile")  # what the local dashboard does
    issued = c.post(f"/mobile/v1/pairings/{started['pairing_id']}/token", json={"secret": secret})
    out["issued"] = [issued.status_code, issued.json()["scopes"], issued.headers.get("cache-control")]
    auth = {"Authorization": "Bearer " + issued.json()["token"]}

    me = c.get("/mobile/v1/me", headers=auth)
    out["me"] = [me.status_code, me.json()["email"], me.headers.get("cache-control"), me.headers.get("x-content-type-options")]
    out["websites"] = [s["site_name"] for s in c.get("/mobile/v1/websites", headers=auth).json()["items"]]
    out["own_site"] = c.get(f"/mobile/v1/websites/{shop.id}", headers=auth).status_code
    out["other_site"] = c.get(f"/mobile/v1/websites/{forum.id}", headers=auth).json()
    out["missing_site"] = c.get("/mobile/v1/websites/987654321", headers=auth).json()
    out["analyze"] = c.post("/mobile/v1/sms/analyze", json={"text": "Your Example Shop order shipped"}, headers=auth).status_code
    out["narrow_scope"] = c.get("/mobile/v1/websites", headers={"Authorization": "Bearer " + narrow}).status_code
    out["web_bearer"] = c.get("/mobile/v1/me", headers={"Authorization": "Bearer " + web}).status_code
    out["extension_bearer"] = c.get("/mobile/v1/me", headers={"Authorization": "Bearer " + ext}).status_code
    cookie_client = TestClient(app); cookie_client.cookies.set("lt_session", web)
    out["cookie"] = cookie_client.get("/mobile/v1/me").status_code
    out["logout"] = c.post("/mobile/v1/logout", headers=auth).status_code
    out["after_logout"] = c.get("/mobile/v1/me", headers=auth).status_code
    print(json.dumps(out))
finally:
    db.close()
    transaction.rollback()
    connection.close()
"""


@pytest.mark.integration
def test_real_mobile_mode_app_end_to_end(engine) -> None:
    out = probe(END_TO_END, {**MOBILE, "DATABASE_URL": os.environ["TEST_DATABASE_URL"]})
    assert out["pending"] == 202
    assert out["issued"] == [200, ["account:read", "call:analyze", "call:write", "email:read", "sms:analyze", "sms:write", "timeline:read",
                                   "websites:read"], "no-store"]
    assert out["me"] == [200, "alice@example.com", "no-store", "nosniff"]
    assert out["websites"] == ["Example Shop"] and out["own_site"] == 200
    assert out["other_site"] == out["missing_site"] == {"detail": "Not found"}
    assert out["analyze"] == 200 and out["narrow_scope"] == 403
    assert (out["web_bearer"], out["extension_bearer"], out["cookie"]) == (401, 401, 401)
    assert (out["logout"], out["after_logout"]) == (204, 401)
