"""Dashboard page, local-only guard and validation. No database needed."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from backend.config import get_settings
from backend.database import get_db
from backend.main import app
from tests.auth_support import FAKE_HEADERS, fake_auth
from backend.routes.dashboard import DashboardConfig, get_dashboard_config

LOCAL = ("127.0.0.1", 50000)
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "backend/dashboard"
API_PATHS = ["/dashboard/api/overview", "/dashboard/api/signups", "/dashboard/api/emails",
             "/dashboard/api/emails/1", "/dashboard/api/inbox", "/dashboard/api/inbox/updates",
             "/dashboard/api/inbox/1"]


class BrokenSession:
    def _fail(self, *args, **kwargs):
        raise OperationalError("SELECT", {}, Exception("postgresql://user:pw@host/db refused"))

    get = scalar = scalars = execute = _fail


@pytest.fixture(autouse=True)
def overrides():
    app.dependency_overrides[get_db] = lambda: None
    fake_auth(app)
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def local():
    return TestClient(app, client=LOCAL, headers=FAKE_HEADERS)


def test_page_renders_with_notice_and_security_headers(local) -> None:
    response = local.get("/dashboard")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Local development only." in response.text
    assert 'id="login-form"' in response.text and 'id="register-form"' in response.text  # sign-in view
    assert "not proof" in response.text
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(("name", "kind"), [("app.js", "text/javascript"), ("styles.css", "text/css")])
def test_static_assets_served(local, name, kind) -> None:
    response = local.get(f"/dashboard/static/{name}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(kind)


@pytest.mark.parametrize("name", ["index.html", "../config.py", "..%2Fconfig.py", "missing.js"])
def test_only_whitelisted_static_files(local, name) -> None:
    assert local.get(f"/dashboard/static/{name}").status_code == 404


@pytest.mark.parametrize("host", ["203.0.113.7", "10.0.0.5", "testclient"])
@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/static/app.js", *API_PATHS])
def test_non_local_clients_are_refused(host, path) -> None:
    response = TestClient(app, client=(host, 50000)).get(path)
    assert response.status_code == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_loopback_clients_allowed(host) -> None:
    assert TestClient(app, client=(host, 50000)).get("/dashboard").status_code == 200


@pytest.mark.parametrize("path", ["/dashboard", *API_PATHS])
def test_disabled_dashboard_is_404(local, path) -> None:
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=False)
    assert local.get(path).status_code == 404


def test_dashboard_enabled_by_default_only_in_development(monkeypatch) -> None:
    monkeypatch.delenv("LEAKTRACE_DASHBOARD_ENABLED", raising=False)
    monkeypatch.setenv("LEAKTRACE_ENV", "development")
    assert get_settings().dashboard_enabled is True
    monkeypatch.setenv("LEAKTRACE_ENV", "production")
    assert get_settings().dashboard_enabled is False
    monkeypatch.setenv("LEAKTRACE_DASHBOARD_ENABLED", "false")
    monkeypatch.setenv("LEAKTRACE_ENV", "development")
    assert get_settings().dashboard_enabled is False


@pytest.mark.parametrize(
    "query",
    ["/dashboard/api/signups?limit=0", "/dashboard/api/signups?limit=101",
     "/dashboard/api/signups?offset=-1", "/dashboard/api/emails?limit=abc",
     "/dashboard/api/emails?status=confirmed_leak",
     "/dashboard/api/emails/0", "/dashboard/api/emails/abc", "/dashboard/api/inbox?filter=spam",
     "/dashboard/api/inbox?limit=0", "/dashboard/api/inbox/updates?after_id=-1", "/dashboard/api/inbox/0"],
)
def test_invalid_parameters_are_422(local, query) -> None:
    assert local.get(query).status_code == 422


@pytest.mark.parametrize("path", API_PATHS + ["/dashboard/api/overview?user_id=3"])  # user_id is ignored
def test_database_failure_is_503_without_details(local, path) -> None:
    app.dependency_overrides[get_db] = lambda: BrokenSession()
    response = local.get(path)
    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable."}


def test_frontend_renders_data_safely_and_has_no_secrets_or_external_resources() -> None:
    source = "\n".join(p.read_text() for p in DASHBOARD_DIR.iterdir())
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert unsafe not in source, unsafe
    for marker in ("http://", "https://", "INGEST_SECRET", "DATABASE_URL", "postgresql"):
        assert marker not in source, marker


def test_existing_routes_still_registered() -> None:
    paths = TestClient(app).get("/openapi.json").json()["paths"]
    for path in ("/", "/health", "/signups", "/signups/{signup_id}", "/matcher/check",
                 "/ingest/email", "/dashboard/api/overview", "/dashboard/api/emails/{mail_log_id}",
                 "/dashboard/api/inbox", "/dashboard/api/inbox/{mail_log_id}/read"):
        assert path in paths


def test_navigation_has_every_section_in_order(local) -> None:
    html = local.get("/dashboard").text
    tabs = re.findall(r'role="tab" id="tab-(\w+)"', html)
    assert tabs == ["overview", "websites", "inbox", "receipts", "activity", "check", "settings"]
    for panel in tabs:
        assert f'id="view-{panel}" role="tabpanel" aria-labelledby="tab-{panel}"' in html
    filters = re.findall(r'data-filter="(\w+)" aria-pressed', html)
    assert filters == ["all", "unread", "matched", "unmatched", "failed"]
    assert 'id="notifications"' in html and 'aria-live="polite"' in html and 'id="unread-badge"' in html
    assert 'id="inbox-retry"' in html  # error state offers a retry


# Loads app.js with a stub document and evaluates the pure inbox text helpers.
HELPERS = """
const vm = require("node:vm");
const fs = require("node:fs");
const context = { document: { addEventListener() {} }, Intl, console };
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + `
  globalThis.__run = (m) => ({ identity: identityText(m), note: notificationText(m), sender: senderText(m),
                               reason: reasonText(m.status_reason), unread: unreadLabel(m.n ?? 0) });`, context);
process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0, "utf8")).map((m) => context.__run(m))));
"""


def run_helpers(items: list[dict]) -> list[dict]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    out = subprocess.run([node, "-e", HELPERS, str(DASHBOARD_DIR / "app.js")], input=json.dumps(items),
                         capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


def test_inbox_text_uses_stored_identity_and_never_invents_one() -> None:
    nick, real, bare, deleted = run_helpers([
        {"identity": "Ocelot Smith", "identity_kind": "nickname", "site_name": "Example Shop",
         "sender_name": "Deals", "sender_email": "d@shop.example", "alias": "ab12cd34@leaktrap.xyz", "n": 1},
        {"identity": None, "identity_kind": "real_name", "site_name": "Daily News", "sender_email": "n@news.example", "n": 3},
        {"identity": None, "identity_kind": "none", "alias": "ab12cd34@leaktrap.xyz", "site_name": None,
         "sender_domain": "x.example"},
        {"identity": None, "identity_kind": "none", "alias": None, "status_reason": "not_linked"},
    ])
    assert nick["note"] == "New email received for Ocelot Smith on Example Shop"
    assert nick["sender"] == "Deals <d@shop.example>" and nick["unread"] == "1 unread email"
    assert real["note"] == "New email received for your real name on Daily News"
    assert real["sender"] == "n@news.example" and real["unread"] == "3 unread emails"
    assert bare["note"] == "New email received for ab12cd34@leaktrap.xyz" and bare["sender"] == "someone at x.example"
    assert deleted["identity"] == "an unknown alias" and deleted["sender"] == "Unknown sender"
    assert deleted["reason"].startswith("Not linked to any of your websites")
    assert nick["reason"] is None
