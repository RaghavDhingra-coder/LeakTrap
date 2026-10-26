"""Consent receipts: validation, local-only guard, limits and dashboard assets.
No database needed."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from backend.database import get_db
from backend.main import app
from tests.auth_support import FAKE_HEADERS, fake_auth
from backend.models.consent_receipt import CAPTURE_SOURCES, RECEIPT_ACTIONS
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.schemas.consent_receipt import ConsentReceiptCreate, sha256_of

LOCAL = ("127.0.0.1", 50000)
DASHBOARD = Path(__file__).resolve().parent.parent / "backend/dashboard"
VALID = {"signup_id": 1, "action": "accepted", "source_url": "https://shop.example.com/privacy"}


class BrokenSession:
    def _fail(self, *args, **kwargs):
        raise OperationalError("SELECT", {}, Exception("postgresql://user:pw@host/db refused"))

    get = scalar = execute = add = commit = rollback = _fail


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


def post(client, body, **kwargs):
    return client.post("/consent-receipts", json=body, **kwargs)


def test_vocabulary_has_no_verified_state() -> None:
    assert RECEIPT_ACTIONS == ("accepted", "declined", "notice_only")
    assert CAPTURE_SOURCES == ("manual",)


def test_valid_minimal_receipt() -> None:
    receipt = ConsentReceiptCreate(**VALID)
    assert receipt.action == "accepted" and receipt.content_hash is None


def test_notice_text_hash_is_computed_and_checked() -> None:
    text = "We share data with partners.\n"
    receipt = ConsentReceiptCreate(signup_id=1, action="notice_only", notice_text=text)
    assert receipt.content_hash == sha256_of(text)
    same = ConsentReceiptCreate(signup_id=1, action="notice_only", notice_text=text,
                                content_hash=sha256_of(text).removeprefix("sha256:").upper())
    assert same.content_hash == sha256_of(text)
    with pytest.raises(ValidationError, match="does not match"):
        ConsentReceiptCreate(signup_id=1, action="notice_only", notice_text=text, content_hash="a" * 64)


def test_hash_only_receipt_is_accepted() -> None:
    receipt = ConsentReceiptCreate(signup_id=1, action="declined", content_hash="sha256:" + "AB" * 32)
    assert receipt.content_hash == "sha256:" + "ab" * 32


@pytest.mark.parametrize(
    "body",
    [
        {**VALID, "action": "verified"}, {**VALID, "action": "ACCEPTED"}, {**VALID, "action": None},
        {"signup_id": 1, "source_url": "https://x.example/p"},  # no action
        {**VALID, "signup_id": 0}, {**VALID, "signup_id": -1}, {**VALID, "signup_id": 2**63},
        {**VALID, "signup_id": "abc"}, {"action": "accepted", "source_url": "https://x.example"},
        {**VALID, "source_url": "javascript:alert(1)"}, {**VALID, "source_url": "file:///etc/passwd"},
        {**VALID, "source_url": "ftp://x.example/p"}, {**VALID, "source_url": "data:text/html,hi"},
        {**VALID, "source_url": "https://user:pw@x.example/p"}, {**VALID, "source_url": "https:///nohost"},
        {**VALID, "source_url": "https://x.example/a b"}, {**VALID, "source_url": "https://x.example/" + "a" * 2048},
        {**VALID, "content_hash": "xyz"}, {**VALID, "content_hash": "md5:" + "a" * 32},
        {**VALID, "notice_text": "   "}, {**VALID, "notice_text": "x" * 20_001},
        {**VALID, "notice_text": "bad\x00byte"}, {**VALID, "consent_text": "y" * 2_001},
        {**VALID, "notice_version": "v" * 101},
        {**VALID, "reported_occurred_at": "2026-10-01T10:00:00"},  # no timezone
        {**VALID, "reported_occurred_at": "yesterday"},
        {**VALID, "reported_occurred_at": "1985-01-01T00:00:00Z"},
        {**VALID, "reported_occurred_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
        {**VALID, "capture_source": "verified"}, {**VALID, "verified": True}, {**VALID, "user_id": 2},
        {**VALID, "site_name": "Spoofed"}, {**VALID, "recorded_at": "2026-01-01T00:00:00Z"},
        {"signup_id": 1, "action": "accepted"},  # no evidence at all
    ],
)
def test_invalid_payloads_are_422_without_echo(local, body) -> None:
    response = post(local, body)
    assert response.status_code == 422, body
    assert all(set(e) == {"loc", "msg"} for e in response.json()["detail"])
    assert "alert(1)" not in response.text and "pw@" not in response.text


def test_oversized_body_is_413(local) -> None:
    response = local.post("/consent-receipts", content=json.dumps({**VALID, "notice_text": "x" * 140_000}),
                          headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_non_json_is_415(local) -> None:
    response = local.post("/consent-receipts", content=b"signup_id=1", headers={"content-type": "text/plain"})
    assert response.status_code == 415


@pytest.mark.parametrize(
    "query", ["/consent-receipts?limit=0", "/consent-receipts?limit=101", "/consent-receipts?offset=-1",
              "/consent-receipts?signup_id=0", "/consent-receipts/0",
              "/consent-receipts/abc"],
)
def test_invalid_query_parameters_are_422(local, query) -> None:
    assert local.get(query).status_code == 422


@pytest.mark.parametrize(
    ("method", "path"), [("get", "/consent-receipts"), ("get", "/consent-receipts/1"), ("post", "/consent-receipts")]
)
def test_non_local_clients_are_refused(method, path) -> None:
    client = TestClient(app, client=("203.0.113.9", 50000))
    response = getattr(client, method)(path, **({"json": VALID} if method == "post" else {}))
    assert response.status_code == 403


def test_disabled_is_404(local) -> None:
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=False)
    assert local.get("/consent-receipts").status_code == 404
    assert post(local, VALID).status_code == 404


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/consent-receipts"), ("get", "/consent-receipts/1"), ("post", "/consent-receipts"),
     ("get", "/consent-receipts?user_id=4")],
)
def test_database_failure_is_503_without_details(local, method, path) -> None:
    app.dependency_overrides[get_db] = lambda: BrokenSession()
    response = getattr(local, method)(path, **({"json": VALID} if method == "post" else {}))
    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable."}


def test_dashboard_has_receipts_view_with_states_and_safe_rendering(local) -> None:
    page = local.get("/dashboard")
    assert page.status_code == 200
    assert 'id="tab-receipts"' in page.text and 'id="view-receipts"' in page.text
    assert "does not prove that legally valid consent" in page.text
    assert "Local development only." in page.text
    assert "content-security-policy" in page.headers
    js = (DASHBOARD / "app.js").read_text()
    for state in ("Loading…", "No consent receipts yet.", "setStatus(section, error.message, true)"):
        assert state in js, state
    assert "user-reported (not verified)" in js
    assert "Reported event time (unverified)" in js and "Recorded by LeakTrace (server time)" in js
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert unsafe not in js
    # No delete controls for receipts (DELETE is used only for the account and extension connections).
    assert "/consent-receipts/" not in [line for line in js.splitlines() if "DELETE" in line].__str__()


def test_existing_routes_still_registered() -> None:
    paths = TestClient(app).get("/openapi.json").json()["paths"]
    for path in ("/", "/health", "/signups", "/matcher/check", "/ingest/email", "/dashboard/api/overview",
                 "/consent-receipts", "/consent-receipts/{receipt_id}"):
        assert path in paths
