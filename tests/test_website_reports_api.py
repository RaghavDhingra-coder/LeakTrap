"""Community reporting must be authenticated, minimal, distinct, and exact-host scoped."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.database import get_db
from backend.main import app
from backend.models import WebsiteReport
from tests.auth_support import extension_token, make_account, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
def clients(session):
    app.dependency_overrides[get_db] = lambda: session
    alice = make_account(session, "report-alice@example.com")
    bob = make_account(session, "report-bob@example.com")
    web = TestClient(app)
    sign_in(web, session, alice)
    other = TestClient(app)
    sign_in(other, session, bob)
    ext = TestClient(app)
    ext.headers.update({"Authorization": f"Bearer {extension_token(session, alice)}"})
    yield web, other, ext, session, alice
    app.dependency_overrides.clear()


def test_submit_duplicate_reputation_and_exact_host(clients):
    web, other, ext, session, alice = clients
    payload = {"domain": "BÜCHER.Example.", "category": "personal_marker_match"}
    first = web.post("/website-reports", json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["domain"] == "xn--bcher-kva.example"
    assert first.json()["verification_status"] == "unverified"
    assert web.post("/website-reports", json=payload).json()["already_reported"] is True
    assert other.post("/website-reports", json=payload).status_code == 201
    row = session.scalars(select(WebsiteReport)).first()
    assert row.reporter_user_id == alice.id and row.reported_at and row.verification_status == "unverified"
    report = ext.get("/website-reports/reputation", params={"domain": "xn--bcher-kva.example"})
    assert report.status_code == 200
    assert report.json()["report_count"] == 2
    assert report.json()["reporter_count"] == 2
    assert report.json()["verified_count"] == 0
    assert report.json()["categories"] == [{"category": "personal_marker_match", "unverified_count": 2, "verified_count": 0}]
    assert ext.get("/website-reports/reputation", params={"domain": "shop.xn--bcher-kva.example"}).json()["report_count"] == 0
    assert ext.get("/website-reports/reputation", params={"domain": "www.xn--bcher-kva.example"}).json()["report_count"] == 2
    row.verification_status = "verified"
    session.commit()
    result = ext.get("/website-reports/reputation", params={"domain": "xn--bcher-kva.example"}).json()
    assert result["verified_count"] == 1 and result["unverified_count"] == 1
    assert web.post("/website-reports", json={"domain": "xn--bcher-kva.example", "category": "suspicious_message_link"}).status_code == 201
    result = ext.get("/website-reports/reputation", params={"domain": "xn--bcher-kva.example"}).json()
    assert result["report_count"] == 3 and result["reporter_count"] == 2


def test_validation_auth_privacy_and_rate_limit(clients):
    web, _, ext, session, _ = clients
    anonymous = TestClient(app)
    assert anonymous.post("/website-reports", json={"domain": "example.com", "category": "suspicious_message_link"}).status_code == 401
    assert anonymous.get("/website-reports/reputation?domain=example.com").status_code == 401
    submitted = ext.post("/website-reports", json={"domain": "example.com", "category": "suspicious_message_link"})
    assert submitted.status_code == 201 and submitted.json()["domain"] == "example.com"
    assert ext.post("/website-reports", json={"domain": "example.com", "category": "suspicious_message_link"}).json()["already_reported"]
    for domain in ("https://example.com/path", "localhost", "127.0.0.1", "a..example", "example.com:443"):
        assert web.post("/website-reports", json={"domain": domain, "category": "suspicious_message_link"}).status_code == 422
    assert web.post("/website-reports", json={"domain": "example.com", "category": "confirmed_breach"}).status_code == 422
    assert web.post("/website-reports", json={"domain": "example.com", "category": "suspicious_message_link", "message": "private"}).status_code == 422
    for n in range(9):
        assert web.post("/website-reports", json={"domain": f"host{n}.example.com", "category": "suspicious_message_link"}).status_code == 201
    assert web.post("/website-reports", json={"domain": "host11.example.com", "category": "suspicious_message_link"}).status_code == 429


def test_www_and_base_share_one_report_scope(clients):
    web, _, ext, session, _ = clients
    payload = {"domain": "WWW.Example.COM", "category": "personal_marker_match"}
    first = web.post("/website-reports", json=payload)
    assert first.status_code == 201 and first.json()["domain"] == "example.com"
    assert web.post("/website-reports", json={**payload, "domain": "example.com"}).json()["already_reported"] is True
    assert ext.get("/website-reports/reputation", params={"domain": "www.example.com"}).json()["report_count"] == 1
    assert ext.get("/website-reports/reputation", params={"domain": "accounts.example.com"}).json()["report_count"] == 0


def test_extension_requires_reporting_scope(clients):
    _, _, ext, session, alice = clients
    limited = extension_token(session, alice, scopes={"signups:lookup"})
    denied = ext.post("/website-reports", json={"domain": "example.com", "category": "personal_marker_match"},
                      headers={"Authorization": f"Bearer {limited}"})
    assert denied.status_code == 403
