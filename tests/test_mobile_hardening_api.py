"""Mobile API hardening against the isolated PostgreSQL test database: rate limits
(per user for SMS, per client address for pairing, with the shared unknown-client
key), response headers on every /mobile/v1 response, access-log privacy and the
bounded cleanup of expired pairings."""

import hashlib
import logging
import secrets
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend import security
from backend.database import get_db
from backend.main import app
from backend.mobile_http import AccessLogPrivacy
from backend.models import AuthEvent, ExtensionPairing, User, UserSession
from backend.routes import mobile as mobile_routes
from backend.routes import sms as sms_routes
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.services import pairing
from backend.services.auth import LIMITS, now, token_hash
from tests.auth_support import make_account, mobile_token, sign_in

pytestmark = pytest.mark.integration

TOO_MANY = {"detail": "Too many attempts. Wait a while and try again."}
MESSAGE = "Your Example Shop order shipped"
ALL_SCOPES = ("account:read", "websites:read", "email:read", "timeline:read", "sms:analyze", "sms:write")


@pytest.fixture(autouse=True)
def alias_domain(monkeypatch):
    for module in (sms_routes, mobile_routes):
        monkeypatch.setattr(module, "settings", replace(module.settings, alias_domain="leaktrap.xyz"))


@pytest.fixture
def client(session: Session):
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    yield TestClient(app, client=("127.0.0.1", 50000))
    app.dependency_overrides.clear()


@pytest.fixture
def accounts(session: Session) -> dict:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


@pytest.fixture
def tokens(session: Session, accounts) -> dict:
    return {name: mobile_token(session, user, scopes=ALL_SCOPES) for name, user in accounts.items()}


@pytest.fixture
def mobile_mode(monkeypatch):
    """Client addresses as a mobile-mode deployment determines them."""
    def set_hops(hops: int) -> None:
        monkeypatch.setattr(security, "settings", replace(security.settings, app_mode="mobile", trusted_proxy_hops=hops))
    return set_hops


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def start(client, headers=None):
    secret = secrets.token_urlsafe(32)
    return client.post("/mobile/v1/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest()},
                       headers=headers or {}), secret


# ---------- configured limits ----------

def test_configured_limits() -> None:
    hour = timedelta(hours=1)
    assert LIMITS["mobile_pairing_start_ip"] == (10, hour)
    assert LIMITS["mobile_pairing_exchange_ip"] == (120, hour)
    assert LIMITS["sms_analyze_user"] == (60, hour)
    assert LIMITS["sms_write_user"] == (120, hour)


# ---------- per-user SMS limits ----------

def test_sms_analysis_is_limited_per_user(client, tokens, session) -> None:
    for _ in range(60):
        assert client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"])).status_code == 200
    refused = client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"]))
    assert refused.status_code == 429 and refused.json() == TOO_MANY and MESSAGE not in refused.text
    # Bob's quota and Alice's write quota are independent.
    assert client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["bob"])).status_code == 200
    assert client.post("/mobile/v1/sms/investigations", json={"text": MESSAGE}, headers=bearer(tokens["alice"])).status_code == 201
    # Refused requests are not counted.
    session.expire_all()
    kinds = session.scalars(select(AuthEvent.kind)).all()
    assert kinds.count("sms_analyze_user") == 61  # Alice 60, Bob 1


def test_sms_writes_are_limited_per_user_across_save_actions_and_delete(client, tokens) -> None:
    saved = client.post("/mobile/v1/sms/investigations", json={"text": MESSAGE}, headers=bearer(tokens["alice"])).json()
    url = f"/mobile/v1/sms/investigations/{saved['investigation']['id']}"
    for _ in range(119):
        assert client.post(f"{url}/actions", json={"action": "reviewed"}, headers=bearer(tokens["alice"])).status_code == 200
    for method, path, body in [("POST", f"{url}/actions", {"action": "reviewed"}), ("DELETE", url, None),
                               ("POST", "/mobile/v1/sms/investigations", {"text": "another"})]:
        r = client.request(method, path, json=body, headers=bearer(tokens["alice"]))
        assert r.status_code == 429 and r.json() == TOO_MANY, path
    # Reads and analysis are not write-limited, and Bob is unaffected.
    assert client.get(url, headers=bearer(tokens["alice"])).status_code == 200
    assert client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"])).status_code == 200
    assert client.post("/mobile/v1/sms/investigations", json={"text": MESSAGE}, headers=bearer(tokens["bob"])).status_code == 201


def test_limits_apply_after_authentication_and_scope(client, session, accounts, tokens) -> None:
    reader = mobile_token(session, accounts["alice"], scopes=("sms:analyze",))
    for _ in range(5):
        assert client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}).status_code == 401
        assert client.post("/mobile/v1/sms/investigations", json={"text": MESSAGE}, headers=bearer(reader)).status_code == 403
    session.expire_all()
    assert session.scalar(select(func.count()).select_from(AuthEvent).where(AuthEvent.kind.like("sms_%"))) == 0


def test_invalid_bodies_count_towards_the_limit(client, session, tokens) -> None:
    assert client.post("/mobile/v1/sms/analyze", json={"text": ""}, headers=bearer(tokens["alice"])).status_code == 422
    session.expire_all()
    assert session.scalar(select(func.count()).select_from(AuthEvent).where(AuthEvent.kind == "sms_analyze_user")) == 1


def test_dashboard_sms_routes_are_not_limited(client, session, accounts, tokens) -> None:
    sign_in(client, session, accounts["alice"])
    for _ in range(60):
        client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"]))
    assert client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"])).status_code == 429
    assert client.post("/dashboard/api/sms/analyze", json={"text": MESSAGE}).status_code == 200


# ---------- pairing limits by client address ----------

def test_unknown_clients_share_one_strict_pairing_limit(client, mobile_mode) -> None:
    mobile_mode(0)  # the default until staging establishes the hop count
    for i in range(10):
        r, _ = start(client, {"X-Forwarded-For": f"198.51.100.{i}"})  # forwarding headers are not trusted
        assert r.status_code == 201
    r, _ = start(client, {"X-Forwarded-For": "203.0.113.99", "X-Real-IP": "203.0.113.98"})
    assert r.status_code == 429 and r.json() == TOO_MANY


def test_unknown_clients_share_the_exchange_limit(client, mobile_mode) -> None:
    mobile_mode(1)
    started, secret = start(client, {"X-Forwarded-For": "not-an-ip"})
    url = f"/mobile/v1/pairings/{started.json()['pairing_id']}/token"
    for i in range(120):
        assert client.post(url, json={"secret": secret}, headers={"X-Forwarded-For": f"garbage-{i}"}).status_code == 202
    assert client.post(url, json={"secret": secret}).status_code == 429


def test_trusted_hop_addresses_get_independent_limits_and_forged_ones_do_not(client, mobile_mode) -> None:
    mobile_mode(1)
    for i in range(10):
        r, _ = start(client, {"X-Forwarded-For": f"{i}.{i}.{i}.{i}, 203.0.113.5"})  # varying forged leftmost
        assert r.status_code == 201
    r, _ = start(client, {"X-Forwarded-For": "1.2.3.4, 203.0.113.5"})
    assert r.status_code == 429
    r, _ = start(client, {"X-Forwarded-For": "203.0.113.6"})
    assert r.status_code == 201  # a different client address has its own limit


def test_full_mode_pairing_still_keys_by_socket_peer(client) -> None:
    for i in range(10):
        r, _ = start(client, {"X-Forwarded-For": f"198.51.100.{i}"})
        assert r.status_code == 201
    r, _ = start(client)
    assert r.status_code == 429  # one peer (127.0.0.1), whatever the headers say


# ---------- response headers ----------

def test_every_mobile_api_response_is_no_store_and_nosniff(client, session, accounts, tokens, mobile_mode) -> None:
    narrow = mobile_token(session, accounts["alice"], scopes=())
    started, secret = start(client)
    pairing_url = f"/mobile/v1/pairings/{started.json()['pairing_id']}/token"
    saved = client.post("/mobile/v1/sms/investigations", json={"text": MESSAGE}, headers=bearer(tokens["alice"]))
    responses = {
        "201 pairing": started,
        "202 pending": client.post(pairing_url, json={"secret": secret}),
        "404 unknown pairing": client.post("/mobile/v1/pairings/987654321/token", json={"secret": secret}),
        "200 me": client.get("/mobile/v1/me", headers=bearer(tokens["alice"])),
        "200 list": client.get("/mobile/v1/websites?q=private-search", headers=bearer(tokens["alice"])),
        "201 save": saved,
        "204 delete": client.delete(f"/mobile/v1/sms/investigations/{saved.json()['investigation']['id']}",
                                    headers=bearer(tokens["alice"])),
        "401 no token": client.get("/mobile/v1/me"),
        "401 bad token": client.get("/mobile/v1/me", headers=bearer("nope")),
        "403 scope": client.get("/mobile/v1/me", headers=bearer(narrow)),
        "404 record": client.get("/mobile/v1/websites/987654321", headers=bearer(tokens["alice"])),
        "404 route": client.get("/mobile/v1/nothing-here"),
        "405 method": client.put("/mobile/v1/me"),
        "413 too large": client.post("/mobile/v1/sms/analyze", json={"text": "a" * 20000}, headers=bearer(tokens["alice"])),
        "415 content type": client.post("/mobile/v1/sms/analyze", content=b"x", headers={**bearer(tokens["alice"]),
                                                                                          "content-type": "text/plain"}),
        "422 invalid": client.get("/mobile/v1/websites?limit=0", headers=bearer(tokens["alice"])),
    }
    session.execute(update(ExtensionPairing).values(expires_at=now() - timedelta(seconds=1)))
    session.commit()
    responses["410 expired"] = client.post(pairing_url, json={"secret": secret})
    mobile_mode(0)  # a fresh, shared key: the starts above were keyed by the socket peer
    for _ in range(10):
        start(client)
    responses["429 limited"] = start(client)[0]
    for name, r in responses.items():
        assert r.status_code == int(name.split()[0]), (name, r.status_code)
        assert r.headers.get("cache-control") == "no-store", name
        assert r.headers.get("x-content-type-options") == "nosniff", name
        assert r.headers.get_list("cache-control") == ["no-store"], name  # replaced, never duplicated


def test_other_routes_keep_their_headers(client) -> None:
    r = client.get("/health")
    assert r.status_code == 200 and "cache-control" not in r.headers


# ---------- access log ----------

def access_record(path: str) -> logging.LogRecord:
    return logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                             ("10.0.0.9:5000", "GET", path, "1.1", 200), None)


@pytest.mark.parametrize(("strip_all", "path", "logged"), [
    (False, "/mobile/v1/websites?q=private-search&limit=5", "/mobile/v1/websites"),
    (False, "/mobile/v1/sms/investigations?offset=20", "/mobile/v1/sms/investigations"),
    (False, "/dashboard/api/signups?q=kept-locally", "/dashboard/api/signups?q=kept-locally"),
    (True, "/dashboard?q=anything", "/dashboard"),
    (True, "/health", "/health"),
])
def test_access_log_privacy_filter(strip_all, path, logged) -> None:
    record = access_record(path)
    assert AccessLogPrivacy(strip_all).filter(record) is True
    assert record.getMessage() == f'10.0.0.9:5000 - "GET {logged} HTTP/1.1" 200'


def test_access_log_filter_is_installed() -> None:
    assert any(isinstance(f, AccessLogPrivacy) for f in logging.getLogger("uvicorn.access").filters)


def test_logs_never_contain_tokens_secrets_or_search_terms(client, tokens, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    started, secret = start(client)
    client.post(f"/mobile/v1/pairings/{started.json()['pairing_id']}/token", json={"secret": secret})
    client.get("/mobile/v1/websites?q=private-search", headers=bearer(tokens["alice"]))
    client.post("/mobile/v1/sms/analyze", json={"text": MESSAGE}, headers=bearer(tokens["alice"]))
    # httpx is the test client logging its own outgoing URLs, not the server.
    server_logs = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith("httpx"))
    assert "SMS analysis: entities=" in server_logs
    for value in (tokens["alice"], secret, started.json()["code"], "private-search", "order shipped"):
        assert value not in server_logs


# ---------- expired pairing cleanup ----------

def pairing_row(session, expires_in: timedelta, kind="extension", user=None, approved=False, consumed=False) -> int:
    row = ExtensionPairing(code_hash=secrets.token_hex(32), secret_hash=secrets.token_hex(32), client_kind=kind,
                           expires_at=now() + expires_in, user_id=user.id if user else None,
                           approved_at=now() if approved else None, consumed_at=now() if consumed else None)
    session.add(row)
    session.flush()
    return row.id


def test_cleanup_deletes_only_pairings_expired_over_a_day_ago(client, session, accounts, tokens) -> None:
    alice, bob = accounts["alice"], accounts["bob"]
    old = [pairing_row(session, -timedelta(days=2)), pairing_row(session, -timedelta(days=3), "mobile", alice, approved=True),
           pairing_row(session, -timedelta(days=1, minutes=1), "mobile", bob, approved=True, consumed=True)]
    kept = [pairing_row(session, -timedelta(hours=23)), pairing_row(session, -timedelta(minutes=1), "mobile", bob),
            pairing_row(session, timedelta(minutes=9)), pairing_row(session, timedelta(minutes=5), "mobile", alice, approved=True)]
    session.commit()
    sessions_before = session.scalar(select(func.count()).select_from(UserSession))

    r, _ = start(client)
    assert r.status_code == 201
    session.expire_all()
    remaining = set(session.scalars(select(ExtensionPairing.id)).all())
    assert remaining == set(kept) | {r.json()["pairing_id"]}
    # Nothing else is touched: sessions, users and their tokens still work.
    assert session.scalar(select(func.count()).select_from(UserSession)) == sessions_before
    assert session.scalar(select(func.count()).select_from(User)) == 2
    assert client.get("/mobile/v1/me", headers=bearer(tokens["alice"])).status_code == 200


def test_cleanup_is_bounded_per_request(client, session) -> None:
    for i in range(pairing.CLEANUP_BATCH + 50):
        pairing_row(session, -timedelta(days=2, minutes=i))
    session.commit()
    start(client)
    session.expire_all()
    stale = select(func.count()).select_from(ExtensionPairing).where(ExtensionPairing.expires_at < now() - timedelta(days=1))
    assert session.scalar(stale) == 50
    start(client)
    session.expire_all()
    assert session.scalar(stale) == 0


def test_cleanup_runs_for_extension_pairing_starts_too(client, session) -> None:
    pairing_row(session, -timedelta(days=2))
    session.commit()
    secret = secrets.token_urlsafe(32)
    assert client.post("/extension/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest()}).status_code == 201
    session.expire_all()
    assert session.scalar(select(func.count()).select_from(ExtensionPairing)) == 1


def test_valid_pairings_still_complete_after_cleanup(client, session, accounts) -> None:
    started, secret = start(client)
    pairing_row(session, -timedelta(days=5))
    session.commit()
    start(client)  # runs cleanup
    pairing.approve(session, accounts["alice"].id, started.json()["code"], "mobile")
    issued = client.post(f"/mobile/v1/pairings/{started.json()['pairing_id']}/token", json={"secret": secret})
    assert issued.status_code == 200
    assert session.scalar(select(UserSession.kind).where(UserSession.token_hash == token_hash(issued.json()["token"]))) == "mobile"
