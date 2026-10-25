"""Public dashboard origin and proxy-header protections. No database needed."""

from dataclasses import replace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import backend.security as security
from backend.config import (
    parse_forwarded_allow_ips,
    public_dashboard_proxy_allowlist_valid,
    valid_public_dashboard_origin,
)
from backend.main import app
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.security import PublicDashboardOriginGuard
from tests.auth_support import FAKE_CSRF, fake_auth
from tests.test_deployment import run_app

PUBLIC_ORIGIN = "https://dashboard.example.test"
REMOTE_CLIENT = ("198.51.100.44", 51000)


@pytest.fixture(autouse=True)
def clean_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_remote_dashboard_is_loopback_only_by_default(monkeypatch) -> None:
    monkeypatch.delenv("LEAKTRACE_DASHBOARD_PUBLIC", raising=False)
    monkeypatch.delenv("LEAKTRACE_DASHBOARD_PUBLIC_ORIGIN", raising=False)
    from backend.config import get_settings

    assert get_settings().dashboard_public is False
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    client = TestClient(app, client=REMOTE_CLIENT)
    assert client.get("/dashboard").status_code == 403


def test_public_dashboard_accepts_only_configured_https_origin() -> None:
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(
        enabled=True, public=True, public_origin=PUBLIC_ORIGIN
    )
    allowed = TestClient(app, base_url=PUBLIC_ORIGIN, client=REMOTE_CLIENT)
    rejected_host = TestClient(app, base_url="https://other.example.test", client=REMOTE_CLIENT)
    rejected_scheme = TestClient(app, base_url="http://dashboard.example.test", client=REMOTE_CLIENT)

    response = allowed.get("/dashboard")
    assert response.status_code == 200
    assert "Secure dashboard." in response.text
    assert "Local development only." not in response.text
    assert rejected_host.get("/dashboard").status_code == 403
    assert rejected_scheme.get("/dashboard", headers={"X-Forwarded-Proto": "https"}).status_code == 403


def test_public_dashboard_configuration_requires_https_origin_and_explicit_proxy_allowlist() -> None:
    assert valid_public_dashboard_origin(PUBLIC_ORIGIN) == PUBLIC_ORIGIN
    for invalid in (
        "http://dashboard.example.test", "https://user@dashboard.example.test",
        "https://dashboard.example.test/path", "https://dashboard.example.test?x=1",
        "https://dashboard.example.test#fragment", "https://bad_host.example.test",
    ):
        assert valid_public_dashboard_origin(invalid) is None

    assert parse_forwarded_allow_ips("192.0.2.10,2001:db8::10") is not None
    for invalid in ("*", "0.0.0.0/0", "::/0", "proxy.example.test", "192.0.2.10,,192.0.2.11"):
        assert parse_forwarded_allow_ips(invalid) is None
    assert not public_dashboard_proxy_allowlist_valid("127.0.0.1,::1", True)
    assert not public_dashboard_proxy_allowlist_valid("192.0.2.10", False)
    assert public_dashboard_proxy_allowlist_valid("192.0.2.10", True)


def test_public_dashboard_startup_fails_closed_without_remote_proxy_allowlist() -> None:
    env = {
        "DATABASE_URL": "postgresql+psycopg://u:p@db.invalid/leaktrace",
        "LEAKTRACE_ENV": "staging",
        "LEAKTRACE_APP_MODE": "full",
        "LEAKTRACE_SECRET_KEY": "k" * 40,
        "LEAKTRACE_DASHBOARD_ENABLED": "true",
        "LEAKTRACE_DASHBOARD_PUBLIC": "true",
        "LEAKTRACE_DASHBOARD_PUBLIC_ORIGIN": PUBLIC_ORIGIN,
        "FORWARDED_ALLOW_IPS": "127.0.0.1,::1",
    }
    result = run_app(env)
    assert result.returncode != 0
    assert "FORWARDED_ALLOW_IPS must be an explicit, non-loopback" in result.stderr

    configured = run_app({**env, "FORWARDED_ALLOW_IPS": "192.0.2.10"})
    assert configured.returncode == 0, configured.stderr
    assert "started" in configured.stdout


def test_public_dashboard_csrf_requires_canonical_https_origin_and_token(monkeypatch) -> None:
    monkeypatch.setattr(
        security, "settings",
        replace(security.settings, dashboard_public=True, dashboard_public_origin=PUBLIC_ORIGIN),
    )
    protected = FastAPI()

    @protected.post("/change")
    def change(_context=Depends(security.require_user)):
        return {"ok": True}

    fake_auth(protected)
    client = TestClient(protected, base_url=PUBLIC_ORIGIN, client=REMOTE_CLIENT)
    assert client.post("/change", headers={"Origin": PUBLIC_ORIGIN, "X-CSRF-Token": FAKE_CSRF}).status_code == 200
    assert client.post("/change", headers={"Origin": "https://evil.example", "X-CSRF-Token": FAKE_CSRF}).status_code == 403
    assert client.post("/change", headers={"Origin": PUBLIC_ORIGIN}).status_code == 403

    insecure = TestClient(protected, base_url="http://dashboard.example.test", client=REMOTE_CLIENT)
    assert insecure.post("/change", headers={"Origin": PUBLIC_ORIGIN, "X-CSRF-Token": FAKE_CSRF}).status_code == 403


def test_forwarded_headers_from_untrusted_peer_cannot_spoof_https_or_loopback() -> None:
    inner = FastAPI()

    @inner.get("/dashboard")
    def page():
        return PlainTextResponse("dashboard")

    guarded = PublicDashboardOriginGuard(inner, PUBLIC_ORIGIN)
    proxy_checked = ProxyHeadersMiddleware(guarded, trusted_hosts="192.0.2.10")
    spoofing_client = TestClient(proxy_checked, base_url="http://dashboard.example.test", client=REMOTE_CLIENT)
    trusted_proxy_client = TestClient(
        proxy_checked, base_url="http://dashboard.example.test", client=("192.0.2.10", 51000)
    )

    spoofed = spoofing_client.get(
        "/dashboard",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"},
    )
    trusted = trusted_proxy_client.get(
        "/dashboard",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.44, 192.0.2.10"},
    )
    assert spoofed.status_code == 403
    assert trusted.status_code == 200
