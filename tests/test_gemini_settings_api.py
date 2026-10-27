"""Admin-only encrypted Gemini credential settings (isolated PostgreSQL)."""
from dataclasses import replace

import pytest
from cryptography.fernet import Fernet

from backend.models import DomainVerificationCredential
from backend.routes import auth as auth_routes
from backend.routes import domain_verification as routes
from backend.services import gemini
from tests.test_inbox_api import accounts, signups, alice, bob, worker  # noqa: F401

pytestmark = pytest.mark.integration


def configure_admin(monkeypatch, email="alice@example.com"):
    encryption_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(routes, "settings", replace(
        routes.settings, domain_verification_admin_emails=(email,), domain_verification_encryption_key=encryption_key,
    ))
    monkeypatch.setattr(gemini, "settings", replace(
        gemini.settings, domain_verification_encryption_key=encryption_key, domain_llm_api_key=None,
    ))
    monkeypatch.setattr(auth_routes, "settings", replace(
        auth_routes.settings, domain_verification_admin_emails=(email,),
    ))


def test_admin_can_save_test_and_remove_encrypted_key(alice, session, monkeypatch):
    configure_admin(monkeypatch)
    secret = "test-gemini-key-value-that-must-not-leak"
    saved = alice.put("/dashboard/api/domain-verification/settings", json={"api_key": secret})
    assert saved.status_code == 200
    assert saved.json() == {"configured": True, "masked_api_key": "••••••••"}
    assert secret not in saved.text
    row = session.get(DomainVerificationCredential, 1)
    assert secret not in row.encrypted_api_key
    assert gemini.decrypt_api_key(row.encrypted_api_key) == secret

    state = alice.get("/dashboard/api/domain-verification/settings")
    assert state.json() == {"configured": True, "saved_key": True, "server_managed": False,
                            "masked_api_key": "••••••••", "encryption_ready": True}
    seen = []
    monkeypatch.setattr(gemini, "test_connection", lambda key: seen.append(key))
    tested = alice.post("/dashboard/api/domain-verification/test")
    assert tested.status_code == 200 and tested.json()["ok"] is True
    assert seen == [secret] and secret not in tested.text

    removed = alice.delete("/dashboard/api/domain-verification/settings")
    assert removed.status_code == 204
    assert session.get(DomainVerificationCredential, 1) is None
    assert alice.get("/dashboard/api/domain-verification/settings").json()["configured"] is False


def test_domain_verification_settings_require_allowlisted_verified_admin(alice, bob, worker, monkeypatch):
    configure_admin(monkeypatch)
    assert alice.get("/dashboard/api/domain-verification/settings").status_code == 200
    assert bob.get("/dashboard/api/domain-verification/settings").status_code == 403
    assert worker.get("/dashboard/api/domain-verification/settings").status_code == 401
    assert bob.post("/dashboard/api/domain-verification/test").status_code == 403
    assert worker.delete("/dashboard/api/domain-verification/settings").status_code == 401


def test_save_requires_separate_encryption_key_and_never_echoes_invalid_key(alice, monkeypatch):
    monkeypatch.setattr(routes, "settings", replace(
        routes.settings, domain_verification_admin_emails=("alice@example.com",),
        domain_verification_encryption_key=None,
    ))
    assert alice.put("/dashboard/api/domain-verification/settings", json={"api_key": "secret-value-long-enough"}).status_code == 503
    assert "secret-value" not in alice.put(
        "/dashboard/api/domain-verification/settings", json={"api_key": "short"}
    ).text


def test_gemini_provider_failure_is_generic_and_does_not_expose_secret(alice, monkeypatch):
    configure_admin(monkeypatch)
    secret = "test-gemini-key-value-that-must-not-leak"
    assert alice.put("/dashboard/api/domain-verification/settings", json={"api_key": secret}).status_code == 200

    def failed(_key):
        raise gemini.GeminiError("gemini_authentication_failed")

    monkeypatch.setattr(gemini, "test_connection", failed)
    result = alice.post("/dashboard/api/domain-verification/test")
    assert result.status_code == 401
    assert secret not in result.text and "gemini_authentication_failed" not in result.text


def test_me_only_reports_admin_for_verified_allowlisted_email(alice, monkeypatch):
    configure_admin(monkeypatch)
    assert alice.get("/auth/me").json()["is_domain_verification_admin"] is True
