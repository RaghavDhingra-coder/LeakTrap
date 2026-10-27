"""Google Search grounding is advisory and never sends private email data."""
from datetime import datetime, timezone
from dataclasses import replace

import pytest
import httpx

from backend.services import gemini, sender_classification


def response(url="https://example.com/about", claimed=None):
    return {"candidates": [{"content": {"parts": [{"text": '{"organization":"Example Inc","evidence_type":"about","summary":"Official about page","confidence":"high","uncertainty":"Self published","source_urls":["' + (claimed or url) + '"]}'}]},
                            "groundingMetadata": {"groundingChunks": [{"web": {"uri": url}}],
                                                  "groundingSupports": [{"groundingChunkIndices": [0]}]}}]}


def test_grounding_uses_search_and_only_public_domain(monkeypatch):
    calls = []
    monkeypatch.setattr(gemini, "_request", lambda key, prompt, tokens, **options:
                        calls.append((prompt, options)) or response())
    evidence = {"domain": "example.com", "alias": "private@leaktrap.xyz",
                "email_body": "private OTP", "sender_address": "person@example.com"}
    result = gemini.grounded_discovery("test-only-key", evidence)
    assert calls[0][1] == {"search": True}
    assert all(value not in calls[0][0] for value in ("private@", "private OTP", "person@example.com"))
    assert result["status"] == "grounded_lead" and result["source_urls"] == ["https://example.com/about"]
    assert result["affects_classification"] is False


def test_configured_domain_key_is_used_without_database_credential(monkeypatch):
    monkeypatch.setattr(gemini, "settings", replace(gemini.settings, domain_llm_api_key="unit-test-key"))
    class NoDatabase:
        def get(self, *_args):
            raise AssertionError("database credential should not be read")
    assert gemini.get_api_key(NoDatabase()) == "unit-test-key"


def test_connection_checks_search_grounding_not_plain_text(monkeypatch):
    calls = []
    monkeypatch.setattr(gemini, "_request", lambda _key, prompt, _tokens, **options:
                        calls.append((prompt, options)) or response())
    gemini.test_connection("test-only-key")
    assert calls[0][1]["search"] is True
    monkeypatch.setattr(gemini, "_request", lambda *_args, **_kwargs: {"candidates": [{
        "content": {"parts": [{"text": '{"organization":null,"source_urls":[]}' }]},
        "groundingMetadata": {"groundingChunks": [], "groundingSupports": []}}]})
    with pytest.raises(gemini.GeminiError, match="search_grounding_unavailable"):
        gemini.test_connection("test-only-key")


def test_hallucinated_and_unsafe_sources_are_rejected(monkeypatch):
    monkeypatch.setattr(gemini, "_request", lambda *_args, **_kwargs:
                        response(claimed="https://invented.org/not-retrieved"))
    result = gemini.grounded_discovery("test-only-key", {"domain": "example.com"})
    assert result["status"] == "insufficient_grounded_sources"
    assert not result["source_urls"]
    assert gemini._safe_grounded_url("http://127.0.0.1/private") is None
    assert gemini._safe_grounded_url("https://user@localhost/private") is None
    assert gemini._safe_grounded_url("https://example.com.evil.test/") is None


def test_missing_grounding_cannot_upgrade_sender(monkeypatch):
    monkeypatch.setattr(gemini, "_request", lambda *_args, **_kwargs:
                        {"candidates": [{"content": {"parts": [{"text": '{"organization":"Amazon","source_urls":["https://amazon.com/"]}'}]},
                                         "groundingMetadata": {"groundingChunks": [], "groundingSupports": []}}]})
    lead = gemini.grounded_discovery("test-only-key", {"domain": "amazon.com"})
    evidence = {"domain": "amazon.com", "checked_at": datetime.now(timezone.utc).isoformat(),
                "dns": {"records": []}, "website": {"organization_claims": []},
                "gemini_interpretation": lead}
    result = sender_classification.classify(
        site_name="Amazon", site_domain="amazon.com", alias="test@leaktrap.xyz",
        sender_domain="amazon.com", auth_results="spf=pass dkim=pass dmarc=pass",
        alias_matched=True, site_evidence=evidence, sender_evidence=evidence)
    assert lead["status"] == "insufficient_grounded_sources"
    assert result["status"] == "Unknown"


def test_malformed_grounding_response_is_reported(monkeypatch):
    monkeypatch.setattr(gemini, "_request", lambda *_args, **_kwargs: {"candidates": [{}]})
    with pytest.raises(gemini.GeminiError, match="gemini_invalid_response"):
        gemini.grounded_discovery("test-only-key", {"domain": "example.com"})


def test_gemini_error_and_timeout_categories(monkeypatch):
    class FakeResponse:
        is_redirect = False
        def __init__(self, status): self.status_code = status
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def iter_bytes(self): yield b'{}'
    class FakeClient:
        def __init__(self, statuses, **_kwargs): self.statuses = statuses
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def stream(self, *_args, **_kwargs): return FakeResponse(self.statuses.pop(0))
    statuses = [429, 429]
    monkeypatch.setattr(gemini.httpx, "Client", lambda **kwargs: FakeClient(statuses, **kwargs))
    monkeypatch.setattr(gemini.time, "sleep", lambda _seconds: None)
    with pytest.raises(gemini.GeminiError, match="gemini_rate_limited"):
        gemini._request("test-only-key", "example.com", 64, search=True)
    assert not statuses
    statuses = [400]
    with pytest.raises(gemini.GeminiError, match="search_grounding_unsupported"):
        gemini._request("test-only-key", "example.com", 64, search=True)
    class TimedOutClient(FakeClient):
        def stream(self, *_args, **_kwargs): raise httpx.ReadTimeout("timed out")
    monkeypatch.setattr(gemini.httpx, "Client", lambda **kwargs: TimedOutClient([], **kwargs))
    with pytest.raises(gemini.GeminiError, match="gemini_timeout"):
        gemini._request("test-only-key", "example.com", 64, search=True)


def test_deterministic_evidence_survives_gemini_failure_and_conflicts():
    now = datetime.now(timezone.utc).isoformat()
    def evidence(domain, claims):
        return {"domain": domain, "checked_at": now, "dns": {"records": []},
                "website": {"organization_claims": claims, "observed_url": f"https://{domain}/"},
                "source_urls": [f"https://{domain}/"],
                "gemini_interpretation": {"status": "gemini_rate_limited", "affects_classification": False}}
    site = evidence("example.com", ["Example Inc"])
    sender = evidence("mail.example.com", ["Example Inc"])
    args = {"site_name": "Example", "site_domain": "example.com", "alias": "test@leaktrap.xyz",
            "sender_domain": "mail.example.com", "auth_results": "spf=pass dkim=pass dmarc=pass",
            "alias_matched": True, "site_evidence": site, "sender_evidence": sender}
    assert sender_classification.classify(**args)["status"] == "Verified Sender"
    sender["website"]["organization_claims"] = ["Example Inc", "Unrelated Company"]
    assert sender_classification.classify(**args)["status"] == "Unknown"
    sender["website"]["organization_claims"] = ["Other Inc"]
    sender["checked_at"] = "2020-01-01T00:00:00+00:00"
    assert sender_classification.classify(**args)["status"] == "Unknown"


def test_unrelated_same_name_needs_official_cross_domain_link():
    now = datetime.now(timezone.utc).isoformat()
    def evidence(domain):
        return {"domain": domain, "checked_at": now, "dns": {"records": []},
                "website": {"organization_claims": ["Example Inc"], "observed_url": f"https://{domain}/"},
                "source_urls": [f"https://{domain}/"]}
    site, sender = evidence("example.com"), evidence("example-mail.org")
    args = {"site_name": "Example", "site_domain": "example.com", "alias": "test@leaktrap.xyz",
            "sender_domain": "example-mail.org", "auth_results": "spf=pass dkim=pass dmarc=pass",
            "alias_matched": True, "site_evidence": site, "sender_evidence": sender}
    assert sender_classification.classify(**args)["status"] == "Unknown"
    site["website"]["linked_domains"] = ["example-mail.org"]
    assert sender_classification.classify(**args)["status"] == "Verified Sender"
    args["sender_domain"] = "mail.example-mail.org.evil.net"
    assert sender_classification.classify(**args)["status"] == "Unknown"


def test_one_domain_failure_preserves_other_evidence(monkeypatch, caplog):
    from backend.services import domain_evidence
    valid = {"domain": "example.com", "checked_at": datetime.now(timezone.utc).isoformat(),
             "dns": {"records": []}, "website": {"organization_claims": ["Example Inc"],
                                           "observed_url": "https://example.com/"},
             "source_urls": ["https://example.com/"]}
    def load(_session, domain, **_kwargs):
        if domain == "sender.org":
            raise domain_evidence.EvidenceError("dns_timeout")
        return valid
    monkeypatch.setattr(domain_evidence, "cached_public_evidence", load)
    result = sender_classification.classify_for_email(
        object(), site_name="Example", site_domain="example.com", alias="alias@leaktrap.xyz",
        sender_domain="sender.org", sender_address=None, auth_results="spf=pass dkim=pass dmarc=pass",
        alias_matched=True, correlation_id="123")
    assert result["registered_domain_evidence"] == valid
    assert result["sender_domain_evidence"]["errors"][0]["category"] == "dns_timeout"
    assert result["status"] == "Unknown"
    assert "correlation_id=123" in caplog.text and "domain=sender.org" in caplog.text
