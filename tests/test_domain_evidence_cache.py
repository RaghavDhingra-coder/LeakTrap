"""Evidence cache expiry and refresh behavior using disposable PostgreSQL."""
from datetime import datetime, timedelta, timezone

import pytest

from backend.models import DomainEvidenceCache
from backend.services import domain_evidence

pytestmark = pytest.mark.integration


def test_public_evidence_cache_returns_fresh_and_refreshes_expired_entries(session, monkeypatch):
    collected = []

    def collect(domain):
        collected.append(domain)
        return ({"domain": domain, "checked_at": f"snapshot-{len(collected)}", "dns": {"records": []},
                 "website": {"organization_claims": []}, "source_urls": []}, 3600)

    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)
    first_time = datetime(2026, 10, 27, tzinfo=timezone.utc)
    first = domain_evidence.cached_public_evidence(session, "NewDomain.Example", now=first_time)
    cached = domain_evidence.cached_public_evidence(session, "newdomain.example", now=first_time + timedelta(minutes=30))
    refreshed = domain_evidence.cached_public_evidence(session, "newdomain.example", now=first_time + timedelta(hours=2))
    assert first["checked_at"] == cached["checked_at"] == "snapshot-1"
    assert refreshed["checked_at"] == "snapshot-2"
    assert collected == ["newdomain.example", "newdomain.example"]
    row = session.get(DomainEvidenceCache, "newdomain.example")
    assert row.evidence["checked_at"] == "snapshot-2"
    assert row.expires_at == first_time + timedelta(hours=2, seconds=3600)


def test_old_evidence_format_refreshes_even_before_expiry(session, monkeypatch):
    now = datetime.now(timezone.utc)
    session.add(DomainEvidenceCache(
        domain="adobe.com", evidence={"evidence_version": 2, "domain": "adobe.com"},
        organization_claim=None, fetched_at=now, expires_at=now + timedelta(hours=1),
    ))
    session.flush()
    collected = []
    def collect(domain):
        collected.append(domain)
        return ({"domain": domain, "checked_at": now.isoformat(),
                 "dns": {"records": [{"type": "A", "data": "93.184.216.34"}]},
                 "website": {"error": "website_access_denied", "organization_claims": []},
                 "errors": [{"stage": "https", "category": "website_access_denied"}],
                 "source_urls": []}, 3600)
    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)
    evidence = domain_evidence.cached_public_evidence(session, "adobe.com", now=now)
    assert collected == ["adobe.com"]
    assert evidence["evidence_version"] == domain_evidence.EVIDENCE_VERSION
    assert evidence["website"]["error"] == "website_access_denied"
