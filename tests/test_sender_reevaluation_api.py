"""User-scoped, bounded refresh of stored sender attribution."""
import pytest
from datetime import datetime, timezone

from backend.models import MailLog
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver  # noqa: F401

pytestmark = pytest.mark.integration


def test_refresh_updates_old_snapshot_and_is_idempotent(alice, bob, worker, signups, session, monkeypatch):
    from backend.services import domain_evidence
    seen = []
    def collect(domain):
        seen.append(domain)
        return ({"domain": domain, "checked_at": datetime.now(timezone.utc).isoformat(),
                 "dns": {"records": []}, "website": {"organization_claims": ["Example Shop"],
                                                 "observed_url": f"https://{domain}/"},
                 "source_urls": [f"https://{domain}/"]}, 3600)
    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)
    mail_id = deliver(worker, signups["shop"].alias, 1, auth_results="i=1; mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass")["mail_log_id"]
    log = session.get(MailLog, mail_id)
    log.sender_attribution = {"ruleset_version": "old", "status": "Unknown"}
    session.commit()
    assert alice.get(f"/dashboard/api/inbox/{mail_id}").json()["attribution_pending"] is True
    assert bob.post("/dashboard/api/inbox/reevaluate").json()["refreshed"] == 0
    first = alice.post("/dashboard/api/inbox/reevaluate?limit=10&offset=0")
    assert first.status_code == 200 and first.json()["refreshed"] == 1
    saved = session.get(MailLog, mail_id).sender_attribution
    assert saved["status"] == "Verified Sender" and saved["evaluated_at"]
    second = alice.post("/dashboard/api/inbox/reevaluate")
    assert second.status_code == 200 and second.json()["skipped"] == 1
    assert session.get(MailLog, mail_id).sender_attribution["evaluated_at"] == saved["evaluated_at"]
    assert alice.post("/dashboard/api/inbox/reevaluate?limit=11").status_code == 422
    assert seen == ["shop.example.com"]


def test_refresh_requires_authentication(worker):
    assert worker.post("/dashboard/api/inbox/reevaluate").status_code == 401


def test_missing_snapshot_is_identified_and_targeted_refresh_is_user_scoped(alice, bob, worker, signups, session):
    mail_id = deliver(worker, signups["shop"].alias, 2)["mail_log_id"]
    log = session.get(MailLog, mail_id)
    log.sender_attribution = None  # An older ingest service can still write tracked mail.
    session.commit()
    before = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    assert before["attribution_pending"] is True
    assert before["sender_attribution"]["status"] == "Unknown"
    assert before["sender_attribution"]["evidence_status"]["sender_domain"] == "Evidence not evaluated"
    assert bob.post("/dashboard/api/inbox/reevaluate", json={"mail_log_ids": [mail_id]}).json()["refreshed"] == 0
    refreshed = alice.post("/dashboard/api/inbox/reevaluate", json={"mail_log_ids": [mail_id]})
    assert refreshed.status_code == 200 and refreshed.json()["refreshed"] == 1
    after = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    assert after["attribution_pending"] is False
    assert after["sender_attribution"]["evaluated_at"]
    assert alice.post("/dashboard/api/inbox/reevaluate", json={"mail_log_ids": list(range(1, 12))}).status_code == 422


def test_same_domain_with_spf_none_collects_evidence_but_stays_unknown(
    alice, worker, signups, session, monkeypatch,
):
    from backend.services import domain_evidence
    signup = signups["shop"]
    signup.site_domain = "dailymotion.com"
    session.commit()
    def collect(domain):
        return ({"domain": domain, "checked_at": datetime.now(timezone.utc).isoformat(),
                 "dns": {"records": []},
                 "website": {"organization_claims": ["Dailymotion"],
                             "observed_url": f"https://{domain}/"},
                 "source_urls": [f"https://{domain}/"]}, 3600)
    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)
    mail_id = deliver(worker, signup.alias, 3, from_header="Dailymotion <notice@dailymotion.com>",
                      auth_results="i=1; mx.cloudflare.net; spf=none; dkim=pass; dmarc=pass")["mail_log_id"]
    log = session.get(MailLog, mail_id)
    log.sender_attribution = None
    session.commit()
    assert alice.get(f"/dashboard/api/inbox/{mail_id}").json()["attribution_pending"] is True
    assert alice.post("/dashboard/api/inbox/reevaluate", json={"mail_log_ids": [mail_id]}).status_code == 200
    attribution = alice.get(f"/dashboard/api/inbox/{mail_id}").json()["sender_attribution"]
    assert attribution["status"] == "Unknown"
    assert attribution["sender_organization"] == "Dailymotion"
    assert attribution["evidence_status"]["sender_domain"] == "Evidence collected"
    assert attribution["authentication"]["results"] == {"spf": "none", "dkim": "pass", "dmarc": "pass"}


def test_refresh_rate_limit_is_per_user(alice, bob):
    for _ in range(6):
        assert alice.post("/dashboard/api/inbox/reevaluate").status_code == 200
    assert alice.post("/dashboard/api/inbox/reevaluate").status_code == 429
    assert bob.post("/dashboard/api/inbox/reevaluate").status_code == 200
