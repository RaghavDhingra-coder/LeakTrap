"""A site's recorded markers can suggest exposure without claiming a confirmed leak."""
import pytest

from backend.models import MailLog, Signup
from tests.auth_support import mobile_token
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver  # noqa: F401
from tests.test_sms_api import sites, analyze  # noqa: F401

pytestmark = pytest.mark.integration


def test_external_sender_to_facebook_alias_has_same_dashboard_mobile_signal(alice, worker, signups, accounts, session):
    signups["shop"].site_name = "Facebook"
    signups["shop"].site_domain = "facebook.com"
    session.commit()
    delivered = deliver(worker, signups["shop"].alias, 31,
                        from_header="Mayur <mayur@gmail.com>", subject="Hi Alice")
    mail_id = delivered["mail_log_id"]
    token = mobile_token(session, accounts["alice"], scopes=("email:read",))
    web = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    inbox = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    phone = worker.get(f"/mobile/v1/emails/{mail_id}", headers={"Authorization": f"Bearer {token}"}).json()
    assert web["status"] == inbox["status"] == phone["status"] == "matched"
    assert web["exposure"] == inbox["exposure"] == phone["exposure"]
    [signal] = web["exposure"]
    assert (signal["site_name"], signal["marker_type"], signal["observed_source"], signal["expected_domain"]) == (
        "Facebook", "recipient_alias", "gmail.com", "facebook.com")
    assert "possible source" in signal["explanation"]
    assert "does not prove" in signal["caveat"]
    assert signal["signup_id"] == signups["shop"].id
    assert worker.get(f"/mobile/v1/emails/{mail_id}", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_new_email_mobile_list_matches_dashboard_inbox_evidence(alice, worker, signups, accounts, session):
    signups["shop"].site_name = "Facebook"
    signups["shop"].site_domain = "facebook.com"
    session.commit()
    mail_id = deliver(worker, signups["shop"].alias, 36,
                      from_header="Mayur <mayur@gmail.com>", subject="Hi Alice")["mail_log_id"]
    token = mobile_token(session, accounts["alice"], scopes=("email:read",))
    headers = {"Authorization": f"Bearer {token}"}
    mobile = worker.get("/mobile/v1/emails", headers=headers).json()
    inbox = alice.get("/dashboard/api/inbox").json()
    row = next(item for item in mobile["items"] if item["id"] == mail_id)
    web = next(item for item in inbox["items"] if item["id"] == mail_id)
    for field in ("status", "alias", "site_name", "subject", "sender_email", "auth_results", "exposure"):
        assert row[field] == web[field]
    assert row["exposure"][0]["site_name"] == "Facebook"
    assert row["sender_email"] == "mayur@gmail.com"


def test_mobile_email_pages_are_newest_first_and_scoped(alice, bob, worker, signups, accounts, session):
    older = deliver(worker, signups["shop"].alias, 37)["mail_log_id"]
    newer = deliver(worker, signups["shop"].alias, 38)["mail_log_id"]
    alice_token = mobile_token(session, accounts["alice"], scopes=("email:read",))
    bob_token = mobile_token(session, accounts["bob"], scopes=("email:read",))
    auth = {"Authorization": f"Bearer {alice_token}"}
    first = worker.get("/mobile/v1/emails", params={"limit": 1, "offset": 0}, headers=auth).json()
    second = worker.get("/mobile/v1/emails", params={"limit": 1, "offset": 1}, headers=auth).json()
    assert first["total"] == second["total"] == 2
    assert [first["items"][0]["id"], second["items"][0]["id"]] == [newer, older]
    assert worker.get("/mobile/v1/emails", headers={"Authorization": f"Bearer {bob_token}"}).json()["items"] == []
    assert worker.get(f"/mobile/v1/emails/{newer}", headers={"Authorization": f"Bearer {bob_token}"}).status_code == 404


def test_mobile_website_pages_follow_dashboard_edits_and_deletes(alice, worker, signups, accounts, session):
    token = mobile_token(session, accounts["alice"], scopes=("websites:read",))
    auth = {"Authorization": f"Bearer {token}"}
    signups["shop"].alias = "changed123@leaktrap.xyz"
    added = Signup(user_id=accounts["alice"].id, site_name="New Site", site_domain="new.example",
                   alias="newsite1@leaktrap.xyz", nickname="Ember")
    session.add(added)
    session.commit()
    pages = [worker.get("/mobile/v1/websites", params={"limit": 1, "offset": i}, headers=auth).json()
             for i in range(3)]
    mobile = [page["items"][0] for page in pages]
    web = alice.get("/dashboard/api/signups", params={"limit": 100}).json()["items"]
    assert [(row["id"], row["alias"], row["nickname"]) for row in mobile] == [
        (row["id"], row["alias"], row["nickname"]) for row in web]
    assert next(row for row in mobile if row["id"] == signups["shop"].id)["alias"] == "changed123@leaktrap.xyz"
    session.delete(added)
    session.commit()
    assert added.id not in [row["id"] for row in worker.get("/mobile/v1/websites", headers=auth).json()["items"]]


def test_own_sender_and_legacy_or_failed_records_have_no_exposure(alice, worker, signups, session):
    own = deliver(worker, signups["shop"].alias, 32,
                  from_header="Shop <notice@shop.example.com>")["mail_log_id"]
    own_data = alice.get(f"/dashboard/api/emails/{own}").json()
    assert own_data["exposure"] == []
    row = session.get(MailLog, own)
    row.ingest_status = None
    session.commit()
    assert alice.get(f"/dashboard/api/emails/{own}").json()["exposure"] == []
    row.ingest_status = "failed"
    session.commit()
    assert alice.get(f"/dashboard/api/emails/{own}").json()["exposure"] == []


def test_nickname_in_subject_suggests_second_site_without_changing_recipient_attribution(alice, worker, signups, session):
    signups["news"].site_name = "Amazon"
    signups["news"].site_domain = "amazon.com"
    signups["news"].nickname = "Alice"
    session.commit()
    mail_id = deliver(worker, signups["shop"].alias, 33,
                      from_header="Mayur <mayur@gmail.com>", subject="Hello Alice, your order")["mail_log_id"]
    row = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    assert row["site_name"] == signups["shop"].site_name
    assert {(e["site_name"], e["marker_type"]) for e in row["exposure"]} == {
        ("Example Shop", "recipient_alias"), ("Amazon", "nickname_mention")}
    nickname = next(e for e in row["exposure"] if e["site_name"] == "Amazon")
    assert nickname["confidence"] == "low"


def test_cross_user_nickname_never_leaks_through_email(alice, worker, signups, session):
    mail_id = deliver(worker, signups["shop"].alias, 34,
                      from_header="Mayur <mayur@gmail.com>", subject="Hello Kestrel")["mail_log_id"]
    row = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    assert all(x["signup_id"] != signups["bob"].id for x in row["exposure"])
    assert "Bob Forum" not in str(row)


def test_sms_nickname_from_unverified_sender_suggests_amazon_without_claiming_leak(alice, sites, session):
    sites["clinic"].site_name = "Amazon"
    sites["clinic"].site_domain = "amazon.com"
    sites["clinic"].nickname = "Alice"
    session.commit()
    result = analyze(alice, "Hi Alice, your delivery is waiting at https://parcel.example", sender="mayur@gmail.com")
    source = next(x for x in result["risk"]["exposure"] if x["site_name"] == "Amazon")
    assert source["marker_type"] == "nickname_mention"
    assert source["observed_source"] == "parcel.example"
    assert source["confidence"] == "low"
    assert "does not prove" in source["caveat"]
    assert result["status"] in ("possible", "strong")
    # Scam risk is a separate assessment from the possible source.
    assert result["risk"]["assessment"] in ("Suspicious", "Inconclusive", "Likely scam")


def test_sms_expected_site_link_and_other_users_marker_do_not_suggest_exposure(alice, sites):
    own = analyze(alice, "Hi Ocelot, see https://exampleclinic.com/appointments", sender="ExmplClinic")
    assert own["risk"]["exposure"] == []
    other = analyze(alice, "Hello Kestrel, check your message", sender="unknown")
    assert all(x["signup_id"] != sites["bob"].id for x in other["risk"]["exposure"])


def test_sms_nickname_with_email_sender_and_no_link_is_a_weak_possible_source(alice, sites, session):
    sites["clinic"].site_name = "Amazon"
    sites["clinic"].site_domain = "amazon.com"
    sites["clinic"].nickname = "Alice"
    session.commit()
    result = analyze(alice, "Hello Alice, your package is ready", sender="mayur@gmail.com")
    signal = next(x for x in result["risk"]["exposure"] if x["site_name"] == "Amazon")
    assert signal["marker_type"] == "nickname_mention"
    assert signal["observed_source"] == "gmail.com"
    assert signal["confidence"] == "low"
    assert "cannot be verified" in signal["explanation"]
    assert result["risk"]["assessment"] == "Inconclusive"


def test_sender_subdomain_of_recorded_site_has_no_email_exposure(alice, worker, signups):
    mail_id = deliver(worker, signups["shop"].alias, 35,
                      from_header="Shop <notify@mail.shop.example.com>")["mail_log_id"]
    row = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    assert row["status"] == "matched"
    assert row["exposure"] == []


def test_alias_without_recorded_site_domain_is_possible_but_unverified(alice, worker, signups):
    mail_id = deliver(worker, signups["news"].alias, 36,
                      from_header="Mayur <mayur@gmail.com>")["mail_log_id"]
    row = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    [signal] = row["exposure"]
    assert signal["site_name"] == "Daily News"
    assert signal["expected_domain"] is None
    assert signal["confidence"] == "low"
    assert "cannot be compared" in signal["explanation"]
