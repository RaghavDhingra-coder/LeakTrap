"""Email ingestion against a live PostgreSQL test database (TEST_DATABASE_URL).

Most tests run in a rolled-back transaction. The concurrency test commits real
rows and deletes exactly those rows afterwards.
"""

import logging
import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from backend.database import get_db
from backend.main import app
from backend.models import MailLog, Signup, User
from backend.routes.ingest import IngestConfig, get_ingest_config
from backend.services import mail_ingest

pytestmark = pytest.mark.integration

SECRET = "k" * 48
AUTH = {"Authorization": f"Bearer {SECRET}"}


@pytest.fixture
def client(session: Session):
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_ingest_config] = lambda: IngestConfig(SECRET, 16384, "leaktrap.xyz")
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


@pytest.fixture
def signups(session: Session) -> dict[str, Signup]:
    alice, bob = User(), User()
    session.add_all([alice, bob])
    session.flush()
    rows = {
        "alice_shop": Signup(user_id=alice.id, site_name="Example Shop", site_domain="shop.example.com",
                             alias="ab12@leaktrap.xyz", nickname="Ocelot"),
        "alice_news": Signup(user_id=alice.id, site_name="Daily News", site_domain="news.example.org",
                             alias="cd34@leaktrap.xyz"),
        # Bob has a signup at the same domain the sender claims; it must never be searched.
        "bob_broker": Signup(user_id=bob.id, site_name="Broker", site_domain="broker.example",
                             alias="ef56@leaktrap.xyz", nickname="Kestrel"),
    }
    session.add_all(rows.values())
    session.commit()
    return rows


def ingest(client, **fields):
    body = {"recipient": "ab12@leaktrap.xyz", "envelope_from": "bounce@mailer.example",
            "from_header": "Deals <deals@broker.example>", "subject": "Hi Ocelot",
            "message_id": "<m1@mailer.example>", **fields}
    return client.post("/ingest/email", json=body, headers=AUTH)


def mail_logs(session: Session) -> list[MailLog]:
    session.expire_all()
    return session.scalars(select(MailLog).order_by(MailLog.id)).all()


CLOUDFLARE_AUTH = ("i=1; mx.cloudflare.net; dkim=pass header.d=broker.example; "
                   "spf=pass smtp.mailfrom=bounce@mailer.example; dmarc=fail header.from=broker.example")


def test_attributed_ingestion_stores_inbox_record(client, session, signups) -> None:
    received = "2026-10-22T08:00:00+00:00"
    response = ingest(client, received_at=received, auth_results=CLOUDFLARE_AUTH)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "accepted"
    assert body["recipient_known"] is True
    assert (body["ingest_status"], body["status_reason"]) == ("matched", None)
    assert (body["match_status"], body["match_confidence"]) == ("matched", "high")
    assert set(body) == {"status", "mail_log_id", "recipient_known", "ingest_status", "status_reason",
                         "match_status", "match_confidence"}

    [log] = mail_logs(session)
    assert log.id == body["mail_log_id"]
    assert log.signup_id == signups["alice_shop"].id
    assert log.user_id == signups["alice_shop"].user_id
    assert log.alias == "ab12@leaktrap.xyz"
    assert (log.sender_name, log.sender, log.subject) == ("Deals", "deals@broker.example", "Hi Ocelot")
    assert log.sender_domain == "broker.example"  # From header, not the envelope
    assert log.auth_results == "spf=pass dkim=pass dmarc=fail"
    assert (log.ingest_status, log.status_reason, log.read_at) == ("matched", None, None)
    assert log.is_spam is False
    assert len(log.message_id_hash) == 64 and "m1" not in log.message_id_hash
    assert log.received_at == datetime(2026, 10, 22, 8, tzinfo=timezone.utc)
    assert (log.match_status, log.match_confidence) == ("matched", "high")


def test_recipient_is_matched_exactly_and_never_guessed(client, session, signups) -> None:
    assert ingest(client, recipient="AB12@LeakTrap.XYZ", message_id="<c1@x>").json()["ingest_status"] == "matched"
    for i, lookalike in enumerate(["ab12+promo@leaktrap.xyz", "ab12x@leaktrap.xyz", "ab1@leaktrap.xyz",
                                   "a.b12@leaktrap.xyz"]):
        body = ingest(client, recipient=lookalike, message_id=f"<g{i}@x>").json()
        assert (body["ingest_status"], body["status_reason"], body["recipient_known"]) == (
            "unmatched", "unknown_alias", False), lookalike
    logs = mail_logs(session)
    assert [log.user_id is not None for log in logs] == [True, False, False, False, False]


def test_same_message_to_several_aliases_is_kept_once_per_alias(client, session, signups) -> None:
    """One message to Alice and Bob arrives as one delivery per envelope recipient,
    with the same Message-ID. Each owner gets their own record."""
    first = ingest(client, recipient="ab12@leaktrap.xyz")
    second = ingest(client, recipient="ef56@leaktrap.xyz")
    retry = ingest(client, recipient="ef56@leaktrap.xyz")
    assert (first.status_code, second.status_code, retry.status_code) == (201, 201, 200)
    assert retry.json()["mail_log_id"] == second.json()["mail_log_id"]
    by_user = {log.user_id: log for log in mail_logs(session)}
    assert set(by_user) == {signups["alice_shop"].user_id, signups["bob_broker"].user_id}
    assert by_user[signups["bob_broker"].user_id].signup_id == signups["bob_broker"].id


def test_forged_or_foreign_authentication_results_are_ignored(client, session, signups) -> None:
    ingest(client, auth_results="i=1; mx.evil.example; spf=pass dkim=pass dmarc=pass")
    ingest(client, message_id="<m2@x>", auth_results="spf=pass dkim=pass")
    ingest(client, message_id="<m3@x>", auth_results="i=1; mx.cloudflare.net; spf=softfail, i=1; mx.cloudflare.net; spf=pass")
    assert [log.auth_results for log in mail_logs(session)] == [None, None, "spf=softfail"]
    too_long = ingest(client, message_id="<m4@x>", auth_results="a" * 2001)
    assert too_long.status_code == 422


def test_envelope_sender_used_when_from_header_unusable(client, session, signups) -> None:
    ingest(client, from_header="garbage")
    assert mail_logs(session)[0].sender_domain == "mailer.example"


def test_retry_with_same_message_id_is_idempotent(client, session, signups) -> None:
    first = ingest(client)
    retry = ingest(client, subject="different subject on retry")
    assert first.status_code == 201
    assert retry.status_code == 200
    assert retry.json()["status"] == "duplicate"
    assert retry.json()["mail_log_id"] == first.json()["mail_log_id"]
    assert retry.json()["match_status"] == "matched"
    assert len(mail_logs(session)) == 1


def test_messages_without_message_id_dedupe_on_fields(client, session, signups) -> None:
    assert ingest(client, message_id=None).status_code == 201
    assert ingest(client, message_id=None).status_code == 200
    assert ingest(client, message_id=None, subject="Another").status_code == 201
    assert len(mail_logs(session)) == 2


def test_unknown_alias_is_recorded_without_searching(client, session, signups, monkeypatch) -> None:
    called = []
    monkeypatch.setattr(mail_ingest.matcher, "check", lambda *a, **k: called.append(1))
    response = ingest(client, recipient="zz99@leaktrap.xyz", subject="Hi Kestrel")
    assert response.status_code == 201
    body = response.json()
    assert body["recipient_known"] is False
    assert (body["ingest_status"], body["status_reason"]) == ("unmatched", "unknown_alias")
    assert (body["match_status"], body["match_confidence"]) == ("no_match", "none")
    assert called == []  # no broadened search across owners
    [log] = mail_logs(session)
    assert log.signup_id is None and log.user_id is None
    # Nobody can see this record, so no message details are kept.
    assert (log.sender, log.sender_name, log.subject, log.auth_results) == (None, None, None, None)
    assert (log.alias, log.sender_domain) == ("zz99@leaktrap.xyz", "broker.example")


def test_matching_stays_within_alias_owner(client, session, signups) -> None:
    # Sender domain and subject nickname belong to Bob's signup; mail is to Alice's alias.
    response = ingest(client, subject="Hi Kestrel")
    assert (response.json()["match_status"], response.json()["match_confidence"]) == ("matched", "high")
    assert "Broker" not in response.text and "Kestrel" not in response.text


def test_sender_domain_matching_another_own_signup_is_ambiguous(client, session, signups) -> None:
    response = ingest(client, from_header="news@news.example.org", subject="Hello")
    assert response.json()["match_status"] == "ambiguous"
    assert response.json()["match_confidence"] == "medium"


def test_unowned_alias_scope(client, session) -> None:
    session.add(Signup(site_name="Anon Shop", site_domain="anon.example", alias="aa11@leaktrap.xyz"))
    session.commit()
    body = ingest(client, recipient="aa11@leaktrap.xyz", from_header="x@anon.example").json()
    assert (body["match_status"], body["recipient_known"]) == ("no_match", True)
    assert (body["ingest_status"], body["status_reason"]) == ("unmatched", "unowned_alias")
    [log] = mail_logs(session)
    assert log.user_id is None and log.subject is None and log.sender is None


def test_analysis_failure_is_recorded_as_failed_and_retried(client, session, signups, monkeypatch) -> None:
    real_check = mail_ingest.matcher.check

    def explode(*args, **kwargs):
        raise RuntimeError("matcher bug")

    monkeypatch.setattr(mail_ingest.matcher, "check", explode)
    response = ingest(client)
    assert response.status_code == 201
    assert "matcher bug" not in response.text
    body = response.json()
    assert (body["ingest_status"], body["status_reason"], body["match_status"]) == ("failed", "analysis_failed", None)
    [log] = mail_logs(session)
    assert log.user_id == signups["alice_shop"].user_id and log.subject == "Hi Ocelot"  # still in the inbox

    assert ingest(client).json()["status"] == "duplicate"  # still failing: unchanged
    monkeypatch.setattr(mail_ingest.matcher, "check", real_check)
    retry = ingest(client)
    assert (retry.status_code, retry.json()["status"], retry.json()["mail_log_id"]) == (200, "reprocessed", log.id)
    [log] = mail_logs(session)
    assert (log.ingest_status, log.status_reason, log.match_status) == ("matched", None, "matched")
    assert ingest(client).json()["status"] == "duplicate"


def test_database_failure_during_analysis_stores_nothing(client, session, signups, monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        raise OperationalError("SELECT", {}, Exception("connection refused"))

    monkeypatch.setattr(mail_ingest.matcher, "check", unavailable)
    response = ingest(client)
    assert response.status_code == 503  # the Worker then forwards or retries
    assert mail_logs(session) == []


def test_logs_never_contain_addresses_subjects_or_secret(client, session, signups, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    ingest(client)
    ingest(client)  # duplicate
    ingest(client, recipient="zz99@leaktrap.xyz", message_id="<m2@x.example>")
    text = caplog.text.lower()
    for value in ["ab12@leaktrap.xyz", "zz99", "bounce@mailer.example", "deals@broker.example",
                  "hi ocelot", "m1@mailer.example", SECRET, "deals <"]:
        assert value not in text, value
    assert "mail_log_id=" in text


def test_concurrent_retries_store_one_row(engine: Engine, monkeypatch) -> None:
    """Four deliveries of the same message race. All pass the duplicate check
    before any inserts (forced with a barrier), so PostgreSQL's unique index
    decides: one is accepted, the rest are reported as duplicates."""
    make_session = sessionmaker(bind=engine, expire_on_commit=False)
    with make_session() as s:
        user = User()
        s.add(user)
        s.flush()
        signup = Signup(user_id=user.id, site_name="Race Shop", alias="rr77@leaktrap.xyz")
        s.add(signup)
        s.commit()

    barrier = threading.Barrier(4)
    real_check = mail_ingest.matcher.check

    def synchronized_check(*args, **kwargs):
        result = real_check(*args, **kwargs)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(mail_ingest.matcher, "check", synchronized_check)
    mail = mail_ingest.InboundMail("rr77@leaktrap.xyz", "a@b.example", None, None, "race@x",
                                   datetime.now(timezone.utc))
    outcomes, errors = [], []

    def worker() -> None:
        with make_session() as s:
            try:
                outcomes.append(mail_ingest.process(s, mail))
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

    try:
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, errors
        assert sorted(o.duplicate for o in outcomes) == [False, True, True, True]
        assert len({o.mail_log_id for o in outcomes}) == 1
        with make_session() as s:
            assert s.scalar(select(func.count()).where(MailLog.signup_id == signup.id)) == 1
    finally:
        with make_session() as s:
            s.execute(delete(MailLog).where(MailLog.signup_id == signup.id))
            s.execute(delete(Signup).where(Signup.id == signup.id))
            s.execute(delete(User).where(User.id == user.id))
            s.commit()
