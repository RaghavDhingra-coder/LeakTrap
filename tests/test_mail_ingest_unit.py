"""Email ingestion: authentication, payload limits and validation, parsing.
No database needed: these requests are rejected before any query runs."""

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from backend.database import get_db
from backend.main import app
from backend.routes.ingest import IngestConfig, get_ingest_config
from backend.schemas.mail_ingest import MailIngestRequest
from backend.services.mail_ingest import (
    InboundMail,
    decode_subject,
    dedup_hash,
    parse_auth_results,
    parse_from_header,
    parse_sender_name,
)

SECRET = "t" * 48
CONFIG = IngestConfig(secret=SECRET, max_bytes=16384, alias_domain="leaktrap.xyz")
AUTH = {"Authorization": f"Bearer {SECRET}"}
VALID = {
    "recipient": "ab12@leaktrap.xyz",
    "envelope_from": "bounce@mailer.example",
    "from_header": "Deals <deals@broker.example>",
    "subject": "Hi Ocelot",
    "message_id": "<abc@mailer.example>",
}
SENSITIVE = ["ab12@leaktrap.xyz", "bounce@mailer.example", "deals@broker.example", "Ocelot",
             "abc@mailer.example", SECRET]


class BrokenSession:
    def scalar(self, *args, **kwargs):
        raise OperationalError("SELECT", {}, Exception("connection refused"))


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = lambda: None
    app.dependency_overrides[get_ingest_config] = lambda: CONFIG
    yield TestClient(app)
    app.dependency_overrides.clear()


def post(client, body, headers=AUTH, **kwargs):
    return client.post("/ingest/email", json=body, headers=headers, **kwargs)


def assert_no_sensitive(text: str) -> None:
    for value in SENSITIVE:
        assert value.lower() not in text.lower(), value


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": ""}, {"Authorization": "Bearer"}, {"Authorization": "Bearer wrong"},
     {"Authorization": f"Basic {SECRET}"}, {"Authorization": f"Bearer {SECRET}x"},
     {"Authorization": f"Bearer {SECRET[:-1]}"}, {"X-Api-Key": SECRET}],
)
def test_missing_or_wrong_secret_is_401(client, headers) -> None:
    response = post(client, VALID, headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"detail": "Invalid or missing credentials."}


@pytest.mark.parametrize("secret", [None, "", "too-short"])
def test_unconfigured_or_weak_secret_disables_ingestion(client, secret) -> None:
    app.dependency_overrides[get_ingest_config] = lambda: IngestConfig(secret, 16384, "leaktrap.xyz")
    response = post(client, VALID, headers={"Authorization": f"Bearer {secret}"})
    assert response.status_code == 503


def test_auth_is_checked_before_the_body_is_read(client) -> None:
    response = client.post("/ingest/email", content=b"x" * 100_000, headers={"content-type": "application/json"})
    assert response.status_code == 401


def test_oversized_body_is_413(client) -> None:
    big = {**VALID, "subject": "x" * 20_000}
    response = post(client, big)
    assert response.status_code == 413


def test_oversized_streamed_body_without_content_length_is_413(client) -> None:
    def chunks():
        for _ in range(40):
            yield b"x" * 1024

    response = client.post("/ingest/email", content=chunks(), headers={**AUTH, "content-type": "application/json"})
    assert response.status_code == 413


def test_non_json_content_type_is_415(client) -> None:
    response = client.post("/ingest/email", content=json.dumps(VALID),
                           headers={**AUTH, "content-type": "text/plain"})
    assert response.status_code == 415


@pytest.mark.parametrize(
    "body",
    [{}, {"recipient": "not-an-email"}, {"recipient": "Name <ab12@leaktrap.xyz>"},
     {**VALID, "envelope_from": "bad address"}, {**VALID, "message_id": "two tokens"},
     {**VALID, "message_id": "  "}, {**VALID, "subject": "x" * 999},
     {**VALID, "received_at": "2026-10-22T10:00:00"},  # no timezone
     {**VALID, "body": "full message text"}, {**VALID, "spf": "pass"},
     {**VALID, "verified_by_cloudflare": True}, {**VALID, "user_id": 1}, [VALID]],
)
def test_malformed_payload_is_422_without_echoing_input(client, body) -> None:
    response = post(client, body)
    assert response.status_code == 422
    assert_no_sensitive(response.text)
    assert all(set(e) == {"loc", "msg"} for e in response.json()["detail"])


def test_invalid_json_is_422(client) -> None:
    response = client.post("/ingest/email", content=b"{not json", headers={**AUTH, "content-type": "application/json"})
    assert response.status_code == 422


@pytest.mark.parametrize("offset", [timedelta(hours=1), -timedelta(days=31)])
def test_received_at_outside_window_is_422(client, offset) -> None:
    when = (datetime.now(timezone.utc) + offset).isoformat()
    assert post(client, {**VALID, "received_at": when}).status_code == 422


@pytest.mark.parametrize(
    "recipient", ["ab12@example.com", "ab12@sub.leaktrap.xyz", "ab12@leaktrap.xyz.evil.com",
                  "ab12@leaktrap.xy"],
)
def test_recipient_outside_alias_domain_is_422(client, recipient) -> None:
    response = post(client, {**VALID, "recipient": recipient})
    assert response.status_code == 422
    assert response.json() == {"detail": "Recipient is not at the alias domain."}


def test_missing_alias_domain_is_503(client) -> None:
    app.dependency_overrides[get_ingest_config] = lambda: IngestConfig(SECRET, 16384, None)
    assert post(client, VALID).status_code == 503


def test_database_error_is_503_without_details(client) -> None:
    app.dependency_overrides[get_db] = lambda: BrokenSession()
    response = post(client, VALID)
    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable."}


def test_rejections_do_not_log_sensitive_values(client, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    post(client, VALID, headers={"Authorization": "Bearer wrong"})
    post(client, {**VALID, "recipient": "ab12@example.com"})
    post(client, {**VALID, "envelope_from": "bad address"})
    app.dependency_overrides[get_db] = lambda: BrokenSession()
    post(client, VALID)
    assert_no_sensitive(caplog.text)


def test_worker_and_backend_agree_on_payload_fields() -> None:
    source = (Path(__file__).resolve().parent.parent / "worker/src/index.js").read_text()
    block = re.search(r"PAYLOAD_FIELDS = \[(.*?)\]", source, re.S).group(1)
    worker_fields = re.findall(r'"(\w+)"', block)
    assert worker_fields == list(MailIngestRequest.model_fields)


@pytest.mark.parametrize(
    ("header", "expected"),
    [("Deals <Deals@Broker.Example>", "deals@broker.example"),
     ("deals@broker.example", "deals@broker.example"),
     ('"Odd, Name" <x@shop.example.com>', "x@shop.example.com"),
     ("not an address", None), ("<>", None), ("", None), (None, None),
     ("Evil <x@127.0.0.1>", None)],
)
def test_parse_from_header(header, expected) -> None:
    assert parse_from_header(header) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("=?UTF-8?B?SGkgT2NlbG90?=", "Hi Ocelot"), ("Hi\tthere\r\n  friend", "Hi there friend"),
     ("=?bogus?Q?broken", "=?bogus?Q?broken"), ("   ", None), (None, None)],
)
def test_decode_subject(raw, expected) -> None:
    assert decode_subject(raw) == expected


def test_dedup_hash_prefers_message_id_and_is_stable() -> None:
    now = datetime.now(timezone.utc)
    a = InboundMail("ab12@leaktrap.xyz", None, None, "Hi", "abc@x", now)
    b = InboundMail("ab12@leaktrap.xyz", "z@y.example", None, "Other", "abc@x", now + timedelta(1))
    c = InboundMail("ab12@leaktrap.xyz", None, None, "Hi", None, now)
    d = InboundMail("ab12@leaktrap.xyz", None, None, "Hi", None, now + timedelta(1))
    assert dedup_hash(a) == dedup_hash(b)  # same Message-ID
    assert dedup_hash(c) == dedup_hash(d)  # same fields, retried later
    assert dedup_hash(a) != dedup_hash(c)
    assert re.fullmatch(r"[0-9a-f]{64}", dedup_hash(a))
    assert "abc" not in dedup_hash(a)

    # The same message delivered to a second alias is a separate copy.
    other = InboundMail("cd34@leaktrap.xyz", None, None, "Hi", "abc@x", now)
    assert dedup_hash(a) != dedup_hash(other)


@pytest.mark.parametrize(
    ("header", "expected"),
    [("Deals <deals@broker.example>", "Deals"), ('"Odd, Name" <x@shop.example.com>', "Odd, Name"),
     ("=?UTF-8?B?Q2Fmw6k=?= <x@shop.example.com>", "Café"), ("deals@broker.example", None),
     ('"support@bank.example" <x@evil.example>', None),  # an address as a name would mislead
     ("Bad\x07Name <x@shop.example.com>", "Bad Name"), ("Name <not-an-address>", None),
     ("N" * 500 + " <x@shop.example.com>", "N" * 200), (None, None), ("", None)],
)
def test_parse_sender_name(header, expected) -> None:
    assert parse_sender_name(header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [("i=1; mx.cloudflare.net; dkim=pass header.d=a.example; spf=pass smtp.mailfrom=b@a.example; dmarc=pass",
      "spf=pass dkim=pass dmarc=pass"),
     ("i=1; MX.Cloudflare.NET; spf=SoftFail", "spf=softfail"),
     ("i=1; mx.cloudflare.net; dkim=fail; dkim=pass", "dkim=fail"),
     ("i=1; mx.cloudflare.net; arc=none", None),
     ("i=1; mx.cloudflare.net.evil.example; spf=pass", None),
     ("i=1; evil.example; spf=pass, i=1; mx.cloudflare.net; spf=pass", None),  # topmost instance only
     ("spf=pass dkim=pass", None), ("", None), (None, None)],
)
def test_parse_auth_results(header, expected) -> None:
    assert parse_auth_results(header) == expected
