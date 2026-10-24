"""Dashboard validation messages and responsive-layout rules.

Real 422 bodies from the API are run through the dashboard's own formatter
(backend/dashboard/app.js) in Node. No database is needed: these requests fail
validation before any query runs.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.database import get_db
from backend.main import app
from tests.auth_support import FAKE_HEADERS, fake_auth
from backend.routes.dashboard import DashboardConfig, get_dashboard_config

DASHBOARD = Path(__file__).resolve().parent.parent / "backend/dashboard"
NODE = shutil.which("node")

# Loads app.js with a stub document, then formats each 422 detail list from stdin.
FORMATTER = """
const vm = require("node:vm");
const fs = require("node:fs");
const context = { document: { addEventListener() {} }, Intl, console };
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + `
  globalThis.__format = (detail) => {
    const errors = validationErrors(detail);
    return { message: validationSummary(errors), fields: errors.map((e) => e.field).filter(Boolean) };
  };`, context);
const cases = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(cases.map((detail) => context.__format(detail))));
"""


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = lambda: None
    fake_auth(app)
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    yield TestClient(app, client=("127.0.0.1", 50000), headers=FAKE_HEADERS)
    app.dependency_overrides.clear()


def format_details(details: list) -> list[dict]:
    if NODE is None:
        pytest.skip("node is not installed")
    result = subprocess.run(
        [NODE, "-e", FORMATTER, str(DASHBOARD / "app.js")],
        input=json.dumps(details), capture_output=True, text=True, timeout=30, check=True,
    )
    return json.loads(result.stdout)


def detail_of(response) -> list:
    assert response.status_code == 422, response.text
    return response.json()["detail"]


RECEIPT = {"signup_id": 1, "action": "accepted", "source_url": "https://shop.example.com/privacy"}


def test_receipt_form_errors_name_the_field_and_reason(client) -> None:
    cases = [
        ({**RECEIPT, "source_url": "javascript:alert(1)"},
         "Privacy notice URL: must be an http or https URL with a host.", ["source_url"]),
        ({**RECEIPT, "action": "verified"},
         "What you did: Input should be 'accepted', 'declined' or 'notice_only'.", ["action"]),
        ({**RECEIPT, "notice_version": "v" * 101}, "Notice version: must be at most 100 characters.", ["notice_version"]),
        ({**RECEIPT, "reported_occurred_at": "2026-10-01T10:00:00"},
         "When it happened: Input should have timezone info.", ["reported_occurred_at"]),
        ({"signup_id": 1, "action": "accepted"},
         "Provide at least one of Privacy notice URL, Notice text hash, Notice text, Notice version or "
         "Consent prompt wording.", []),
    ]
    details = [detail_of(client.post("/consent-receipts", json=body)) for body, _, _ in cases]
    for (_, message, fields), formatted in zip(cases, format_details(details)):
        assert formatted == {"message": message, "fields": fields}


def test_match_check_errors_never_echo_submitted_values(client) -> None:
    secret_looking = "Name <someone.private@example.com>"
    details = [
        detail_of(client.post("/matcher/check", json={"recipient": secret_looking})),
        detail_of(client.post("/matcher/check", json={})),
        detail_of(client.post("/matcher/check", json={"sender": "bad", "subject": "x" * 999})),
    ]
    assert secret_looking in json.dumps(details[0])  # FastAPI's raw detail does echo the input
    recipient, missing, several = format_details(details)
    assert recipient == {"message": "Recipient address: email address has an invalid local part.", "fields": ["recipient"]}
    assert "someone.private" not in json.dumps([recipient, missing, several])
    assert missing["message"] == "Provide at least one of Recipient address, Sender address, Nickname or Surname."
    assert several["fields"] == ["sender", "subject"]
    assert several["message"].startswith("Sender address: must be a single email address")
    assert "Subject: must be at most 998 characters" in several["message"]


def test_query_parameter_errors_name_the_parameter(client) -> None:
    [limit, status] = format_details([
        detail_of(client.get("/dashboard/api/signups", params={"limit": 0})),
        detail_of(client.get("/dashboard/api/emails", params={"status": "confirmed_leak"})),
    ])
    assert limit == {"message": "Page size: Input should be greater than or equal to 1.", "fields": ["limit"]}
    assert status["fields"] == ["status"] and status["message"].startswith("Status filter: Input should be")


def test_many_errors_are_summarised() -> None:
    detail = [{"loc": ["body", f"field_{i}"], "msg": "bad"} for i in range(5)]
    [formatted] = format_details([detail])
    assert formatted["message"].endswith("; and 2 more.")
    assert len(formatted["fields"]) == 5


def test_malformed_detail_items_do_not_break_formatting() -> None:
    [formatted] = format_details([[None, "text", {"msg": "Value error, something is wrong"}, {"loc": "x"}]])
    assert formatted["message"] == "Something is wrong; Is invalid."
    assert formatted["fields"] == []


def test_generic_message_is_gone() -> None:
    assert "Some values are invalid" not in (DASHBOARD / "app.js").read_text()


def rule(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, selector
    return match.group(1)


def test_responsive_layout_rules() -> None:
    css = (DASHBOARD / "styles.css").read_text()
    # Screen-reader-only text inside tables stays within the scrolling wrapper.
    assert "position: relative" in rule(css, ".table-wrap")
    assert "overflow-x: auto" in rule(css, ".table-wrap")
    # Long unbroken values wrap inside detail panels instead of widening them.
    assert "minmax(0, max-content) minmax(0, 1fr)" in rule(css, ".detail dl")
    assert "overflow-wrap: anywhere" in rule(css, ".detail dd")
    assert "overflow-wrap: anywhere" in rule(css, ".detail, .result")
    # Overflow is not hidden globally.
    for selector in ("body", "html", "main"):
        match = re.search(rf"(^|\n){selector}\s*\{{([^}}]*)\}}", css)
        assert not match or "overflow" not in match.group(2), selector


def test_messages_that_end_with_a_full_stop_are_not_doubled() -> None:
    [one, two] = format_details([[{"loc": ["password"], "msg": "Use at least 12 characters."}],
                                 [{"loc": ["password"], "msg": "Too short."}, {"loc": ["email"], "msg": "Invalid."}]])
    assert one["message"] == "Password: Use at least 12 characters."
    assert two["message"] == "Password: Too short; Email: Invalid."


def test_hidden_attribute_always_hides() -> None:
    # Rules such as ".count { display: inline-block }" would otherwise show hidden elements.
    css = (DASHBOARD / "styles.css").read_text()
    assert "display: none !important" in rule(css, "[hidden]")
