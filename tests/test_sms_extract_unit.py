"""SMS entity extraction and redaction (backend/services/sms_extract.py).
Synthetic messages and fictional data only; no database."""

import time

import pytest

from backend.services.sms_extract import extract, excerpt, normalize_phone, parse_sender, redact, sender_key


def entities(text: str, type_: str | None = None) -> list:
    return [e for e in extract(text).entities if type_ is None or e.type == type_]


def values(text: str, type_: str) -> list:
    return [e.value for e in entities(text, type_)]


# ---------- emails ----------

def test_emails_are_validated_normalized_and_masked() -> None:
    [e] = entities("Contact Appointments@ExampleClinic.com today.", "email")
    assert (e.value, e.certainty, e.display) == ("appointments@exampleclinic.com", "validated", "ap••••••@exampleclinic.com")
    assert e.meta == {"domain": "exampleclinic.com", "freemail": False}
    assert entities("write to someone@gmail.com", "email")[0].meta["freemail"] is True
    assert values("bad@@x.com, no@tld, @example.com", "email") == []


# ---------- phone numbers ----------

@pytest.mark.parametrize(("text", "expected"), [
    ("Call +44 20 7946 0958 now", ("+442079460958", "international")),
    ("Call 0044 20 7946 0958", ("+442079460958", "international")),
    ("Ring +1 (555) 010-0199.", ("+15550100199", "international")),
    ("Call 0207 946 0123 if not you", ("02079460123", "national")),
    ("Text 98765 43210", ("9876543210", "national")),
])
def test_phone_numbers(text, expected) -> None:
    [e] = entities(text, "phone")
    assert (e.value, e.meta["format"]) == expected
    assert e.display.endswith(expected[0][-3:]) and expected[0] not in e.display
    if expected[1] == "national":
        assert "country is unknown" in e.note


@pytest.mark.parametrize("text", [
    "Pay 1234.56 by Friday", "Your code is 482913", "Order 12345 shipped", "Due 2026-10-24 or 24/10/2026",
    "Call 12345", "+12 34",
])
def test_things_that_are_not_phone_numbers(text) -> None:
    assert values(text, "phone") == []


def test_normalize_phone_limits() -> None:
    assert normalize_phone("+1234567890123456") is None  # 16 digits: longer than E.164
    assert normalize_phone("+4420794609") == ("+4420794609", "international")


# ---------- links and domains ----------

def test_links_with_scheme_or_www_and_bare_domains() -> None:
    text = "See https://Shop.Example.com/orders/12?ref=sms or www.exampleclinic.com and dailynews.example.org today."
    urls = entities(text, "url")
    assert [u.display for u in urls] == ["https://shop.example.com/orders/12?…", "http://www.exampleclinic.com"]
    assert urls[0].value == "https://shop.example.com/orders/12"  # query string never kept
    assert urls[0].meta["domain"] == "example.com" and urls[1].meta["domain"] == "exampleclinic.com"
    assert values(text, "domain") == ["dailynews.example.org"]


def test_registrable_domain_handles_two_level_suffixes() -> None:
    [u] = entities("Visit https://book.clinic.example.co.uk/a", "url")
    assert u.meta["domain"] == "example.co.uk"


@pytest.mark.parametrize("text", ["Dr.Smith will see you", "e.g. today", "file.txt attached", "v2.0 is out"])
def test_ordinary_words_are_not_domains(text) -> None:
    assert entities(text, "domain") == [] and entities(text, "url") == []


def test_suspicious_link_features_are_noted_not_followed() -> None:
    [short] = entities("Track: bit.ly/3xYzQ1", "url")
    assert short.meta["shortener"] and "not opened" in short.note
    [ip] = entities("Login at http://203.0.113.9/acct", "url")
    assert ip.meta["ip"] and "raw IP address" in ip.note
    [trick] = entities("Go to https://shop.example.com@evil.example/x", "url")
    assert trick.meta["host"] == "evil.example" and "disguise" in trick.note
    [idn] = entities("Visit https://xn--exmple-cua.com/", "url")
    assert "international characters" in idn.note


# ---------- sensitive values ----------

@pytest.mark.parametrize("text", [
    "123456 is your Example Shop verification code.",
    "Your verification code is 482913. Do not share it.",
    "Use code: A1B2C3 to sign in",
    "G-482913 is your Google verification code",
    "Your OTP is 4829",
])
def test_verification_codes_are_hidden(text) -> None:
    [code] = entities(text, "code")
    assert code.sensitive and code.value is None and "hidden" in code.display
    hidden = redact(extract(text))
    assert "[code hidden]" in hidden
    for secret in ("123456", "482913", "A1B2C3", "4829"):
        assert secret not in hidden


def test_reset_links_card_and_account_numbers_are_hidden() -> None:
    text = ("Reset your password: https://shop.example.com/reset?token=abcdEFGH1234ijklMNOP . "
            "Card 4111 1111 1111 1111 charged. Account no 12345678. Order #A1B2C3")
    found = {e.type: e for e in entities(text)}
    assert found["url"].value is None and found["url"].display == "https://shop.example.com/… (link details hidden)"
    assert found["card"].display == "Card number ending 1111 (hidden)" and found["card"].value is None
    refs = {e.meta["kind"]: e for e in entities(text, "reference")}
    assert refs["account"].display == "Account ending 5678" and refs["account"].value is None
    assert refs["order"].value == "A1B2C3" and not refs["order"].sensitive  # order numbers are not credentials
    hidden = redact(extract(text))
    for secret in ("abcdEFGH1234ijklMNOP", "4111 1111 1111 1111", "12345678"):
        assert secret not in hidden
    assert "Order #A1B2C3" in hidden


def test_non_luhn_digit_runs_are_not_cards() -> None:
    assert entities("Ref 1234 5678 9012 3456", "card") == []


def test_excerpts_never_reveal_hidden_values() -> None:
    ex = extract("Hi, 123456 is your Example Shop code. Reset: https://shop.example.com/reset?token=abcdEFGH1234ijklMNOP")
    business = next(e for e in ex.entities if e.type == "business")
    quote = excerpt(ex, business.start, business.end, radius=200)
    assert "123456" not in quote and "abcdEFGH" not in quote and "[code hidden]" in quote


# ---------- names, dates ----------

def test_business_and_person_names_are_uncertain_heuristics() -> None:
    text = "Hi Alice Smith, your appointment at Example Clinic is confirmed. Thanks, Example Bank"
    assert values(text, "business") == ["Example Clinic", "Example Bank"]
    assert values(text, "person") == ["Alice Smith"]
    assert {e.certainty for e in entities(text) if e.type in ("business", "person")} == {"uncertain"}
    assert values("[Daily News] Breaking story", "business") == ["Daily News"]
    assert values("Parcel on its way - Parcel Express", "business") == ["Parcel Express"]


@pytest.mark.parametrize("text", [
    "Thanks for choosing The Bank. Reply STOP to opt out.", "Dear Customer, your account is ready.",
    "Hello there, it's me", "Hey, are we still on for tonight?",
])
def test_generic_words_are_not_names(text) -> None:
    assert entities(text, "business") == [] and entities(text, "person") == []


def test_dates_and_times_with_ambiguity_noted() -> None:
    text = "Confirmed for 12 Oct at 3:30pm, or 2026-10-24, or 04/05/2026, tomorrow."
    dates = entities(text, "date")
    assert [d.value for d in dates] == ["12 Oct", "3:30pm", "2026-10-24", "04/05/2026", "tomorrow"]
    assert "ambiguous" in next(d for d in dates if d.value == "04/05/2026").note


# ---------- normalisation, senders, adversarial input ----------

def test_invisible_and_fullwidth_characters_are_normalized() -> None:
    text = "Contact ap​pointments@exampleclinic.com or call ＋４４ 20 7946 0958"
    assert values(text, "email") == ["appointments@exampleclinic.com"]
    assert values(text, "phone") == ["+442079460958"]


def test_markup_is_plain_text() -> None:
    text = '<script>alert("x")</script> <img src=x onerror=alert(1)> visit https://shop.example.com/a'
    ex = extract(text)
    assert [e.type for e in ex.entities] == ["url"]
    assert ex.text == text  # kept as text; the dashboard renders it with textContent only


def test_input_is_capped_and_pathological_input_is_fast() -> None:
    assert len(extract("a" * 5000).text) == 2000
    for nasty in ("1 " * 1000, "a." * 1000, "+" + "(1" * 999, "Hi " + "A" * 1990, "@" * 2000, "x@" * 1000):
        start = time.perf_counter()
        extract(nasty)
        assert time.perf_counter() - start < 1.0, nasty[:10]


@pytest.mark.parametrize(("raw", "type_", "value"), [
    ("+44 7700 900123", "phone", "+447700900123"), ("62820", "short_code", "62820"),
    ("ExampleClnc", "alphanumeric", "ExampleClnc"), ("Alerts@Example.com", "email", "alerts@example.com"),
])
def test_sender_identifiers(raw, type_, value) -> None:
    sender = parse_sender(raw)
    assert (sender["type"], sender["value"]) == (type_, value)
    assert parse_sender(None) is None and parse_sender("  ") is None


def test_sender_keys_ignore_case_and_spacing_for_sender_ids() -> None:
    assert sender_key(parse_sender("Example Clinic")) == sender_key(parse_sender("EXAMPLE-CLINIC")) == "alphanumeric:exampleclinic"


@pytest.mark.parametrize("raw", ["??", "a", "<script>", "x" * 30, "12"])
def test_invalid_senders(raw) -> None:
    with pytest.raises(ValueError):
        parse_sender(raw)
