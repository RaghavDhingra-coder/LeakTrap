"""Deterministic entity extraction from one SMS message.

Pure functions, no database and no network: links are parsed, never opened.
Everything returned is derived from the text itself; nothing is guessed to
fill gaps. Each entity carries a certainty:

- "validated": parsed and checked against a strict format (emails, URLs,
  domains, card numbers with a valid checksum);
- "pattern": matched a specific pattern (phone numbers, dates, references,
  verification codes);
- "uncertain": a heuristic (person and business names).

Sensitive values (verification codes, card numbers, account numbers and
sign-in, reset or token links) are never returned in full: their `value` is
None and their `display` is masked. `redact()` produces a copy of the text
with them replaced, which is the only form of the text that may be stored.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from backend.services.domains import normalize_domain, normalize_email

MAX_SMS_LENGTH = 2000

ENTITY_TYPES = ("email", "phone", "url", "domain", "person", "business", "reference", "date", "code", "card")

# Removed before analysis: zero-width characters and bidirectional controls,
# which can hide or reorder text.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿]")

# Bare domains (without http:// or www.) are only recognised with these
# common top-level domains, so ordinary words such as "Dr.Smith" are not
# mistaken for websites. Links with a scheme or "www." accept any TLD.
KNOWN_TLDS = (
    "com", "org", "net", "info", "biz", "io", "co", "ai", "app", "dev", "me", "us", "uk", "ca", "au", "in",
    "de", "fr", "es", "it", "nl", "be", "ch", "at", "se", "no", "dk", "fi", "ie", "nz", "za", "sg", "hk",
    "jp", "kr", "cn", "br", "mx", "ar", "ru", "pl", "pt", "gr", "tr", "ae", "sa", "ng", "ke", "pk", "bd",
    "lk", "my", "ph", "id", "vn", "th", "shop", "store", "online", "site", "xyz", "club", "health",
    "clinic", "bank", "travel", "email", "link", "live", "tech", "news", "today", "top",
    # TLDs of common link shorteners (bit.ly, goo.gl, is.gd, tiny.cc).
    "ly", "gl", "gd", "cc",
)
# Two-level public suffixes such as co.uk or com.au. A small, documented
# approximation of the Public Suffix List, which is not a dependency here.
_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "ltd", "plc", "nhs", "or", "ne", "go"}
LINK_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "t.ly",
    "rb.gy", "shorturl.at", "s.id", "tiny.cc", "lnkd.in", "bl.ink",
}
# Webmail domains say nothing about which service sent a message.
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com",
    "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}
_SENSITIVE_LINK = re.compile(
    r"reset|password|passwd|verify|verification|token|auth|login|log-in|signin|sign-in|magic|otp|"
    r"confirm|activate|session|unsubscribe|[?&](?:key|code|sig|signature|t|k)=", re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}")

# Words that look like names at the start of a sentence but are not.
GENERIC_WORDS = {
    "your", "you", "the", "hi", "hello", "hey", "dear", "thanks", "thank", "please", "reply", "stop", "text",
    "call", "msg", "message", "code", "order", "account", "appointment", "today", "tomorrow", "tonight",
    "customer", "team", "support", "bank", "service", "services", "info", "alert", "notice", "otp", "sms",
    "do", "not", "never", "share", "use", "we", "it", "this", "is", "valued", "user", "member", "client",
    "sir", "madam", "friend", "all", "there", "delivery", "parcel", "package", "payment", "verification",
    "security", "reminder", "update", "important", "urgent", "free", "win", "winner", "congratulations",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "mr", "mrs", "ms", "dr",
    "miss", "prof", "mx", "a", "an", "and", "of", "for", "on", "at", "to", "from", "with", "by", "in", "our",
    "my", "us", "click", "visit", "see", "here", "now", "link", "online", "app", "help", "details",
}
_TITLES = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)"
_CAP_WORD = r"(?:[A-Z][A-Za-z0-9&'.-]*|[A-Z]{2,})"
_BUSINESS = rf"{_CAP_WORD}(?:\s+(?:{_CAP_WORD}|&|of|and|de|la|du|the))*"
_MONTHS = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?"


@dataclass
class Entity:
    key: str
    type: str
    display: str
    certainty: str
    value: str | None = None
    sensitive: bool = False
    note: str | None = None
    start: int = 0
    end: int = 0
    meta: dict = field(default_factory=dict)


@dataclass
class Extraction:
    text: str
    entities: list[Entity]
    # Raw sensitive substrings, for redaction only. Never returned or stored.
    _secrets: list[tuple[int, int, str]] = field(default_factory=list)

    def of_type(self, *types: str) -> list[Entity]:
        return [e for e in self.entities if e.type in types]


def normalize_text(raw: str) -> str:
    """NFKC, invisible characters removed, other control characters made spaces."""
    text = unicodedata.normalize("NFKC", raw)
    text = _INVISIBLE.sub("", text)
    return "".join(ch if ch in "\n\t" or not unicodedata.category(ch).startswith("C") else " " for ch in text)


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _overlaps(taken: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < b and a < end for a, b in taken)


def mask_email(address: str) -> str:
    local, domain = address.split("@", 1)
    return f"{local[:2]}{'•' * max(1, min(len(local) - 2, 6))}@{domain}"


def mask_digits(normalized: str, keep: int = 3) -> str:
    digits = re.sub(r"\D", "", normalized)
    prefix = "+" if normalized.startswith("+") else ""
    head = digits[:2] if prefix else ""
    return f"{prefix}{head}{'•' * max(1, len(digits) - len(head) - keep)}{digits[-keep:]}"


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def normalize_phone(raw: str) -> tuple[str, str] | None:
    """(normalized, format) for a plausible phone number, else None.

    International numbers become +<digits> (E.164 length rules); numbers
    without a country prefix are kept as national digits, country unknown.
    """
    digits = re.sub(r"\D", "", raw)
    stripped = raw.strip()
    if stripped.startswith("+"):
        return (f"+{digits}", "international") if 8 <= len(digits) <= 15 else None
    if stripped.startswith("00") and 10 <= len(digits) <= 17:
        return f"+{digits[2:]}", "international"
    if 9 <= len(digits) <= 12:
        return digits, "national"
    return None


def parse_sender(raw: str | None) -> dict | None:
    """Classify the sender identifier the user typed. Raises ValueError."""
    if raw is None or not raw.strip():
        return None
    value = normalize_text(raw).strip()
    if "@" in value:
        return {"type": "email", "value": normalize_email(value), "display": mask_email(normalize_email(value))}
    compact = re.sub(r"[\s().-]", "", value)
    if re.fullmatch(r"\d{3,6}", compact):
        return {"type": "short_code", "value": compact, "display": compact}
    phone = normalize_phone(value) if re.fullmatch(r"\+?[\d\s().-]{7,24}", value) else None
    if phone:
        return {"type": "phone", "value": phone[0], "display": mask_digits(phone[0])}
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 &._-]{1,19}", value) and re.search(r"[A-Za-z]", value):
        return {"type": "alphanumeric", "value": value, "display": value}
    raise ValueError("enter a phone number, short code, alphanumeric sender ID or email address")


def sender_key(sender: dict | None) -> str | None:
    """Comparable form of a sender, for matching earlier confirmations."""
    if not sender:
        return None
    value = sender["value"]
    if sender["type"] == "alphanumeric":
        value = re.sub(r"[^a-z0-9]", "", value.lower())
    return f"{sender['type']}:{value}"


class _Builder:
    def __init__(self, text: str):
        self.text = text
        self.entities: list[Entity] = []
        self.taken: list[tuple[int, int]] = []
        self.secrets: list[tuple[int, int, str]] = []
        self.counts: dict[str, int] = {}
        self.seen: set[tuple[str, str]] = set()

    def add(self, type_: str, start: int, end: int, *, display: str, certainty: str, value: str | None = None,
            sensitive: bool = False, note: str | None = None, meta: dict | None = None, claim: bool = True) -> Entity | None:
        if claim and _overlaps(self.taken, start, end):
            return None
        if claim:
            self.taken.append((start, end))
        if sensitive:
            self.secrets.append((start, end, type_))
        dedupe = (type_, (value or display).lower())
        if dedupe in self.seen:
            return None
        self.seen.add(dedupe)
        n = self.counts.get(type_, 0)
        self.counts[type_] = n + 1
        entity = Entity(f"{type_}:{n}", type_, display, certainty, value, sensitive, note, start, end, meta or {})
        self.entities.append(entity)
        return entity


def _strip_trailing(url: str) -> str:
    while url and url[-1] in ".,;:!?'\"]}>":
        url = url[:-1]
    if url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    return url


def _link_entity(b: _Builder, raw: str, start: int, host: str, scheme: str, path: str, query: str, userinfo: bool) -> None:
    notes = []
    ip = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
    domain = None
    if not ip:
        try:
            domain = normalize_domain(host)
        except ValueError:
            return
    sensitive_reason = None
    if _SENSITIVE_LINK.search(f"{path}?{query}") or _LONG_TOKEN.search(query) or _LONG_TOKEN.search(path):
        sensitive_reason = "it looks like a sign-in, reset, verification or tracking link"
    if userinfo:
        notes.append("The link contains text before an @, which can disguise its real destination.")
    if ip:
        notes.append("The link uses a raw IP address instead of a domain name.")
    if domain and "xn--" in domain:
        notes.append("The domain uses international characters, which can imitate another domain.")
    shortener = bool(domain and registrable_domain(domain) in LINK_SHORTENERS)
    if shortener:
        notes.append("This is a link shortener: its real destination is unknown and was not opened.")
    shown_host = host if ip else domain
    if sensitive_reason:
        display, value = f"{scheme}://{shown_host}/… (link details hidden)", None
        notes.append(f"Details hidden because {sensitive_reason}.")
    else:
        short_path = path if len(path) <= 60 else f"{path[:57]}…"
        display = f"{scheme}://{shown_host}{short_path}{'?…' if query else ''}"
        value = f"{scheme}://{shown_host}{path}"
    b.add("url", start, start + len(raw), display=display, certainty="validated", value=value,
          sensitive=bool(sensitive_reason), note=" ".join(notes) or None,
          meta={"host": shown_host, "domain": registrable_domain(domain) if domain else None,
                "shortener": shortener, "ip": bool(ip)})


def _links(b: _Builder) -> None:
    for m in re.finditer(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+", b.text):
        raw = _strip_trailing(m.group(0))
        target = raw if re.match(r"(?i)https?://", raw) else f"http://{raw}"
        try:
            parts = urlsplit(target)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        scheme = parts.scheme.lower() if re.match(r"(?i)https?://", raw) else "http"
        _link_entity(b, raw, m.start(), host, scheme, parts.path, parts.query, "@" in (parts.netloc or ""))


def _emails(b: _Builder) -> None:
    for m in re.finditer(r"(?i)(?<![\w.+%-])[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}(?![\w-])", b.text):
        try:
            address = normalize_email(m.group(0))
        except ValueError:
            continue
        domain = address.split("@", 1)[1]
        b.add("email", m.start(), m.end(), display=mask_email(address), certainty="validated", value=address,
              meta={"domain": registrable_domain(domain), "freemail": registrable_domain(domain) in FREEMAIL_DOMAINS})


def _bare_domains(b: _Builder) -> None:
    tlds = "|".join(sorted(KNOWN_TLDS, key=len, reverse=True))
    pattern = rf"(?i)(?<![\w@./-])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{tlds}))(/[^\s<>\"']*)?(?![\w@-])"
    for m in re.finditer(pattern, b.text):
        raw = _strip_trailing(m.group(0))
        try:
            domain = normalize_domain(m.group(1))
        except ValueError:
            continue
        path = (m.group(2) or "")
        if path:
            path = _strip_trailing(path)
            _link_entity(b, raw, m.start(), domain, "http", path.split("?")[0], path.partition("?")[2], False)
            continue
        b.add("domain", m.start(), m.start() + len(raw), display=domain, certainty="validated", value=domain,
              meta={"domain": registrable_domain(domain), "shortener": registrable_domain(domain) in LINK_SHORTENERS})


_CODE_PATTERNS = (
    r"(?i)\b(?:verification|security|login|sign-in|one[- ]time|confirmation|access|auth(?:entication)?|2fa|otp|pass)?\s*"
    r"(?:code|otp|passcode|pin|password)\b\s*(?:is|:|=|-)?\s*(?:[^\w\n]{0,3})(?P<v>[A-Z0-9]{4,8}|[A-Z]-\d{4,8})\b",
    r"(?i)(?<![\w-])(?P<v>(?:[A-Z]-)?\d{4,8})\s+(?:is|=)\s+(?:your|the)\b[^\n.]{0,40}?\b(?:code|otp|pin|passcode|password)\b",
)


def _codes(b: _Builder) -> None:
    for pattern in _CODE_PATTERNS:
        for m in re.finditer(pattern, b.text):
            value = m.group("v")
            if not re.search(r"\d", value):
                continue
            b.add("code", m.start("v"), m.end("v"), display=f"Verification code ({len(value)} characters, hidden)",
                  certainty="pattern", sensitive=True,
                  note="Never share this code. LeakTrace does not keep it.")


def _cards(b: _Builder) -> None:
    for m in re.finditer(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", b.text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            b.add("card", m.start(), m.end(), display=f"Card number ending {digits[-4:]} (hidden)",
                  certainty="validated", sensitive=True, note="A full card number appears in this message.")


_REFERENCE = re.compile(
    r"(?i)\b(?P<kind>order|booking|appointment|appt|reservation|ref(?:erence)?|account|acct|a/c|transaction|txn|"
    r"invoice|ticket|confirmation|tracking|policy|member(?:ship)?|customer|case|claim|parcel|shipment)\b\.?"
    r"(?:\s*(?:no\.?|number|num|#|id|code|ref))?\s*[:#.]?\s*(?P<v>[A-Z0-9][A-Z0-9-]{3,23})\b"
)
_ACCOUNT_KINDS = {"account", "acct", "a/c", "customer", "member", "membership", "policy", "transaction", "txn"}


def _references(b: _Builder) -> None:
    for m in _REFERENCE.finditer(b.text):
        value = m.group("v")
        if not re.search(r"\d", value) or re.fullmatch(r"\d{1,2}", value):
            continue
        kind = m.group("kind").lower().replace("appt", "appointment").replace("a/c", "account")
        kind = {"ref": "reference", "acct": "account", "txn": "transaction", "membership": "member"}.get(kind, kind)
        account_like = kind in _ACCOUNT_KINDS
        display = f"{kind.capitalize()} ending {value[-4:]}" if account_like else f"{kind.capitalize()} {value}"
        b.add("reference", m.start("v"), m.end("v"), display=display, certainty="pattern",
              value=None if account_like else value, sensitive=account_like, meta={"kind": kind},
              note="Account-type numbers are shown masked." if account_like else None)


_DATE_PATTERNS = (
    (r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{1,2}:\d{2})?\b", None),
    (r"\b\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2})\b", "numeric"),
    (rf"(?i)\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTHS}(?:\s+\d{{4}})?\b", None),
    (rf"(?i)\b{_MONTHS}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{4}})?\b", None),
    (r"(?i)\b(?:mon|tues?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)(?:day)?\b", None),
    (r"(?i)\b(?:today|tomorrow|tonight|yesterday)\b", None),
    (r"(?i)\b\d{1,2}:\d{2}(?:\s*[ap]\.?m\.?)?(?!\d)", None),
    (r"(?i)\b\d{1,2}\s*[ap]\.?m\.?(?!\w)", None),
)


def _dates(b: _Builder) -> None:
    for pattern, kind in _DATE_PATTERNS:
        for m in re.finditer(pattern, b.text):
            note = None
            if kind == "numeric":
                first, second = (int(x) for x in re.split(r"[/.-]", m.group(0))[:2])
                if first <= 12 and second <= 12 and first != second:
                    note = "Day and month order is ambiguous."
            value = m.group(0).rstrip(".") if re.search(r"(?i)m\.$", m.group(0)) else m.group(0)
            b.add("date", m.start(), m.start() + len(value), display=value, certainty="pattern", value=value, note=note)


def _phones(b: _Builder) -> None:
    for m in re.finditer(r"(?<![\w+])(?:\+|00)?\(?\d[\d\s().-]{5,22}\d(?!\w)", b.text):
        raw = m.group(0).strip()
        if re.search(r"\d\.\d{2}$", raw) or re.search(r"\n", raw):
            continue  # amounts, or digits on separate lines
        phone = normalize_phone(raw)
        if not phone:
            continue
        normalized, fmt = phone
        b.add("phone", m.start(), m.start() + len(m.group(0).rstrip()), display=mask_digits(normalized),
              certainty="pattern", value=normalized,
              note=None if fmt == "international" else "No country code: the country is unknown.", meta={"format": fmt})


# Only these are trimmed from the edges of a candidate name; other generic
# words ("Bank", "Parcel") can be part of a real brand and are kept.
_LEADING = {"the", "your", "our", "my", "a", "an", "dear", "hi", "hello", "hey", "thanks", "thank", "you"}
_TRAILING = {"reply", "stop", "msg", "sms", "otp", "code", "today", "tomorrow", "now", "please", "team", "support"}


def _clean_name(raw: str) -> str | None:
    words = raw.strip(" .,:;!-'").split()
    while words and words[0].lower() in _LEADING:
        words = words[1:]
    while words and words[-1].lower().strip(".") in _TRAILING:
        words = words[:-1]
    name = " ".join(words).strip(" .,:;!-'")
    if len(name) < 3 or not re.search(r"[A-Za-z]{2}", name):
        return None
    if all(w.lower().strip(".") in GENERIC_WORDS for w in name.split()):
        return None
    return name


_BUSINESS_PATTERNS = (
    # "Example Shop: your order…" or "[Example Shop] …" at the start.
    (rf"^\s*\[?(?P<n>{_BUSINESS})\]?\s*:\s", "named at the start of the message"),
    (rf"^\s*\[(?P<n>{_BUSINESS})\]", "named at the start of the message"),
    # "appointment at Example Clinic", "a message from Example Bank".
    (rf"\b(?:at|from|with|by|this is|welcome to|thank you for choosing|thanks for choosing)\s+(?P<n>{_BUSINESS})", "named in the message"),
    # "your Example code", "the Example Shop order".
    (rf"\b(?:your|the)\s+(?P<n>{_BUSINESS})\s+(?:verification code|code|order|account|appointment|booking|password|login|app|card|delivery|parcel)\b", "named in the message"),
    # "Example Shop Team", "Example Support".
    (rf"\b(?P<n>{_BUSINESS})\s+(?:Team|Support|Customer Care|Customer Service|Services)\b", "named in a sign-off"),
    # "Thanks, Example Shop" or "- Example Shop" at the end.
    (rf"(?:Thanks|Regards|Cheers|Thank you|Kind regards),?\s+(?P<n>{_BUSINESS})\s*[.!]?\s*$", "named in a sign-off"),
    (rf"(?:^|\s)[-–—]\s*(?P<n>{_BUSINESS})\s*$", "named in a sign-off"),
)


def _businesses(b: _Builder) -> None:
    for pattern, where in _BUSINESS_PATTERNS:
        for m in re.finditer(pattern, b.text, flags=re.MULTILINE):
            name = _clean_name(m.group("n"))
            if not name:
                continue
            offset = m.group("n").find(name)
            start = m.start("n") + max(offset, 0)
            b.add("business", start, start + len(name), display=name, certainty="uncertain", value=name,
                  note=f"Heuristic: {where}.", claim=False)


_PERSON = re.compile(
    rf"\b(?:(?:Hi|Hello|Hey|Dear|Hiya|Good (?:morning|afternoon|evening))\s+(?:{_TITLES}\.?\s+)?|{_TITLES}\.?\s+)"
    r"(?P<n>[A-Z][a-z'-]{1,30}(?:\s+[A-Z][a-z'-]{1,30})?)\b"
)


def _people(b: _Builder) -> None:
    businesses = {e.value.lower() for e in b.entities if e.type == "business"}
    for m in _PERSON.finditer(b.text):
        name = m.group("n")
        words = [w for w in name.split() if w.lower() not in GENERIC_WORDS]
        name = " ".join(words)
        if not name or name.lower() in businesses or any(name.lower() in biz for biz in businesses):
            continue
        b.add("person", m.start("n"), m.start("n") + len(m.group("n")), display=name, certainty="uncertain",
              value=name, note="Heuristic: from a greeting or title.", claim=False)


def extract(raw: str) -> Extraction:
    """Extract entities. Order matters: earlier extractors claim their text
    so later ones (e.g. phone numbers) cannot reuse it."""
    text = normalize_text(raw)[:MAX_SMS_LENGTH]
    b = _Builder(text)
    for step in (_links, _emails, _bare_domains, _codes, _cards, _references, _dates, _phones, _businesses, _people):
        step(b)
    b.entities.sort(key=lambda e: (e.start, e.type))
    return Extraction(text, b.entities, b.secrets)


_PLACEHOLDERS = {"code": "[code hidden]", "card": "[card number hidden]", "url": "[link hidden]",
                 "reference": "[account number hidden]"}


def redact(extraction: Extraction) -> str:
    """The text with every sensitive value replaced by a placeholder."""
    text = extraction.text
    for start, end, type_ in sorted(extraction._secrets, reverse=True):
        text = text[:start] + _PLACEHOLDERS.get(type_, "[hidden]") + text[end:]
    return text


def excerpt(extraction: Extraction, start: int, end: int, radius: int = 32) -> str:
    """A short, redacted quotation around a span, for showing evidence."""
    lo, hi = max(0, start - radius), min(len(extraction.text), end + radius)
    pieces = []
    cursor = lo
    for s, e, type_ in sorted(extraction._secrets):
        if e <= lo or s >= hi:
            continue
        pieces.append(extraction.text[cursor:max(s, cursor)])
        pieces.append(_PLACEHOLDERS.get(type_, "[hidden]"))
        cursor = max(cursor, e)
    pieces.append(extraction.text[cursor:hi])
    quote = " ".join("".join(pieces).split())
    return f"{'…' if lo > 0 else ''}{quote}{'…' if hi < len(extraction.text) else ''}"
