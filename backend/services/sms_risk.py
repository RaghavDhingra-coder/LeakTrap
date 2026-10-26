"""Conservative risk assessment layered on LeakTrace's extracted SMS evidence.

Source association and scam risk are independent. No URL is fetched and no
sender is authenticated here. A clean heuristic result is inconclusive, never
proof of safety. Reasons contain redacted link displays or domains, not codes.
"""

import re
from difflib import SequenceMatcher

from backend.services.sms_extract import registrable_domain

_URGENCY = re.compile(r"\b(?:urgent|immediately|act now|last chance|within\s+\d+\s+(?:minutes?|hours?)|expires?\s+(?:today|soon))\b", re.I)
_THREAT = re.compile(r"\b(?:account|card|service)\s+(?:(?:has been|will be|is)\s+)?(?:suspended|locked|blocked|closed)\b|\bunusual activity\b", re.I)
_REQUEST = re.compile(r"\b(?:send|share|reply\s+with|enter|provide|confirm|submit|verify)\b.{0,40}\b(?:password|passcode|one[ -]time\s+(?:code|password)|otp|cvv|pin|verification\s+code|card\s+number|bank\s+details)\b", re.I)
_NEGATED = re.compile(r"(?:do\s+not|don't|never)\s+$", re.I)
_PAYMENT = re.compile(r"\b(?:pay|send)\b.{0,25}\b(?:fee|deposit|money|amount)\b|\b(?:claim|collect)\b.{0,30}\b(?:prize|reward|winnings)\b", re.I)


def assess(extraction, entities, excluded, candidates, signups) -> dict:
    active = [e for e in entities if e.key not in excluded]
    links = [e for e in active if e.type == "url"]
    reasons = []

    def add(code, message, evidence=None):
        if not any(r["code"] == code and r["evidence"] == evidence for r in reasons):
            reasons.append({"code": code, "message": message, "evidence": evidence})

    text = extraction.text
    if _URGENCY.search(text):
        add("urgency", "The message pressures you to act quickly.")
    if _THREAT.search(text):
        add("account_threat", "The message threatens account or service access.")
    if any(not _NEGATED.search(text[max(0, m.start()-20):m.start()]) for m in _REQUEST.finditer(text)):
        add("sensitive_request", "It asks for credentials, a verification code or financial information.")
    if _PAYMENT.search(text):
        add("payment_request", "It asks for payment or offers a prize; verify independently before responding.")
    expected_domains = {registrable_domain(s.site_domain) for s in signups if s.site_domain}
    for link in links:
        meta = link.meta
        host = meta.get("host") or ""
        domain = meta.get("domain") or host
        if meta.get("userinfo"):
            add("deceptive_url", "Text before @ can disguise the link's actual destination.", host)
        if meta.get("ip"):
            add("ip_url", "The link uses an IP address rather than a named website.", host)
        if meta.get("shortener"):
            add("shortened_url", "A shortened link hides its destination; it has not been opened.", host)
        if meta.get("scheme") == "http":
            add("insecure_url", "The link does not use HTTPS.", host)
        if "xn--" in host:
            add("international_domain", "International characters can imitate another domain; verify the spelling.", host)
        for expected in expected_domains:
            if domain == expected:
                continue
            stem, known = domain.split('.')[0], expected.split('.')[0]
            if (host.startswith(expected + ".") or
                (len(known) >= 4 and len(stem) >= 4 and
                 (stem.translate(str.maketrans("0135", "oles")) == known or
                  SequenceMatcher(None, domain, expected).ratio() >= .88))):
                add("lookalike_domain", "This link resembles one of your registered domains but is different.", f"{host} (expected {expected})")
    for candidate in candidates:
        types = {s.type for s in candidate.signals}
        if candidate.signup_id and candidate.domain and types & {"alias_in_message", "nickname_in_message", "name_in_message", "sender_id_name"}:
            expected = registrable_domain(candidate.domain)
            conflicts = [e.meta.get("host") for e in links if e.meta.get("domain") and e.meta["domain"] != expected]
            if conflicts:
                add("source_conflict", "This message does not match your known source. It may be a scam. Avoid clicking links until verified.",
                    f"{', '.join(sorted(set(conflicts)))} (registered: {expected})")
    codes = {r["code"] for r in reasons}
    high = "sensitive_request" in codes and bool(codes & {"deceptive_url", "lookalike_domain"})
    high = high or {"sensitive_request", "urgency", "source_conflict"} <= codes
    assessment = "Likely scam" if high else "Suspicious" if reasons else "Inconclusive"
    return {
        "assessment": assessment, "risk_level": "high" if high else "moderate" if reasons else "unknown",
        "reasons": reasons, "urls": [e.display for e in links],
        "domains": sorted({e.meta["host"] for e in links if e.meta.get("host")}),
        "next_steps": ["Do not share passwords, verification codes or payment details.",
                       "Open the service's official app or a saved website address to verify the message.",
                       "Block or report suspicious messages using your SMS app." ] if reasons else
                      ["No supported warning signs were found. This does not establish that the message is safe.",
                       "Verify unexpected requests through the service's official app or a known contact."],
        "notice": "Sender identity is unverified. Alias or nickname references are clues, not proof of a scam or data leak.",
    }
