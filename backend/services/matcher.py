"""Leak matcher: compare clues from a suspicious email with stored signups.

A match links a message to a LeakTrace signup. It never shows that the site
leaked, sold or shared data: addresses can be guessed or forged, mail can be
legitimately sent by the site itself, and nicknames can be common words.

The rules below are deterministic and use only exact, normalized comparisons.
"""

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.models import Incident, Signup
from backend.services.domains import parent_domains

logger = logging.getLogger("leaktrace.matcher")

# Confidence describes how strongly the clues tie the message to one signup.
# It is never a statement about whether a leak happened.
CONFIDENCE_ORDER = ("none", "low", "medium", "high")

# Strength of each signal on its own. A candidate's confidence is the
# strongest signal it has; extra weaker signals add explanation, not rank.
SIGNAL_CONFIDENCE = {
    # Each generated alias is unique and was given to exactly one site, so a
    # message addressed to it is tied to that signup. (How the sender got the
    # address is a separate question; see the warnings.)
    "alias_exact": "high",
    # Nicknames are unique within an owner's scope but are ordinary words
    # that could appear by coincidence, so they can never reach "high".
    "nickname_exact": "medium",
    # Surname variants are user-chosen and not unique; weak on their own.
    "surname_variant_exact": "low",
    # Any sender can claim any domain, and the site emailing its own users is
    # normal. On its own this only says which signup the sender relates to.
    "sender_domain": "low",
}

# Never return more candidates than this, to limit what one request reveals.
MAX_CANDIDATES = 10

LIMITATIONS = (
    "A match links this message to a LeakTrace signup. It is not proof that the "
    "site leaked, sold or shared your data.",
    "Sender addresses and domains can be forged.",
    "Short random aliases on a shared domain can be guessed; an alias match shows "
    "which address was used, not how the sender obtained it.",
    "Only exact, case-insensitive comparisons are made; misspelled or altered "
    "markers are not detected.",
    "There is no authentication yet: user_id is not verified, so results are only "
    "suitable for single-user local use.",
)


class SignupLike(Protocol):
    id: int
    site_name: str
    site_domain: str | None
    alias: str | None
    nickname: str | None
    surname_variant: str | None


@dataclass(frozen=True)
class Clues:
    """Normalized clues. Email values are lowercase; text clues are lowercased
    with collapsed whitespace."""

    recipient: str | None = None
    sender: str | None = None
    subject: str | None = None
    nickname: str | None = None
    surname_variant: str | None = None
    user_id: int | None = None

    @property
    def sender_domain(self) -> str | None:
        return self.sender.split("@", 1)[1] if self.sender else None


@dataclass
class Signal:
    type: str
    explanation: str


@dataclass
class Candidate:
    signup_id: int
    site_name: str
    site_domain: str | None
    confidence: str
    signals: list[Signal]


@dataclass
class MatchResult:
    status: str  # "matched", "ambiguous" or "no_match"
    confidence: str
    matches: list[Candidate]
    warnings: list[str] = field(default_factory=list)
    limitations: tuple[str, ...] = LIMITATIONS
    incident_id: int | None = None


def _lower(value: str | None) -> str | None:
    return " ".join(value.split()).lower() if value else None


def _word_in(text: str, word: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(word)}(?!\w)", text, re.IGNORECASE) is not None


def _signals_for(signup: SignupLike, clues: Clues) -> list[Signal]:
    signals: list[Signal] = []
    if clues.recipient and _lower(signup.alias) == clues.recipient:
        signals.append(Signal(
            "alias_exact", "The recipient address is the alias generated for this signup."
        ))

    nickname = _lower(signup.nickname)
    if nickname:
        sources = []
        if clues.nickname == nickname:
            sources.append("the nickname clue")
        if clues.subject and _word_in(clues.subject, nickname):
            sources.append("the subject line")
        if sources:
            # One underlying marker, however many places it appears.
            signals.append(Signal(
                "nickname_exact",
                f"The nickname assigned to this signup appears in {' and '.join(sources)}.",
            ))

    if clues.surname_variant and _lower(signup.surname_variant) == clues.surname_variant:
        signals.append(Signal(
            "surname_variant_exact",
            "The surname clue equals the surname variant given to this site. Surname "
            "variants are not unique, so this is weak evidence.",
        ))

    sender_domain = clues.sender_domain
    if sender_domain and signup.site_domain and signup.site_domain in parent_domains(sender_domain):
        signals.append(Signal(
            "sender_domain",
            "The sender's domain belongs to this signup's site domain. The site emailing "
            "its own users is normal, and sender domains can be forged.",
        ))
    return signals


def _rank(confidence: str) -> int:
    return CONFIDENCE_ORDER.index(confidence)


def _candidate_warnings(candidate: Candidate, signup: SignupLike, clues: Clues) -> list[str]:
    types = {s.type for s in candidate.signals}
    if "alias_exact" not in types or not clues.sender_domain:
        return []
    label = f"signup {candidate.signup_id} ({candidate.site_name})"
    if "sender_domain" in types:
        return [
            f"For {label}, the sender appears to be the site itself. This is likely the "
            "site's own mail, not evidence that the address was shared."
        ]
    if signup.site_domain:
        return [
            f"For {label}, mail to this alias came from a domain not associated with the "
            "site. That is consistent with the address having been shared, leaked or "
            "guessed, but does not prove which."
        ]
    return [
        f"{label.capitalize()} has no site domain recorded, so the sender cannot be "
        "compared with the site."
    ]


def score(signups: Iterable[SignupLike], clues: Clues) -> MatchResult:
    """Score candidate signups against clues. Pure and deterministic: the same
    inputs always give the same result, regardless of input order."""
    scored: list[tuple[Candidate, SignupLike]] = []
    for signup in signups:
        signals = _signals_for(signup, clues)
        if not signals:
            continue
        confidence = max((SIGNAL_CONFIDENCE[s.type] for s in signals), key=_rank)
        scored.append((
            Candidate(signup.id, signup.site_name, signup.site_domain, confidence, signals),
            signup,
        ))

    # Strongest first; signup id breaks ties so ordering is stable.
    scored.sort(key=lambda pair: (-_rank(pair[0].confidence), pair[0].signup_id))
    warnings: list[str] = []
    if len(scored) > MAX_CANDIDATES:
        warnings.append(f"Only the first {MAX_CANDIDATES} matching signups are shown.")
        scored = scored[:MAX_CANDIDATES]

    candidates = [candidate for candidate, _ in scored]
    if not candidates:
        if clues.recipient:
            warnings.append(
                "The recipient address does not match any alias in this scope. It may "
                "belong to another owner, have been deleted, or never have been issued."
            )
        return MatchResult("no_match", "none", [], warnings)

    for candidate, signup in scored:
        warnings.extend(_candidate_warnings(candidate, signup, clues))

    top = candidates[0].confidence
    if len(candidates) == 1:
        return MatchResult("matched", top, candidates, warnings)

    # Clues point at more than one signup. Lower the overall confidence one
    # step (never below "low") because the clues disagree or are not unique.
    warnings.append(
        f"The clues match {len(candidates)} different signups, so the result is ambiguous."
    )
    overall = CONFIDENCE_ORDER[max(_rank(top) - 1, _rank("low"))]
    return MatchResult("ambiguous", overall, candidates, warnings)


def find_candidates(session: Session, clues: Clues) -> Sequence[Signup]:
    """Signups in the caller's ownership scope that share at least one clue.

    The scope mirrors the nickname uniqueness rule: signups of the given user,
    or signups without a user when no user_id is given. Other owners' signups
    are never considered.
    """
    conditions = []
    if clues.recipient:
        conditions.append(func.lower(Signup.alias) == clues.recipient)
    if clues.nickname:
        conditions.append(func.lower(Signup.nickname) == clues.nickname)
    if clues.surname_variant:
        conditions.append(func.lower(Signup.surname_variant) == clues.surname_variant)
    if clues.sender_domain:
        conditions.append(Signup.site_domain.in_(parent_domains(clues.sender_domain)))
    if not conditions:
        return []

    owner = Signup.user_id.is_(None) if clues.user_id is None else Signup.user_id == clues.user_id
    query = (
        select(Signup)
        .where(owner, or_(*conditions))
        .order_by(Signup.id)
        .limit(MAX_CANDIDATES + 1)  # one extra so score() can report truncation
    )
    return session.scalars(query).all()


def check(session: Session, clues: Clues) -> MatchResult:
    result = score(find_candidates(session, clues), clues)
    # Log the outcome only, never addresses, subjects or other clue values.
    logger.info("Matcher check: status=%s confidence=%s candidates=%d",
                result.status, result.confidence, len(result.matches))
    return result


def record_incident(session: Session, clues: Clues, result: MatchResult) -> Incident:
    """Save the result as a suspected incident (caller opted in) and commit.

    Stores signal types and signup ids, not the subject, nickname, surname or
    sender address. result is the matcher status, never "confirmed".
    """
    incident = Incident(
        user_id=clues.user_id,
        channel="email",
        result=result.status,
        matched_site=result.matches[0].site_name if result.status == "matched" else None,
        confidence=result.confidence,
        evidence={
            "source": "matcher",
            "recipient_alias_matched": any(
                s.type == "alias_exact" for m in result.matches for s in m.signals
            ),
            "sender_domain": clues.sender_domain,
            "candidates": [
                {
                    "signup_id": m.signup_id,
                    "confidence": m.confidence,
                    "signals": [s.type for s in m.signals],
                }
                for m in result.matches
            ],
        },
    )
    try:
        session.add(incident)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return incident
