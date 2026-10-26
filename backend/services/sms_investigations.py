"""Saved SMS investigations, stored in the existing incidents table.

incidents.channel already allows "sms" (migration 0001), so no schema change
is needed. Saving is always the user's explicit choice. What is stored:

- channel "sms", the overall status (result) and the confirmed or strongest
  service name (matched_site);
- evidence: the sender identifier, user-entered date and label, entity counts,
  service domains and names, each candidate's status and signal types, the
  user's confirmations and rejections, the reviewed flag, and a SHA-256
  deduplication key;
- message_text: only when the user asks, and only the redacted text (codes,
  card and account numbers and sensitive links replaced).

Extracted email addresses, phone numbers and person names are not stored.
Every query is limited to the authenticated user's rows.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import Incident, Signup
from backend.services import sms_extract
from backend.services.ownership import owned_by
from backend.services.sms_investigate import STATUS_ORDER, Analysis

EVIDENCE_SOURCE = "sms_analyzer"


@dataclass(frozen=True)
class SaveResult:
    incident: Incident
    duplicate: bool


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence(analysis: Analysis) -> dict:
    active = [e for e in analysis.entities if e.key not in analysis.excluded]
    domains = sorted({e.meta["domain"] for e in active if e.type in ("url", "domain", "email")
                      and e.meta.get("domain") and not e.meta.get("freemail")})
    return {
        "source": EVIDENCE_SOURCE,
        "version": 2,
        "risk": analysis.risk,
        "dedup": analysis.dedup_key,
        "sender": {"type": analysis.sender["type"], "value": analysis.sender["value"]} if analysis.sender else None,
        "sender_key": sms_extract.sender_key(analysis.sender),
        "received_at": analysis.received_at.isoformat() if analysis.received_at else None,
        "label": analysis.label,
        "entity_counts": dict(Counter(e.type for e in active)),
        "domains": domains,
        "services": [c.name for c in analysis.candidates if c.signup_id is None],
        "candidates": [
            {"key": c.key, "name": c.name, "domain": c.domain, "signup_id": c.signup_id, "status": c.status,
             "signals": [s.type for s in c.signals]}
            for c in analysis.candidates
        ],
        "missing": analysis.missing,
        "confirmed": None,
        "rejected": [],
        "reviewed": False,
        "reviewed_at": None,
    }


def _top_name(analysis: Analysis) -> str | None:
    strong = [c for c in analysis.candidates if c.status == "strong"]
    return strong[0].name if len(strong) == 1 else None


def save(session: Session, user_id: int, analysis: Analysis, *, store_text: bool) -> SaveResult:
    existing = session.scalar(
        select(Incident).where(owned_by(Incident.user_id, user_id), Incident.channel == "sms",
                               Incident.evidence["dedup"].astext == analysis.dedup_key)
    )
    if existing is not None:
        return SaveResult(existing, True)
    incident = Incident(
        user_id=user_id, channel="sms", result=analysis.status, matched_site=_top_name(analysis), confidence=None,
        message_text=sms_extract.redact(analysis.extraction) if store_text else None,
        evidence=_evidence(analysis),
    )
    try:
        session.add(incident)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return SaveResult(incident, False)


def _query(user_id: int):
    return select(Incident).where(owned_by(Incident.user_id, user_id), Incident.channel == "sms",
                                  Incident.evidence["source"].astext == EVIDENCE_SOURCE)


def list_saved(session: Session, user_id: int, limit: int, offset: int) -> tuple[list[Incident], int]:
    query = _query(user_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit).offset(offset)).all()
    return list(rows), total


def get(session: Session, user_id: int, incident_id: int) -> Incident | None:
    return session.scalar(_query(user_id).where(Incident.id == incident_id))


class ActionError(ValueError):
    pass


def _recompute(evidence: dict) -> tuple[str, str | None]:
    if evidence.get("confirmed"):
        return "confirmed", evidence["confirmed"]["name"]
    rejected = set(evidence.get("rejected") or [])
    remaining = [c for c in evidence.get("candidates", []) if c["key"] not in rejected]
    strong = [c for c in remaining if c["status"] == "strong"]
    if len(strong) == 1:
        return "strong", strong[0]["name"]
    if strong or remaining:
        return "possible", None
    return "unknown", None


def apply_action(session: Session, user_id: int, incident: Incident, action: str, *,
                 candidate_key: str | None = None, signup_id: int | None = None) -> Incident:
    """confirm / reject / clear / reviewed / unreviewed. Raises ActionError."""
    evidence = dict(incident.evidence or {})
    candidates = {c["key"]: c for c in evidence.get("candidates", [])}
    rejected = list(evidence.get("rejected") or [])
    if action == "confirm":
        if signup_id is not None:
            signup = session.scalar(select(Signup).where(Signup.id == signup_id, owned_by(Signup.user_id, user_id)))
            if signup is None:
                raise ActionError("That website was not found.")
            key = f"signup:{signup.id}"
            evidence["confirmed"] = {"key": key, "signup_id": signup.id, "name": signup.site_name,
                                     "manual": key not in candidates, "at": _now()}
        elif candidate_key in candidates:
            c = candidates[candidate_key]
            evidence["confirmed"] = {"key": c["key"], "signup_id": c["signup_id"], "name": c["name"],
                                     "manual": False, "at": _now()}
        else:
            raise ActionError("Choose one of the suggested services or one of your websites.")
        rejected = [k for k in rejected if k != evidence["confirmed"]["key"]]
    elif action == "reject":
        if candidate_key not in candidates:
            raise ActionError("That service is not one of the suggestions for this message.")
        if candidate_key not in rejected:
            rejected.append(candidate_key)
        if (evidence.get("confirmed") or {}).get("key") == candidate_key:
            evidence["confirmed"] = None
    elif action == "clear":
        evidence["confirmed"] = None
        rejected = []
    elif action in ("reviewed", "unreviewed"):
        evidence["reviewed"] = action == "reviewed"
        evidence["reviewed_at"] = _now() if action == "reviewed" else None
    else:
        raise ActionError("Unknown action.")
    evidence["rejected"] = rejected
    incident.evidence = evidence  # reassigned so the JSONB change is saved
    incident.result, incident.matched_site = _recompute(evidence)
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise
    return incident


def delete(session: Session, user_id: int, incident_id: int) -> bool:
    incident = get(session, user_id, incident_id)
    if incident is None:
        return False
    try:
        session.delete(incident)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return True


def linked_to_signup(session: Session, user_id: int, signup_id: int, limit: int = 20) -> list[Incident]:
    """Saved SMS investigations that suggested or confirmed this website."""
    query = _query(user_id).where(
        Incident.evidence.contains({"candidates": [{"signup_id": signup_id}]})
        | Incident.evidence.contains({"confirmed": {"signup_id": signup_id}})
    )
    return list(session.scalars(query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit)).all())


def status_rank(status: str | None) -> int:
    return STATUS_ORDER.index(status) if status in STATUS_ORDER else 0
