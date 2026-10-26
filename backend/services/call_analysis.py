"""Analyze only a transcript the user explicitly submits, using existing evidence rules."""

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import Incident, Signup
from backend.schemas.call import CallAnalysis, CallAnalysisPage
from backend.schemas.sms import SmsCandidate, SmsEntity, SmsRiskReason, SmsSignal
from backend.services import sms_extract
from backend.services.ownership import owned_by
from backend.services.sms_investigate import investigate


def analyze(db: Session, user_id: int, email: str, transcript: str, alias_domain: str | None,
            *, save: bool = False, store_redacted_transcript: bool = False) -> CallAnalysis:
    result = investigate(db, user_id, email, transcript, alias_domain=alias_domain)
    relations = {item.entity_key: item for item in result.identifiers}
    entities = [SmsEntity(key=e.key, type=e.type, display=e.display,
                          value=None if e.sensitive else e.value, certainty=e.certainty,
                          sensitive=e.sensitive, note=e.note, excluded=False,
                          relation=relations[e.key].relation if e.key in relations else None,
                          signup_id=relations[e.key].signup_id if e.key in relations else None)
                for e in result.entities]
    candidates = [SmsCandidate(key=c.key, name=c.name, domain=c.domain, signup_id=c.signup_id,
                               status=c.status,
                               signals=[SmsSignal(type=s.type, explanation=s.explanation,
                                                  excerpt=s.excerpt, weak=s.weak) for s in c.signals],
                               unknowns=c.unknowns, email_count=c.email_count,
                               last_email_at=c.last_email_at, sms_count=c.sms_count)
                  for c in result.candidates]
    own = {s.id: s for s in db.scalars(select(Signup).where(owned_by(Signup.user_id, user_id))).all()}
    exposure = []
    for c in result.candidates:
        signup = own.get(c.signup_id)
        if signup is None:
            continue
        types = {signal.type for signal in c.signals}
        if "alias_in_message" in types and signup.alias:
            marker_type, marker, confidence = "alias_mention", signup.alias, "medium"
        elif "nickname_in_message" in types and signup.nickname:
            marker_type, marker, confidence = "nickname_mention", signup.nickname, "low"
        else:
            continue
        exposure.append({"signup_id": signup.id, "site_name": signup.site_name,
                         "marker_type": marker_type, "marker": marker,
                         "observed_source": None, "expected_domain": signup.site_domain,
                         "confidence": confidence,
                         "explanation": f"The transcript mentions the {marker_type.replace('_mention', '')} recorded for {signup.site_name}. "
                                        "The caller and how they learned it cannot be verified.",
                         "caveat": f"This is a possible source lead, not proof that {signup.site_name} leaked data or made the call."})
    redacted = sms_extract.redact(result.extraction)
    # Saved transcripts and dashboard views should not retain whole addresses
    # or phone numbers merely because they were useful during analysis.
    for entity in result.entities:
        if entity.value and entity.type in ("email", "phone"):
            redacted = re.sub(re.escape(entity.value), entity.display, redacted, flags=re.IGNORECASE)
    out = CallAnalysis(status=result.status, redacted_transcript=redacted,
                       entities=entities, candidates=candidates, exposure=exposure,
                       statements=[SmsRiskReason(**r) for r in (result.risk or {}).get("reasons", [])],
                       missing=result.missing)
    if save:
        stored_analysis = out.model_dump(mode="json", exclude={"id", "created_at", "redacted_transcript"})
        for entity in stored_analysis["entities"]:
            entity["value"] = None
        incident = Incident(user_id=user_id, channel="call", result=result.status,
                            matched_site=exposure[0]["site_name"] if len(exposure) == 1 else None,
                            message_text=redacted if store_redacted_transcript else None,
                            evidence={"source": "call_transcript", "version": 1,
                                      "analysis": stored_analysis})
        db.add(incident)
        db.commit()
        db.refresh(incident)
        out.id, out.created_at = incident.id, incident.created_at
    return out


def list_saved(db: Session, user_id: int, limit: int, offset: int) -> CallAnalysisPage:
    where = (owned_by(Incident.user_id, user_id), Incident.channel == "call",
             Incident.evidence["source"].astext == "call_transcript")
    total = db.scalar(select(func.count()).select_from(Incident).where(*where)) or 0
    rows = db.scalars(select(Incident).where(*where).order_by(Incident.created_at.desc(), Incident.id.desc())
                      .limit(limit).offset(offset)).all()
    return CallAnalysisPage(items=[CallAnalysis(**row.evidence["analysis"], id=row.id,
                                                 created_at=row.created_at,
                                                 redacted_transcript=row.message_text or "") for row in rows],
                            total=total, limit=limit, offset=offset)


def delete_saved(db: Session, user_id: int, call_id: int) -> bool:
    row = db.scalar(select(Incident).where(owned_by(Incident.user_id, user_id), Incident.id == call_id,
                                           Incident.channel == "call",
                                           Incident.evidence["source"].astext == "call_transcript"))
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True
