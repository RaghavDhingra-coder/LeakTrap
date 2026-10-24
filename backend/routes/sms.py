"""SMS analyzer for the personal dashboard.

The user pastes a message; nothing reads SMS from a device, and nothing is
sent anywhere else. Analysis stores nothing. Saving is a separate, explicit
request and uses the existing incidents table (channel "sms"). Like the rest
of the dashboard API, every route needs a signed-in web session (CSRF-checked
for changes) and only answers requests from this machine.

Request bodies are parsed by hand so validation errors never repeat the
submitted message text. Logs never contain message text or identifiers.
"""

from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import Incident
from backend.routes.common import read_limited_body, require_json, validation_error
from backend.routes.dashboard import require_local_dashboard
from backend.schemas.signup import MAX_BIGINT
from backend.schemas.sms import (
    SmsActionRequest,
    SmsAnalysis,
    SmsAnalyzeRequest,
    SmsCandidate,
    SmsConfirmation,
    SmsEntity,
    SmsInvestigation,
    SmsInvestigationPage,
    SmsSaveRequest,
    SmsSaveResponse,
    SmsSavedCandidate,
    SmsSender,
    SmsSignal,
)
from backend.security import require_user
from backend.services import sms_extract, sms_investigations
from backend.services.auth import AuthContext
from backend.services.sms_investigate import Analysis, added_entity, investigate

MAX_BODY_BYTES = 16_384
NOT_FOUND = HTTPException(404, "SMS investigation not found")

router = APIRouter(prefix="/dashboard/api/sms", tags=["sms"], dependencies=[Depends(require_local_dashboard)])


def _field_error(loc: list, message: str) -> HTTPException:
    return HTTPException(422, [{"loc": list(loc), "msg": f"Value error, {message}"}])


async def _parse(request: Request, model):
    require_json(request)
    body = await read_limited_body(request, MAX_BODY_BYTES)
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        raise validation_error(exc) from None


def _run(db: Session, auth: AuthContext, payload: SmsAnalyzeRequest) -> Analysis:
    try:
        sms_extract.parse_sender(payload.sender)
    except ValueError as exc:
        raise _field_error(["sender"], str(exc)) from None
    for i, addition in enumerate(payload.additions):
        try:
            added_entity(i, addition.type, addition.value)
        except ValueError as exc:
            raise _field_error(["additions", i, "value"], str(exc)) from None
    return investigate(
        db, auth.user_id, auth.email, payload.text, sender_raw=payload.sender, received_at=payload.received_at,
        label=payload.label, exclude=set(payload.exclude), additions=[(a.type, a.value) for a in payload.additions],
        alias_domain=settings.alias_domain,
    )


def _analysis_out(a: Analysis) -> SmsAnalysis:
    relations = {f.entity_key: f for f in a.identifiers}
    return SmsAnalysis(
        status=a.status,
        sender=SmsSender(type=a.sender["type"], display=a.sender["display"]) if a.sender else None,
        sender_notes=a.sender_notes, received_at=a.received_at, label=a.label,
        redacted_text=sms_extract.redact(a.extraction),
        entities=[SmsEntity(
            key=e.key, type=e.type, display=e.display, value=None if e.sensitive else e.value,
            certainty=e.certainty, sensitive=e.sensitive, note=e.note, excluded=e.key in a.excluded,
            relation=relations[e.key].relation if e.key in relations else None,
            signup_id=relations[e.key].signup_id if e.key in relations else None,
        ) for e in a.entities],
        candidates=[SmsCandidate(
            key=c.key, name=c.name, domain=c.domain, signup_id=c.signup_id, status=c.status,
            signals=[SmsSignal(type=s.type, explanation=s.explanation, excerpt=s.excerpt, weak=s.weak) for s in c.signals],
            unknowns=c.unknowns, email_count=c.email_count, last_email_at=c.last_email_at, sms_count=c.sms_count,
        ) for c in a.candidates],
        missing=a.missing, warnings=a.warnings,
    )


def _sender_out(sender: dict | None) -> SmsSender | None:
    if not sender:
        return None
    value = sender["value"]
    display = {"phone": sms_extract.mask_digits, "email": sms_extract.mask_email}.get(sender["type"], lambda v: v)(value)
    return SmsSender(type=sender["type"], display=display)


def _saved_out(incident: Incident) -> SmsInvestigation:
    ev = incident.evidence or {}
    confirmed = ev.get("confirmed")
    return SmsInvestigation(
        id=incident.id, created_at=incident.created_at,
        status=incident.result if incident.result in ("confirmed", "strong", "possible", "unknown") else "unknown",
        matched_site=incident.matched_site, sender=_sender_out(ev.get("sender")),
        received_at=ev.get("received_at"), label=ev.get("label"), entity_counts=ev.get("entity_counts") or {},
        domains=ev.get("domains") or [],
        candidates=[SmsSavedCandidate(**{k: c.get(k) for k in ("key", "name", "domain", "signup_id", "status", "signals")})
                    for c in ev.get("candidates") or []],
        missing=ev.get("missing") or [],
        confirmed=SmsConfirmation(**{k: confirmed.get(k) for k in ("key", "signup_id", "name", "manual")}) if confirmed else None,
        rejected=ev.get("rejected") or [], reviewed=bool(ev.get("reviewed")), reviewed_at=ev.get("reviewed_at"),
        stored_text=incident.message_text,
    )


@router.post("/analyze", response_model=SmsAnalysis, responses={413: {}, 415: {}, 422: {}},
             openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
                 "schema": SmsAnalyzeRequest.model_json_schema()}}}})
async def analyze(request: Request, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> SmsAnalysis:
    """Extract details and suggest a source. Stores nothing."""
    payload = await _parse(request, SmsAnalyzeRequest)
    analysis = await run_in_threadpool(_run, db, auth, payload)
    return _analysis_out(analysis)


@router.post("/investigations", response_model=SmsSaveResponse, status_code=201,
             responses={200: {"description": "Already saved; nothing new was stored"}, 413: {}, 415: {}, 422: {}},
             openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
                 "schema": SmsSaveRequest.model_json_schema()}}}})
async def save_investigation(request: Request, auth: AuthContext = Depends(require_user),
                             db: Session = Depends(get_db)):
    """Analyse again on the server (client results are never trusted) and save."""
    payload = await _parse(request, SmsSaveRequest)
    analysis = await run_in_threadpool(_run, db, auth, payload)
    result = await run_in_threadpool(sms_investigations.save, db, auth.user_id, analysis, store_text=payload.store_text)
    body = SmsSaveResponse(investigation=_saved_out(result.incident), duplicate=result.duplicate)
    return JSONResponse(body.model_dump(mode="json"), status_code=200 if result.duplicate else 201)


@router.get("/investigations", response_model=SmsInvestigationPage)
def list_investigations(
    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=MAX_BIGINT),
    auth: AuthContext = Depends(require_user), db: Session = Depends(get_db),
) -> SmsInvestigationPage:
    items, total = sms_investigations.list_saved(db, auth.user_id, limit, offset)
    return SmsInvestigationPage(items=[_saved_out(i) for i in items], total=total, limit=limit, offset=offset)


InvestigationId = PathParam(gt=0, le=MAX_BIGINT)


@router.get("/investigations/{investigation_id}", response_model=SmsInvestigation, responses={404: {}})
def get_investigation(investigation_id: int = InvestigationId, auth: AuthContext = Depends(require_user),
                      db: Session = Depends(get_db)) -> SmsInvestigation:
    incident = sms_investigations.get(db, auth.user_id, investigation_id)
    if incident is None:
        raise NOT_FOUND
    return _saved_out(incident)


@router.post("/investigations/{investigation_id}/actions", response_model=SmsInvestigation, responses={404: {}, 422: {}})
async def investigation_action(request: Request, investigation_id: int = InvestigationId,
                               auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> SmsInvestigation:
    """Confirm or reject a suggested source, link a website by hand, or mark as reviewed."""
    payload = await _parse(request, SmsActionRequest)
    incident = await run_in_threadpool(sms_investigations.get, db, auth.user_id, investigation_id)
    if incident is None:
        raise NOT_FOUND
    try:
        incident = await run_in_threadpool(
            lambda: sms_investigations.apply_action(db, auth.user_id, incident, payload.action,
                                                    candidate_key=payload.candidate_key, signup_id=payload.signup_id))
    except sms_investigations.ActionError as exc:
        raise HTTPException(422, str(exc)) from None
    return _saved_out(incident)


@router.delete("/investigations/{investigation_id}", status_code=204, responses={404: {}})
def delete_investigation(investigation_id: int = InvestigationId, auth: AuthContext = Depends(require_user),
                         db: Session = Depends(get_db)) -> Response:
    if not sms_investigations.delete(db, auth.user_id, investigation_id):
        raise NOT_FOUND
    return Response(status_code=204)
