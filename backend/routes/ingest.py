"""Machine-to-machine email ingestion, called by the Cloudflare email Worker.

Authenticated with a shared secret (LEAKTRACE_INGEST_SECRET) sent as a Bearer
token. Responses and logs never repeat addresses, subjects or other input.
"""

import hmac
import logging
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.routes.common import read_limited_body, require_json, validation_error
from backend.schemas.mail_ingest import MailIngestRequest, MailIngestResponse
from backend.services import mail_ingest
from backend.services.domains import normalize_domain
from backend.services.domains import normalize_email
from backend.models import Signup

logger = logging.getLogger("leaktrace.ingest")

MIN_SECRET_LENGTH = 32

router = APIRouter(prefix="/ingest", tags=["ingest"])


class AliasStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient: str = Field(min_length=3, max_length=320)


@dataclass(frozen=True)
class IngestConfig:
    secret: str | None
    max_bytes: int
    alias_domain: str | None


def get_ingest_config() -> IngestConfig:
    """Ingestion settings for the request; tests override this dependency."""
    return IngestConfig(settings.ingest_secret, settings.ingest_max_bytes, settings.alias_domain)


def require_ingest_auth(
    authorization: str | None = Header(default=None),
    config: IngestConfig = Depends(get_ingest_config),
) -> IngestConfig:
    if not config.secret or len(config.secret) < MIN_SECRET_LENGTH:
        logger.error("Email ingestion rejected: LEAKTRACE_INGEST_SECRET missing or too short")
        raise HTTPException(503, "Email ingestion is not configured.")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token.encode(), config.secret.encode()
    ):
        logger.warning("Email ingestion rejected: invalid or missing credentials")
        raise HTTPException(
            401, "Invalid or missing credentials.", headers={"WWW-Authenticate": "Bearer"}
        )
    return config


@router.post("/alias-status", responses={401: {}, 422: {}, 503: {}})
async def alias_status(
    request: Request,
    config: IngestConfig = Depends(require_ingest_auth),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Return only the status for the exact routed alias; fail closed on invalid input."""
    require_json(request)
    body = await read_limited_body(request, 1024)
    try:
        payload = AliasStatusRequest.model_validate_json(body)
        recipient = normalize_email(payload.recipient)
        alias_domain = normalize_domain(config.alias_domain or "")
    except (ValidationError, ValueError):
        raise HTTPException(422, "Recipient alias is invalid.") from None
    if recipient.split("@", 1)[1] != alias_domain:
        raise HTTPException(422, "Recipient is not at the alias domain.")

    signup = db.scalar(select(Signup).where(
        Signup.user_id.is_not(None), func.lower(Signup.alias) == recipient
    ))
    if signup is None:
        return {"status": "unverifiable"}
    if signup.alias_status not in ("active", "revoked"):
        return {"status": "unverifiable"}
    return {"status": signup.alias_status}


@router.post(
    "/email",
    status_code=201,
    response_model=MailIngestResponse,
    responses={
        200: {"description": "Already ingested (duplicate delivery), or a failed analysis was rerun"},
        401: {"description": "Missing or invalid Bearer secret"},
        413: {"description": "Body too large"},
        415: {"description": "Body is not JSON"},
        422: {"description": "Invalid payload or recipient outside the alias domain"},
        500: {"description": "Unexpected error; nothing was stored"},
        503: {"description": "Ingestion or database not configured or unavailable"},
    },
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
        "schema": MailIngestRequest.model_json_schema()}}}},
)
async def ingest_email(
    request: Request,
    response: Response,
    config: IngestConfig = Depends(require_ingest_auth),
    db: Session = Depends(get_db),
) -> MailIngestResponse:
    """Record one inbound email, attribute it to the signup whose alias is exactly
    the envelope recipient, and match it against that account's signups.

    A match is never proof that a site leaked data. Safe to retry: a repeated
    delivery returns 200 with status "duplicate" and stores nothing new, unless
    the first analysis failed, in which case it is rerun ("reprocessed").
    """
    require_json(request)
    body = await read_limited_body(request, config.max_bytes)
    try:
        payload = MailIngestRequest.model_validate_json(body)
    except ValidationError as exc:
        raise validation_error(exc) from None

    try:
        alias_domain = normalize_domain(config.alias_domain or "")
    except ValueError:
        raise HTTPException(503, "Alias domain is not configured.") from None
    if payload.recipient.split("@", 1)[1] != alias_domain:
        raise HTTPException(422, "Recipient is not at the alias domain.")

    signup = db.scalar(select(Signup).where(
        Signup.user_id.is_not(None), func.lower(Signup.alias) == payload.recipient
    ))
    if signup is not None and signup.alias_status != "active":
        if signup.alias_status == "revoked":
            raise HTTPException(410, "Alias is revoked.")
        raise HTTPException(503, "Alias status is unavailable.")

    mail = mail_ingest.InboundMail(
        recipient=payload.recipient,
        envelope_from=payload.envelope_from,
        claimed_sender=mail_ingest.parse_from_header(payload.from_header),
        subject=mail_ingest.decode_subject(payload.subject),
        message_id=payload.message_id,
        received_at=payload.received_at or mail_ingest.now(),
        sender_name=mail_ingest.parse_sender_name(payload.from_header),
        auth_results=mail_ingest.parse_auth_results(payload.auth_results),
    )
    outcome = await run_in_threadpool(mail_ingest.process, db, mail)
    logger.info(
        "Ingested email: mail_log_id=%d duplicate=%s reprocessed=%s ingest=%s/%s match=%s/%s",
        outcome.mail_log_id, outcome.duplicate, outcome.reprocessed, outcome.ingest_status,
        outcome.status_reason, outcome.match_status, outcome.match_confidence,
    )
    if outcome.duplicate:
        response.status_code = 200
    return MailIngestResponse(
        status="reprocessed" if outcome.reprocessed else "duplicate" if outcome.duplicate else "accepted",
        mail_log_id=outcome.mail_log_id,
        recipient_known=outcome.recipient_known,
        ingest_status=outcome.ingest_status,
        status_reason=outcome.status_reason,
        match_status=outcome.match_status,
        match_confidence=outcome.match_confidence,
    )
