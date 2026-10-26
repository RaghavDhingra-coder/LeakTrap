"""Browser extension connection: dashboard-approved pairing and token management.

The extension never sees the user's password or web session. Tokens are
scoped (signups:create, signups:lookup, receipts:create, reports:create), short-lived and
revocable from the dashboard or by the extension itself.
"""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.responses import JSONResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.routes.auth import TOO_MANY, parse
from backend.schemas.signup import MAX_BIGINT
from backend.security import client_ip, require_extension, require_user
from backend.services import auth as auth_service
from backend.services import pairing
from backend.services.auth import AuthContext, RateLimited

router = APIRouter(prefix="/extension", tags=["extension"])


class PairingStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret_hash: str = Field(description="SHA-256 (hex) of a random secret the extension keeps.", max_length=64)


class PairingStarted(BaseModel):
    pairing_id: int
    code: str = Field(description="Show this to the user; they approve it in the dashboard.")
    expires_at: datetime
    approve_path: str


class PairingApprove(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=8, max_length=12)
    # What the user is approving. A code of the other kind is refused like an unknown code.
    kind: Literal["extension", "mobile"] = "extension"


class PairingExchange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: str = Field(min_length=20, max_length=200)


class ExtensionToken(BaseModel):
    token: str
    expires_at: datetime
    email: str
    scopes: list[str]


class ExtensionSession(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    label: str | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime


class WhoAmI(BaseModel):
    email: str
    scopes: list[str]


@router.post("/pairings", status_code=201, response_model=PairingStarted, responses={422: {}, 429: {}})
async def start_pairing(request: Request, db: Session = Depends(get_db)) -> PairingStarted:
    data = await parse(request, PairingStart)
    try:
        started = await run_in_threadpool(pairing.start, db, data.secret_hash.lower(), client_ip(request))
    except ValueError as exc:
        raise HTTPException(422, [{"loc": ["secret_hash"], "msg": str(exc)}]) from None
    except RateLimited:
        raise TOO_MANY from None
    return PairingStarted(pairing_id=started.pairing_id, code=started.code, expires_at=started.expires_at,
                          approve_path=f"/dashboard#pair={started.code}")


@router.post("/pairings/approve", responses={404: {}, 429: {}})
async def approve_pairing(request: Request, auth: AuthContext = Depends(require_user),
                          db: Session = Depends(get_db)) -> dict:
    data = await parse(request, PairingApprove)
    try:
        await run_in_threadpool(pairing.approve, db, auth.user_id, data.code, data.kind)
    except pairing.PairingNotFound:
        where = "the extension" if data.kind == "extension" else "the LeakTrace app"
        raise HTTPException(404, f"That code is unknown, already used or expired. Start again in {where}.") from None
    except RateLimited:
        raise TOO_MANY from None
    if data.kind == "mobile":
        return {"detail": "Approved. Your device will finish connecting in a moment."}
    return {"detail": "Approved. The extension will finish connecting in a moment."}


@router.post("/pairings/{pairing_id}/token", response_model=ExtensionToken,
             responses={202: {"description": "Not approved yet"}, 404: {}, 410: {}, 429: {}})
async def exchange_pairing(request: Request, response: Response, pairing_id: int = Path(gt=0, le=MAX_BIGINT),
                           db: Session = Depends(get_db)):
    data = await parse(request, PairingExchange)
    try:
        issued = await run_in_threadpool(pairing.exchange, db, pairing_id, data.secret, client_ip(request))
    except pairing.PairingPending:
        return JSONResponse({"detail": "Waiting for approval in the dashboard."}, status_code=202,
                            headers={"Cache-Control": "no-store"})
    except pairing.PairingExpired:
        raise HTTPException(410, "This pairing expired or was already used. Start again.") from None
    except pairing.PairingNotFound:
        raise HTTPException(404, "Unknown pairing.") from None
    except RateLimited:
        raise TOO_MANY from None
    response.headers["Cache-Control"] = "no-store"
    return ExtensionToken(token=issued.token, expires_at=issued.expires_at, email=issued.email, scopes=list(issued.scopes))


@router.get("/sessions", response_model=list[ExtensionSession])
def list_sessions(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> list[ExtensionSession]:
    return [ExtensionSession.model_validate(s) for s in pairing.active_extension_sessions(db, auth.user_id)]


@router.delete("/sessions/{session_id}", status_code=204, responses={404: {}})
def revoke_session(session_id: int = Path(gt=0, le=MAX_BIGINT), auth: AuthContext = Depends(require_user),
                   db: Session = Depends(get_db)) -> Response:
    if not pairing.revoke_extension_session(db, auth.user_id, session_id):
        raise HTTPException(404, "Connection not found")
    return Response(status_code=204)


@router.get("/whoami", response_model=WhoAmI)
def whoami(auth: AuthContext = Depends(require_extension)) -> WhoAmI:
    return WhoAmI(email=auth.email, scopes=sorted(auth.scopes))


@router.post("/disconnect", status_code=204)
def disconnect(auth: AuthContext = Depends(require_extension), db: Session = Depends(get_db)) -> Response:
    auth_service.revoke_session(db, auth.session_id, auth.user_id)
    return Response(status_code=204)
