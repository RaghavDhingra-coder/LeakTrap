"""Dashboard routes for mobile devices: check a pairing code before approving it,
and list or revoke paired devices.

Web session only (CSRF-checked for changes), served in full mode only: a
mobile-mode deployment never loads this module. Approval itself is
POST /extension/pairings/approve with kind "mobile".
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.routes.common import TOO_MANY
from backend.routes.mobile import MobileDevice, parse
from backend.schemas.signup import MAX_BIGINT
from backend.security import require_user
from backend.services import pairing
from backend.services.auth import AuthContext, RateLimited

router = APIRouter(prefix="/mobile", tags=["mobile"])


class MobilePairingPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=8, max_length=12)


class MobilePairingPreview(BaseModel):
    device_label: str | None
    expires_at: datetime


@router.post("/pairings/preview", response_model=MobilePairingPreview, responses={401: {}, 404: {}, 429: {}})
async def preview_pairing(request: Request, auth: AuthContext = Depends(require_user),
                          db: Session = Depends(get_db)) -> MobilePairingPreview:
    """Show which device a code belongs to before approving it. Approves nothing.
    Unknown codes count towards the same failure limit as approvals."""
    data = await parse(request, MobilePairingPreviewRequest)
    try:
        row = await run_in_threadpool(pairing.preview, db, auth.user_id, data.code, "mobile")
    except pairing.PairingNotFound:
        raise HTTPException(404, "That code is unknown, already used or expired. Start again in the LeakTrace app.") from None
    except RateLimited:
        raise TOO_MANY from None
    return MobilePairingPreview(device_label=row.device_label or pairing.DEFAULT_MOBILE_LABEL, expires_at=row.expires_at)


@router.get("/devices", response_model=list[MobileDevice])
def list_devices(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> list[MobileDevice]:
    return [MobileDevice.model_validate(s) for s in pairing.active_sessions(db, auth.user_id, "mobile")]


@router.delete("/devices/{device_id}", status_code=204, responses={404: {}})
def revoke_device(device_id: int = Path(gt=0, le=MAX_BIGINT), auth: AuthContext = Depends(require_user),
                  db: Session = Depends(get_db)) -> Response:
    if not pairing.revoke_session_of_kind(db, auth.user_id, device_id, "mobile"):
        raise HTTPException(404, "Device not found")
    return Response(status_code=204)
