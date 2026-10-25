"""SMS analyzer for the personal dashboard.

The user pastes a message; nothing reads SMS from a device, and nothing is
sent anywhere else. Analysis stores nothing. Saving is a separate, explicit
request and uses the existing incidents table (channel "sms"). Like the rest
of the dashboard API, every route needs a signed-in web session (CSRF-checked
for changes) and only answers requests from this machine.

Request bodies are parsed by hand so validation errors never repeat the
submitted message text. Logs never contain message text or identifiers.
"""

from fastapi import APIRouter, Depends, Path as PathParam, Request, Response
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.routes import sms_shared as shared
from backend.routes.dashboard import require_local_dashboard
from backend.schemas.signup import MAX_BIGINT
from backend.schemas.sms import SmsAnalysis, SmsInvestigation, SmsInvestigationPage, SmsSaveResponse
from backend.security import require_user
from backend.services.auth import AuthContext

router = APIRouter(prefix="/dashboard/api/sms", tags=["sms"], dependencies=[Depends(require_local_dashboard)])

InvestigationId = PathParam(gt=0, le=MAX_BIGINT)


@router.post("/analyze", response_model=SmsAnalysis, responses={413: {}, 415: {}, 422: {}},
             openapi_extra=shared.ANALYZE_BODY)
async def analyze(request: Request, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> SmsAnalysis:
    """Extract details and suggest a source. Stores nothing."""
    return await shared.analyze(request, db, auth, settings.alias_domain)


@router.post("/investigations", response_model=SmsSaveResponse, status_code=201,
             responses={200: {"description": "Already saved; nothing new was stored"}, 413: {}, 415: {}, 422: {}},
             openapi_extra=shared.SAVE_BODY)
async def save_investigation(request: Request, auth: AuthContext = Depends(require_user),
                             db: Session = Depends(get_db)):
    """Analyse again on the server (client results are never trusted) and save."""
    return await shared.save(request, db, auth, settings.alias_domain)


@router.get("/investigations", response_model=SmsInvestigationPage)
def list_investigations(
    limit: int = shared.Limit, offset: int = shared.Offset,
    auth: AuthContext = Depends(require_user), db: Session = Depends(get_db),
) -> SmsInvestigationPage:
    return shared.list_page(db, auth, limit, offset)


@router.get("/investigations/{investigation_id}", response_model=SmsInvestigation, responses={404: {}})
def get_investigation(investigation_id: int = InvestigationId, auth: AuthContext = Depends(require_user),
                      db: Session = Depends(get_db)) -> SmsInvestigation:
    return shared.get_one(db, auth, investigation_id)


@router.post("/investigations/{investigation_id}/actions", response_model=SmsInvestigation, responses={404: {}, 422: {}})
async def investigation_action(request: Request, investigation_id: int = InvestigationId,
                               auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> SmsInvestigation:
    """Confirm or reject a suggested source, link a website by hand, or mark as reviewed."""
    return await shared.act(request, db, auth, investigation_id)


@router.delete("/investigations/{investigation_id}", status_code=204, responses={404: {}})
def delete_investigation(investigation_id: int = InvestigationId, auth: AuthContext = Depends(require_user),
                         db: Session = Depends(get_db)) -> Response:
    return shared.delete(db, auth, investigation_id)
