"""Admin-only dashboard controls for encrypted Gemini domain interpretation."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import DomainVerificationCredential, User
from backend.routes.common import parse_json
from backend.routes.dashboard import require_local_dashboard
from backend.security import require_user
from backend.services import gemini
from backend.services.auth import AuthContext

router = APIRouter(
    prefix="/dashboard/api/domain-verification",
    tags=["domain verification"],
    dependencies=[Depends(require_local_dashboard)],
)


class GeminiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: SecretStr = Field(min_length=20, max_length=512, repr=False)

    @field_validator("api_key")
    @classmethod
    def valid_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw or raw != raw.strip() or any(ord(ch) < 33 or ord(ch) > 126 for ch in raw):
            raise ValueError("Enter a valid API key.")
        return value


def _require_admin(auth: AuthContext, db: Session) -> None:
    user = db.get(User, auth.user_id)
    if (auth.kind != "web" or not auth.email or auth.email.lower() not in settings.domain_verification_admin_emails
            or user is None or user.email_verified_at is None):
        raise HTTPException(403, "Domain verification settings require an allowlisted administrator account.")


@router.get("/settings")
def get_settings(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    _require_admin(auth, db)
    saved = db.get(DomainVerificationCredential, 1) is not None
    server_managed = bool(gemini.settings.domain_llm_api_key)
    return {
        "configured": saved or server_managed,
        "saved_key": saved,
        "server_managed": server_managed,
        "masked_api_key": "••••••••" if saved or server_managed else None,
        "encryption_ready": gemini.encryption_ready(),
    }


@router.put("/settings")
async def save_settings(request: Request, auth: AuthContext = Depends(require_user),
                        db: Session = Depends(get_db)) -> dict:
    _require_admin(auth, db)
    if not gemini.encryption_ready():
        raise HTTPException(503, "Server-side encryption is not configured.")
    payload = await parse_json(request, GeminiKeyRequest, 1024)
    try:
        encrypted = gemini.encrypt_api_key(payload.api_key.get_secret_value())
    except gemini.GeminiError:
        raise HTTPException(503, "Server-side encryption is unavailable.") from None
    row = db.get(DomainVerificationCredential, 1)
    if row is None:
        row = DomainVerificationCredential(id=1, encrypted_api_key=encrypted, updated_by=auth.user_id)
        db.add(row)
    else:
        row.encrypted_api_key = encrypted
        row.updated_by = auth.user_id
        row.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"configured": True, "masked_api_key": "••••••••"}


@router.post("/test")
def test_settings(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    _require_admin(auth, db)
    try:
        key = gemini.get_api_key(db)
        gemini.test_connection(key)
    except gemini.GeminiError as exc:
        status = 401 if exc.code == "gemini_authentication_failed" else 503
        raise HTTPException(status, "Gemini connection test failed. Check the saved key and server configuration.") from None
    return {"ok": True, "detail": "Gemini connection succeeded."}


@router.delete("/settings", status_code=204)
def remove_settings(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> Response:
    _require_admin(auth, db)
    row = db.get(DomainVerificationCredential, 1)
    if row is not None:
        db.delete(row)
        db.commit()
    return Response(status_code=204)
