"""User-consented call transcript analysis. Audio never reaches this API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from backend.schemas.exposure import ExposureSignal
from backend.schemas.sms import SmsCandidate, SmsEntity, SmsRiskReason


class CallAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transcript: str = Field(min_length=1, max_length=8000)
    save: bool = False
    store_redacted_transcript: bool = False


class CallAnalysis(BaseModel):
    id: int | None = None
    created_at: datetime | None = None
    status: str
    redacted_transcript: str
    entities: list[SmsEntity]
    candidates: list[SmsCandidate]
    exposure: list[ExposureSignal]
    statements: list[SmsRiskReason]
    missing: list[str]
    notice: str = (
        "Speech recognition and caller identity are unverified. A matched alias or nickname is a lead, "
        "not proof of a leak or of who called."
    )


class CallAnalysisPage(BaseModel):
    items: list[CallAnalysis]
    total: int
    limit: int
    offset: int
