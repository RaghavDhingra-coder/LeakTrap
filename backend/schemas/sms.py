"""Request and response models for the SMS analyzer (dashboard API).

Sensitive values (verification codes, card and account numbers, sign-in and
reset links) are never returned in full: their `value` is null and `display`
is masked. Responses never include another user's records.
"""

import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Literal

from backend.schemas.exposure import ExposureSignal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from backend.services.sms_extract import MAX_SMS_LENGTH

SourceStatus = Literal["confirmed", "strong", "possible", "unknown"]
SMS_NOTICE = (
    "A suggested source is based only on what the message says and on your own LeakTrace records. "
    "It does not show who collected your phone number or whether your data was leaked, sold or shared."
)
SMS_LIMITATIONS = [
    "Names of people and businesses are found with simple patterns and can be wrong; correct them below.",
    "Links are never opened. Shortened links hide their destination.",
    "Sender IDs and phone numbers can be spoofed. The sender is not treated as the source.",
    "LeakTrace does not store phone numbers, so it cannot match a number to the website you gave it to.",
    "Phone numbers without a country code are kept as written; their country is unknown.",
]


def _clean_line(value: str | None, field: str, max_length: int) -> str | None:
    if value is None:
        return None
    value = " ".join(unicodedata.normalize("NFKC", value).split())
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValueError(f"{field} must not contain control characters")
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value or None


class SmsAddition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["email", "phone", "domain", "business", "person"]
    value: str = Field(min_length=1, max_length=200)


class SmsAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=MAX_SMS_LENGTH, description="The SMS, pasted by the user.")
    sender: str | None = Field(default=None, max_length=64, description="Phone number, short code or sender ID.")
    received_at: AwareDatetime | None = Field(default=None, description="When the message arrived (timezone required).")
    label: str | None = Field(default=None, max_length=100, description="Where you received it, e.g. “work phone”.")
    exclude: list[str] = Field(default_factory=list, max_length=50, description="Entity keys to ignore (corrections).")
    additions: list[SmsAddition] = Field(default_factory=list, max_length=10, description="Details the analyzer missed.")

    @field_validator("text")
    @classmethod
    def check_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank")
        return value

    @field_validator("sender")
    @classmethod
    def check_sender(cls, value: str | None) -> str | None:
        return _clean_line(value, "sender", 64)

    @field_validator("label")
    @classmethod
    def check_label(cls, value: str | None) -> str | None:
        return _clean_line(value, "label", 100)

    @field_validator("received_at")
    @classmethod
    def check_received_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value > datetime.now(timezone.utc) + timedelta(days=1):
            raise ValueError("received_at is in the future")
        return value

    @field_validator("exclude")
    @classmethod
    def check_exclude(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z]{1,12}:\d{1,4}", key) for key in value):
            raise ValueError("exclude must list entity keys such as email:0")
        return value


class SmsSaveRequest(SmsAnalyzeRequest):
    store_text: bool = Field(default=False, description="Also keep the redacted message text.")


class SmsActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["confirm", "reject", "clear", "reviewed", "unreviewed"]
    candidate_key: str | None = Field(default=None, max_length=300)
    signup_id: int | None = Field(default=None, gt=0, le=2**63 - 1)


class SmsSender(BaseModel):
    type: Literal["phone", "short_code", "alphanumeric", "email"]
    display: str


class SmsEntity(BaseModel):
    key: str
    type: str
    display: str
    value: str | None = Field(description="Null for sensitive values, which are never returned in full.")
    certainty: Literal["validated", "pattern", "uncertain", "user_added"]
    sensitive: bool
    note: str | None
    excluded: bool
    relation: str | None = Field(description="How this detail relates to your LeakTrace records, if at all.")
    signup_id: int | None


class SmsSignal(BaseModel):
    type: str
    explanation: str
    excerpt: str | None = Field(description="Redacted quotation from the message.")
    weak: bool


class SmsCandidate(BaseModel):
    key: str
    name: str
    domain: str | None
    signup_id: int | None = Field(description="Set when this is one of your LeakTrace websites.")
    status: SourceStatus
    signals: list[SmsSignal]
    unknowns: list[str]
    email_count: int | None
    last_email_at: datetime | None
    sms_count: int | None


class SmsRiskReason(BaseModel):
    code: str
    message: str
    evidence: str | None = None


class SmsRisk(BaseModel):
    assessment: Literal["Likely scam", "Suspicious", "Inconclusive"]
    risk_level: Literal["high", "moderate", "unknown"]
    reasons: list[SmsRiskReason]
    exposure: list[ExposureSignal] = []
    urls: list[str]
    domains: list[str]
    next_steps: list[str]
    notice: str


class SmsAnalysis(BaseModel):
    risk: SmsRisk | None = None
    status: SourceStatus
    sender: SmsSender | None
    sender_notes: list[str]
    received_at: datetime | None
    label: str | None
    redacted_text: str = Field(description="The message with codes, card numbers and sensitive links hidden.")
    entities: list[SmsEntity]
    candidates: list[SmsCandidate]
    missing: list[str] = Field(description="What would be needed to suggest a source, when none is suggested.")
    warnings: list[str]
    limitations: list[str] = SMS_LIMITATIONS
    notice: str = SMS_NOTICE


class SmsConfirmation(BaseModel):
    key: str
    signup_id: int | None
    name: str
    manual: bool


class SmsSavedCandidate(BaseModel):
    key: str
    name: str
    domain: str | None
    signup_id: int | None
    status: SourceStatus
    signals: list[str]


class SmsInvestigation(BaseModel):
    risk: SmsRisk | None = None
    id: int
    created_at: datetime
    status: SourceStatus
    matched_site: str | None
    sender: SmsSender | None
    received_at: datetime | None
    label: str | None
    entity_counts: dict[str, int]
    domains: list[str]
    candidates: list[SmsSavedCandidate]
    missing: list[str]
    confirmed: SmsConfirmation | None
    rejected: list[str]
    reviewed: bool
    reviewed_at: datetime | None
    stored_text: str | None = Field(description="Redacted text, only if you chose to keep it.")
    notice: str = SMS_NOTICE


class SmsInvestigationPage(BaseModel):
    items: list[SmsInvestigation]
    total: int
    limit: int
    offset: int


class SmsSaveResponse(BaseModel):
    investigation: SmsInvestigation
    duplicate: bool = Field(description="True when this message was already saved; nothing new was stored.")
