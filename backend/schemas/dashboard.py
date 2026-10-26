"""Response models for the personal dashboard API (the signed-in user's own data).

Message hashes and bodies are never returned. Sender names, addresses and
subjects are returned only by the inbox endpoints, only for messages recorded
by inbox tracking, and only to the account that owns the receiving alias.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from backend.schemas.exposure import ExposureSignal

NOT_PROOF = (
    "A match links a message to one of your signups. It is not proof that a site "
    "leaked, sold or shared your data. Recipient attribution does not authenticate the sender or establish safety."
)


class OverviewResponse(BaseModel):
    websites: int
    aliases: int
    nicknames: int
    receipts: int
    emails_total: int
    matched: int
    unmatched: int
    failed: int
    ambiguous: int = Field(description="Legacy source-analysis count, not recipient attribution.")
    no_match: int = Field(description="Legacy source-analysis count, not recipient attribution.")
    unprocessed: int = Field(description="Mail records without a stored match status.")
    investigations: int = Field(description="Matcher results you chose to record.")
    unread: int = Field(description="Unread inbox messages.")
    notice: str = NOT_PROOF


class DashboardSignup(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    site_name: str
    site_domain: str | None
    alias: str | None
    nickname: str | None
    real_name_required: bool
    receipt_count: int
    email_count: int
    created_at: datetime


class DashboardSignupPage(BaseModel):
    items: list[DashboardSignup]
    total: int
    limit: int
    offset: int


class DashboardEmail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: Literal["matched", "unmatched", "failed", "unprocessed"]
    status_reason: str | None
    alias: str | None
    unread: bool
    exposure: list[ExposureSignal]
    tracked: bool = Field(description="False for historical records without stored inbox details.")
    subject: str | None = Field(description="Untrusted subject; absent for historical records.")
    sender_name: str | None = Field(description="Untrusted From display name.")
    sender_email: str | None = Field(description="Untrusted From address, or envelope sender.")
    auth_results: str | None = Field(description="Reported by the inbound provider; not independent sender verification.")

    id: int
    received_at: datetime
    created_at: datetime
    match_status: str | None
    match_confidence: str | None
    recipient_known: bool
    signup_id: int | None
    site_name: str | None
    site_domain: str | None
    sender_domain: str | None = Field(description="Claimed sender domain; may be forged.")


class DashboardEmailPage(BaseModel):
    items: list[DashboardEmail]
    total: int
    limit: int
    offset: int


class DashboardEmailDetail(DashboardEmail):
    stored_details: str = (
        "Only the match status and confidence were stored for this message. Signal-level "
        "explanations are produced when the matcher runs; use the matcher check to see them."
    )
    limitations: list[str]
    notice: str = NOT_PROOF


class SignupReceipt(BaseModel):
    id: int
    action: str | None
    evidence_basis: str
    recorded_at: datetime
    reported_occurred_at: datetime | None
    source_url: str | None


class SignupSms(BaseModel):
    id: int
    created_at: datetime
    status: str | None
    confirmed: bool = Field(description="You confirmed this message relates to this website.")


class SignupDetailResponse(BaseModel):
    id: int
    site_name: str
    site_domain: str | None
    alias: str | None
    nickname: str | None
    surname_variant: str | None
    real_name_required: bool
    real_name_used: bool
    created_at: datetime
    receipts: list[SignupReceipt] = Field(description="Most recent 20.")
    emails: list[DashboardEmail] = Field(description="Most recent 20.")
    sms_investigations: list[SignupSms] = Field(default_factory=list, description="Saved SMS investigations that suggested or confirmed this website; most recent 20.")
    notice: str = NOT_PROOF


class Investigation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    channel: str
    result: str | None = Field(description='Email: "matched", "ambiguous" or "no_match". SMS: the source status '
                                           '"confirmed", "strong", "possible" or "unknown". Never a confirmed leak.')
    confidence: str | None
    matched_site: str | None
    recipient_alias_matched: bool
    sender_domain: str | None
    candidate_count: int
    signal_types: list[str]


class InvestigationPage(BaseModel):
    items: list[Investigation]
    total: int
    limit: int
    offset: int
    notice: str = NOT_PROOF


UNTRUSTED = (
    "Matched identifies a recipient alias and its registered website, not a verified or safe sender. "
    "Sender names, addresses and subjects come from the message itself and can be forged. "
    "Authentication results are as reported by Cloudflare's header; LeakTrace does not verify them."
)


class InboxItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    received_at: datetime
    status: Literal["matched", "unmatched", "failed", "unprocessed"] = Field(
        description='"matched": linked to one of your websites by its exact alias; "unmatched": not linked '
                    '(status_reason says why); "failed": linked, but the leak analysis failed.'
    )
    status_reason: str | None
    tracked: bool = Field(description="False for records from before inbox tracking; they have no message details.")
    unread: bool
    read_at: datetime | None
    alias: str | None = Field(description="The alias the message was delivered to (envelope recipient).")
    signup_id: int | None
    site_name: str | None
    site_domain: str | None
    identity: str | None = Field(description="Nickname and surname variant used for this website.")
    identity_kind: Literal["nickname", "real_name", "none"]
    sender_name: str | None = Field(description="From header display name. Untrusted.")
    sender_email: str | None = Field(description="From header address (or envelope sender). Untrusted.")
    sender_domain: str | None
    subject: str | None = Field(description="Untrusted.")
    auth_results: str | None = Field(description='e.g. "spf=pass dkim=pass dmarc=pass", as reported by Cloudflare.')
    match_status: str | None
    match_confidence: str | None
    exposure: list[ExposureSignal]


class InboxPage(BaseModel):
    items: list[InboxItem]
    total: int
    limit: int
    offset: int
    unread: int
    notice: str = UNTRUSTED


class InboxUpdates(BaseModel):
    unread: int
    latest_id: int = Field(description="Pass as after_id on the next poll; 0 when there are no messages.")
    new: list[InboxItem] = Field(description="Messages recorded after after_id, newest first (at most 10).")


class InboxReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read: StrictBool


class InboxReadAllResponse(BaseModel):
    marked: int
    unread: int


class TimelineItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    channel: Literal["email", "sms"]
    id: int
    at: datetime
    title: str
    status: str | None
    site_name: str | None
    signup_id: int | None
    linked: bool = Field(description="Linked to a website by an exact alias (email) or your confirmation (SMS).")


class Timeline(BaseModel):
    items: list[TimelineItem]
    notice: str = ("Email and SMS records are linked to a website only by an exact alias or by your own "
                   "confirmation, never because they mention the same company.")
