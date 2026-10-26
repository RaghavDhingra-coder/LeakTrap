"""Import every model so Base.metadata (and Alembic) can see all tables."""

from backend.models.auth import (
    AuthEvent,
    EmailVerificationToken,
    ExtensionPairing,
    OwnershipClaim,
    UserSession,
)
from backend.models.complaint_draft import ComplaintDraft
from backend.models.consent_receipt import ConsentReceipt
from backend.models.incident import Incident
from backend.models.leak_edge import LeakEdge
from backend.models.mail_log import MailLog
from backend.models.report import Report
from backend.models.signup import Signup
from backend.models.sender_domain_review import SenderDomainReview
from backend.models.user import User
from backend.models.website_report import WebsiteReport

__all__ = [
    "AuthEvent",
    "ComplaintDraft",
    "ConsentReceipt",
    "EmailVerificationToken",
    "ExtensionPairing",
    "Incident",
    "LeakEdge",
    "MailLog",
    "OwnershipClaim",
    "Report",
    "Signup",
    "SenderDomainReview",
    "User",
    "UserSession",
    "WebsiteReport",
]
