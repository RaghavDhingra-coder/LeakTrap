"""Possible source of a reused LeakTrace marker, separate from attribution and scam risk."""
from typing import Literal

from pydantic import BaseModel


class ExposureSignal(BaseModel):
    signup_id: int
    site_name: str
    marker_type: Literal["recipient_alias", "alias_mention", "nickname_mention"]
    marker: str
    observed_source: str | None
    expected_domain: str | None
    confidence: Literal["medium", "low"]
    explanation: str
    caveat: str
