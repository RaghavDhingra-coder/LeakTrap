"""Request and response models for accounts. Passwords are never echoed."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.services.domains import normalize_email


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class Registration(Credentials):
    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        return normalize_email(value)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class VerifyEmail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=10, max_length=200)


class AccountDeletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(max_length=256)
    confirm: Literal["DELETE"] = Field(description='Type "DELETE" to confirm.')


class Me(BaseModel):
    email: str
    email_verified: bool
    csrf_token: str = Field(description="Send as X-CSRF-Token on every state-changing request.")
    email_delivery_configured: bool
    is_domain_verification_admin: bool = False


class Message(BaseModel):
    detail: str


class RegistrationResult(BaseModel):
    detail: str
    verification_email_sent: bool
