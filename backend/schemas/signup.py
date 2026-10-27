"""Request and response models for the signup API."""

import re
import unicodedata
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.services.domains import normalize_domain

MAX_BIGINT = 2**63 - 1
_SURNAME = re.compile(r"^[^\W\d_]+(?:[ '’-][^\W\d_]+)*$")


def _collapse_whitespace(value: str) -> str:
    return " ".join(value.split())


class SignupCreate(BaseModel):
    """A website signup to protect with generated markers.

    LeakTrace never asks for or stores the user's real name. Set
    real_name_required when the site insists on a real name: no nickname is
    generated in that case (unless generate_nickname is explicitly true), and
    the signup is recorded as having used the real name.
    """

    model_config = ConfigDict(extra="forbid")

    site_name: str = Field(description="Website or organization name.", examples=["Example Shop"])
    site_domain: str | None = Field(default=None, examples=["shop.example.com"])
    real_name_required: bool = False
    surname_variant: str | None = Field(
        default=None,
        description="A surname variant the user chose to give this site. Never generated.",
    )
    generate_alias: bool = True
    generate_nickname: bool | None = Field(
        default=None, description="Defaults to true unless real_name_required is true."
    )

    @field_validator("site_name")
    @classmethod
    def check_site_name(cls, value: str) -> str:
        if any(unicodedata.category(ch).startswith("C") for ch in value.replace(" ", "")):
            raise ValueError("site_name must not contain control characters")
        value = _collapse_whitespace(value)
        if not any(ch.isalnum() for ch in value):
            raise ValueError("site_name must contain at least one letter or digit")
        if len(value) > 255:
            raise ValueError("site_name must be at most 255 characters")
        return value

    @field_validator("site_domain")
    @classmethod
    def check_site_domain(cls, value: str | None) -> str | None:
        return None if value is None else normalize_domain(value)

    @field_validator("surname_variant")
    @classmethod
    def check_surname_variant(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = _collapse_whitespace(value)
        if not value:
            raise ValueError("surname_variant must not be blank")
        if len(value) > 100:
            raise ValueError("surname_variant must be at most 100 characters")
        if not _SURNAME.match(value):
            raise ValueError(
                "surname_variant may only contain letters, single spaces, hyphens and apostrophes"
            )
        return value

    @model_validator(mode="after")
    def default_generate_nickname(self) -> "SignupCreate":
        if self.generate_nickname is None:
            self.generate_nickname = not self.real_name_required
        return self


class SignupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    site_name: str
    site_domain: str | None
    alias_status: Literal["active", "revoked"]
    alias_status_changed_at: datetime
    alias: str | None = Field(
        description="Generated address. Not verified; mail routing is configured separately."
    )
    nickname: str | None
    surname_variant: str | None
    real_name_required: bool
    real_name_used: bool
    created_at: datetime
    updated_at: datetime


class SignupList(BaseModel):
    items: list[SignupRead]
    total: int
    limit: int
    offset: int


class SignupAliasStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias_status: Literal["active", "revoked"]
