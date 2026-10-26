"""Create, list and delete signups with collision-safe marker generation."""

import logging
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import Signup, User
from backend.services.alias_generator import AliasConfig, alias_exists, generate_alias
from backend.services.ownership import owned_by
from backend.services.nickname_generator import (
    choose_nickname,
    used_nicknames,
    used_nicknames_any_owner,
)

logger = logging.getLogger("leaktrace.signups")

# Unique indexes on signups whose violation means "another request took this
# marker first": safe to roll back and try again with a fresh marker.
MARKER_UNIQUE_CONSTRAINTS = {"uq_signups_alias_lower", "uq_signups_user_id_nickname_lower"}
USER_FOREIGN_KEY = "fk_signups_user_id_users"


class UserNotFoundError(Exception):
    pass


class MarkerRetriesExhaustedError(Exception):
    """Markers kept colliding with concurrent signups until the retry limit."""


class SignupDeleteRestrictedError(Exception):
    pass


@dataclass(frozen=True)
class NewSignup:
    site_name: str
    site_domain: str | None
    user_id: int | None
    real_name_required: bool
    surname_variant: str | None
    generate_alias: bool
    generate_nickname: bool


def _constraint_name(exc: IntegrityError) -> str | None:
    diag = getattr(exc.orig, "diag", None)
    return getattr(diag, "constraint_name", None)


def create_signup(session: Session, data: NewSignup, alias_config: AliasConfig) -> Signup:
    """Generate markers, save the signup and return it once committed.

    Raises UserNotFoundError, AliasConfigurationError, AliasGenerationError,
    NicknameExhaustedError or MarkerRetriesExhaustedError. Nothing is saved
    when an error is raised.
    """
    if data.generate_alias:
        alias_config = alias_config.validated()
    if data.user_id is not None and session.get(User, data.user_id) is None:
        raise UserNotFoundError

    for attempt in range(1, alias_config.max_retries + 1):
        signup = Signup(
            user_id=data.user_id,
            site_name=data.site_name,
            site_domain=data.site_domain,
            surname_variant=data.surname_variant,
            real_name_required=data.real_name_required,
            # If the site requires a real name, the user gives it one.
            real_name_used=data.real_name_required,
        )
        try:
            if data.generate_alias:
                signup.alias = generate_alias(alias_config, lambda a: alias_exists(session, a))
            if data.generate_nickname:
                signup.nickname = choose_nickname(
                    used_nicknames(session, data.user_id), used_nicknames_any_owner(session)
                )
            session.add(signup)
            session.commit()
            return signup
        except IntegrityError as exc:
            session.rollback()
            constraint = _constraint_name(exc)
            if constraint == USER_FOREIGN_KEY:
                # The user was deleted between the check and the insert.
                raise UserNotFoundError from None
            if constraint not in MARKER_UNIQUE_CONSTRAINTS:
                raise
            logger.info(
                "Signup marker collision on %s (attempt %d of %d); retrying",
                constraint, attempt, alias_config.max_retries,
            )
        except Exception:
            session.rollback()
            raise

    raise MarkerRetriesExhaustedError


def list_signups(
    session: Session, user_id: int, limit: int, offset: int, site_domain: str | None = None
) -> tuple[list[Signup], int]:
    query = select(Signup).where(owned_by(Signup.user_id, user_id))
    if site_domain is not None:
        query = query.where(Signup.site_domain == site_domain)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    items = session.scalars(
        query.order_by(Signup.created_at.desc(), Signup.id.desc()).limit(limit).offset(offset)
    ).all()
    return list(items), total or 0


def get_signup(session: Session, user_id: int, signup_id: int) -> Signup | None:
    """The user's own signup, or None (also for other users' and unowned signups)."""
    return session.scalar(select(Signup).where(Signup.id == signup_id, owned_by(Signup.user_id, user_id)))


def find_by_exact_domain(
    session: Session, user_id: int, site_domain: str, limit: int = 10
) -> list[Signup]:
    """The user's signups whose site_domain equals site_domain exactly
    (no subdomain or parent-domain matching), newest first."""
    query = (
        select(Signup)
        .where(owned_by(Signup.user_id, user_id), Signup.site_domain == site_domain)
        .order_by(Signup.created_at.desc(), Signup.id.desc())
        .limit(limit)
    )
    return list(session.scalars(query).all())


def delete_signup(session: Session, signup_id: int, user_id: int) -> bool:
    """Delete the user's own signup. Linked consent receipts and mail logs are
    kept; the database sets their signup_id to NULL. Returns False if it does
    not exist or belongs to someone else."""
    signup = get_signup(session, user_id, signup_id)
    if signup is None:
        return False
    try:
        session.delete(signup)
        session.commit()
    except IntegrityError:
        session.rollback()
        raise SignupDeleteRestrictedError from None
    return True
