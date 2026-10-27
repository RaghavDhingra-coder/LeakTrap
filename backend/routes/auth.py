"""Account endpoints: register, sign in/out, password, email verification, deletion.

Bodies are parsed here (not by FastAPI) so validation errors never echo
submitted values such as passwords. Errors are generic where they could
otherwise reveal whether an email is registered.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import User
from backend.routes.common import TOO_MANY, parse_json  # TOO_MANY is re-exported for other routers
from backend.schemas.auth import (
    AccountDeletion,
    Credentials,
    Me,
    Message,
    PasswordChange,
    Registration,
    RegistrationResult,
    VerifyEmail,
)
from backend.security import client_ip, clear_session_cookie, require_user, set_session_cookie
from backend.services import auth as auth_service
from backend.services.auth import AuthContext, AuthError, PasswordPolicyError, RateLimited

MAX_BODY = 8 * 1024
REGISTERED = (
    "If this email address was not already registered, your account has been created. "
    "Sign in to continue."
)

router = APIRouter(prefix="/auth", tags=["auth"])
account_router = APIRouter(tags=["auth"])


async def parse(request: Request, model: type[BaseModel]):
    return await parse_json(request, model, MAX_BODY)


def password_error(exc: PasswordPolicyError, field: str) -> HTTPException:
    return HTTPException(422, [{"loc": [field], "msg": str(exc)}])


@router.post("/register", status_code=202, response_model=RegistrationResult)
async def register(request: Request, db: Session = Depends(get_db)) -> RegistrationResult:
    """Create an account. The response is the same whether or not the email
    was already registered."""
    data = await parse(request, Registration)
    try:
        await run_in_threadpool(auth_service.register, db, data.email, data.password, client_ip(request))
    except PasswordPolicyError as exc:
        raise password_error(exc, "password") from None
    except RateLimited:
        raise TOO_MANY from None
    return RegistrationResult(detail=REGISTERED, verification_email_sent=False)


@router.post("/login", response_model=Me, responses={401: {}, 403: {}, 429: {}})
async def login(request: Request, response: Response, db: Session = Depends(get_db)) -> Me:
    data = await parse(request, Credentials)
    try:
        created = await run_in_threadpool(auth_service.login, db, data.email, data.password, client_ip(request))
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from None
    except RateLimited:
        raise TOO_MANY from None
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from None
    set_session_cookie(response, created.token, int(timedelta(days=settings.session_max_days).total_seconds()))
    return await run_in_threadpool(_me, db, created.session_id, created.csrf_token)


def _me(db: Session, session_id: int, csrf_token: str) -> Me:
    from backend.models import UserSession

    user = db.get(User, db.get(UserSession, session_id).user_id)
    return Me(email=user.email, email_verified=user.email_verified_at is not None, csrf_token=csrf_token,
              email_delivery_configured=auth_service.email_delivery_configured(),
              is_domain_verification_admin=bool(
                  user.email and user.email.lower() in settings.domain_verification_admin_emails
                  and user.email_verified_at is not None
              ))


@router.get("/me", response_model=Me)
def me(context: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> Me:
    return _me(db, context.session_id, context.csrf_token)


@router.post("/logout", status_code=204)
def logout(response: Response, context: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> Response:
    auth_service.revoke_session(db, context.session_id, context.user_id)
    response.status_code = 204
    clear_session_cookie(response)
    return response


@router.post("/password", status_code=204, responses={401: {}, 422: {}})
async def change_password(request: Request, context: AuthContext = Depends(require_user),
                          db: Session = Depends(get_db)) -> Response:
    data = await parse(request, PasswordChange)
    try:
        await run_in_threadpool(auth_service.change_password, db, context.user_id, data.current_password,
                                data.new_password, context.session_id)
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from None
    except PasswordPolicyError as exc:
        raise password_error(exc, "new_password") from None
    return Response(status_code=204)


@router.post("/verify-email", response_model=Message, responses={400: {}, 429: {}})
async def verify_email(request: Request, db: Session = Depends(get_db)) -> Message:
    data = await parse(request, VerifyEmail)
    try:
        ok = await run_in_threadpool(auth_service.verify_email, db, data.token, client_ip(request))
    except RateLimited:
        raise TOO_MANY from None
    if not ok:
        raise HTTPException(400, "This verification link is invalid or has expired.")
    return Message(detail="Your email address is verified.")


@router.post("/verification/resend", status_code=202, response_model=RegistrationResult)
def resend_verification(context: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> RegistrationResult:
    user = db.get(User, context.user_id)
    if user.email_verified_at is not None:
        return RegistrationResult(detail="Your email address is already verified.", verification_email_sent=False)
    token = auth_service.issue_verification_token(db, user.id)
    db.commit()
    sent = auth_service.deliver_verification_email(user.email, token)
    detail = ("A verification email was sent." if sent else
              "Email delivery is not configured, so no verification email was sent.")
    return RegistrationResult(detail=detail, verification_email_sent=sent)


@account_router.delete("/account", status_code=204, responses={401: {}, 422: {}})
async def delete_account(request: Request, context: AuthContext = Depends(require_user),
                         db: Session = Depends(get_db)) -> Response:
    """Permanently delete the account and every record it owns."""
    data = await parse(request, AccountDeletion)
    try:
        await run_in_threadpool(auth_service.delete_account, db, context.user_id, data.password)
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from None
    response = Response(status_code=204)
    clear_session_cookie(response)
    return response
