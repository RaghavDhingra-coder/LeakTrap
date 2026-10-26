"""Request authentication and authorization dependencies.

Web sessions use the HttpOnly `lt_session` cookie; state-changing requests
must also send `X-CSRF-Token` and come from this server's own origin.
Extension tokens use `Authorization: Bearer`, carry explicit scopes, and are
not cookies, so CSRF does not apply to them. Mobile device tokens are Bearer
tokens too, accepted only by mobile routes (require_mobile), which never read
cookies; every other route refuses them.

Every private route depends on one of these; the authenticated user id is
the only ownership scope. Clients can never choose another user's scope.
"""

import hmac
import logging
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.config import settings, valid_public_dashboard_origin
from backend.database import get_db
from backend.forwarding import forwarded_client
from backend.services.auth import AuthContext, authenticate

logger = logging.getLogger("leaktrace.security")

SESSION_COOKIE = "lt_session"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

EXTENSION_SCOPES = frozenset({"signups:create", "signups:lookup", "receipts:create", "reports:create"})

# Every permission a mobile token can ever carry, one per future mobile API area.
MOBILE_SCOPES = frozenset({
    "account:read", "websites:read", "email:read", "timeline:read", "sms:analyze", "sms:write",
    "call:analyze", "call:write",
})
# What a newly paired device receives: every scope, now that each has its routes.
# Devices paired earlier keep the scopes they were given until they pair again.
MOBILE_GRANTED_SCOPES = MOBILE_SCOPES

UNAUTHENTICATED = HTTPException(401, "Sign in required.", headers={"WWW-Authenticate": "Bearer"})
INVALID_TOKEN = HTTPException(401, "Sign in required.", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})


class PublicDashboardOriginGuard:
    """Require the configured HTTPS host on the public full-mode service."""

    HEALTH_PATHS = {"/health", "/health/ready"}

    def __init__(self, app, origin: str | None):
        self.app = app
        self.origin = valid_public_dashboard_origin(origin)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") not in self.HEALTH_PATHS:
            headers = {name.lower(): value for name, value in scope.get("headers", [])}
            host = headers.get(b"host", b"").decode("latin-1")
            observed = valid_public_dashboard_origin(f"{scope.get('scheme', '')}://{host}")
            if self.origin is None or observed != self.origin:
                response = JSONResponse({"detail": "Request origin is not allowed."}, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext | None:
    """The caller's session, or None. A Bearer token takes precedence over the cookie."""
    token = bearer_token(request)
    if token:
        context = authenticate(db, token)
        return context if context and context.kind == "extension" else None
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        context = authenticate(db, cookie)
        return context if context and context.kind == "web" else None
    return None


def _own_origin(request: Request) -> str:
    if settings.dashboard_public:
        return valid_public_dashboard_origin(settings.dashboard_public_origin) or ""
    return f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def verify_csrf(request: Request, context: AuthContext) -> None:
    if request.method in SAFE_METHODS:
        return
    if settings.dashboard_public and request.url.scheme.lower() != "https":
        raise HTTPException(403, "Request blocked: HTTPS is required.")
    origin = request.headers.get("origin")
    if origin is None:
        referer = request.headers.get("referer")
        if referer:
            parts = urlsplit(referer)
            origin = f"{parts.scheme}://{parts.netloc}"
    if origin != _own_origin(request):
        raise HTTPException(403, "Request blocked: it did not come from this site.")
    sent = request.headers.get(CSRF_HEADER, "")
    if not context.csrf_token or not hmac.compare_digest(sent.encode(), context.csrf_token.encode()):
        raise HTTPException(403, "Request blocked: missing or invalid security token. Reload the page and try again.")


def require_user(request: Request, context: AuthContext | None = Depends(get_auth_context)) -> AuthContext:
    """A signed-in web session (dashboard). CSRF-checked for unsafe methods."""
    if context is None or context.kind != "web":
        raise UNAUTHENTICATED
    verify_csrf(request, context)
    return context


def require_scope(scope: str):
    """A web session, or an extension token that carries `scope`."""
    if scope not in EXTENSION_SCOPES:
        raise ValueError(f"unknown scope {scope}")

    def dependency(request: Request, context: AuthContext | None = Depends(get_auth_context)) -> AuthContext:
        if context is None:
            raise UNAUTHENTICATED
        if context.kind == "web":
            verify_csrf(request, context)
            return context
        if scope not in context.scopes:
            raise HTTPException(403, "This connection is not allowed to do that.")
        return context

    dependency.__name__ = f"require_scope_{scope.replace(':', '_')}"
    return dependency


def require_extension(context: AuthContext | None = Depends(get_auth_context)) -> AuthContext:
    if context is None or context.kind != "extension":
        raise UNAUTHENTICATED
    return context


def require_mobile(scope: str | None = None):
    """A paired mobile device's Bearer token, carrying `scope` when one is given.

    Only `Authorization: Bearer` is read: cookies are ignored, so a browser cannot
    be made to send these requests with ambient credentials and CSRF does not
    apply. Web and extension tokens are refused. Every failure to authenticate
    (missing, unknown, expired, idle, revoked, disabled account) looks the same.
    """
    if scope is not None and scope not in MOBILE_SCOPES:
        raise ValueError(f"unknown mobile scope {scope}")

    def dependency(request: Request, db: Session = Depends(get_db)) -> AuthContext:
        token = bearer_token(request)
        if token is None:
            raise UNAUTHENTICATED
        context = authenticate(db, token)
        if context is None or context.kind != "mobile":
            raise INVALID_TOKEN
        if scope is not None and scope not in context.scopes:
            raise HTTPException(403, "This device is not allowed to do that.")
        return context

    dependency.__name__ = f"require_mobile_{(scope or 'any').replace(':', '_')}"
    return dependency


def set_session_cookie(response: Response, token: str, max_age_seconds: int) -> None:
    response.set_cookie(
        SESSION_COOKIE, token, max_age=max_age_seconds, path="/", httponly=True,
        samesite="strict", secure=settings.cookie_secure,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict", secure=settings.cookie_secure)


# Rate-limit key shared by every mobile client whose address cannot be established.
UNKNOWN_CLIENT = "unknown-client"
_unknown_client_requests = 0


def _note_unknown_client() -> None:
    global _unknown_client_requests
    _unknown_client_requests += 1
    if _unknown_client_requests == 1 or _unknown_client_requests % 100 == 0:
        logger.warning("Client address unknown for %d request(s); using the shared rate-limit key",
                       _unknown_client_requests)


def client_ip(request: Request) -> str:
    """The address rate limits are keyed by.

    Full and ingest mode are not deployed behind a known proxy: the socket peer is
    the client, and proxy headers are never read. Mobile mode runs behind the
    hosting platform's proxies: only LEAKTRACE_TRUSTED_PROXY_HOPS entries counted
    from the right of X-Forwarded-For are trusted (never X-Real-IP, Forwarded or
    similar headers). When that does not yield an address, including the default
    of 0 hops, every such client shares the UNKNOWN_CLIENT key, so limits stay strict.
    """
    if settings.app_mode != "mobile":
        return request.client.host if request.client else "unknown"
    found = forwarded_client(request.headers.getlist("x-forwarded-for"), settings.trusted_proxy_hops or 0)
    if found is None:
        _note_unknown_client()
        return UNKNOWN_CLIENT
    return found
