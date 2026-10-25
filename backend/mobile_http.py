"""HTTP-level protections for the mobile API.

- MobileResponseHeaders: every /mobile/v1 response, errors included, carries
  `Cache-Control: no-store` (it holds personal data or tokens) and
  `X-Content-Type-Options: nosniff`.
- AccessLogPrivacy: uvicorn's access log records the full request URL; query
  strings (search terms, paging) are removed before a line is written.
- ProxyDiagnostics: staging only (refused in production at startup). For a
  /health request carrying PROXY_DIAGNOSTIC_HEADER it logs the forwarding
  headers as received, to establish LEAKTRACE_TRUSTED_PROXY_HOPS. It never
  changes a response and logs nothing for any other request.
"""

import logging

from backend.forwarding import forwarded_client

MOBILE_API_PREFIX = "/mobile/v1"
PROXY_DIAGNOSTIC_HEADER = b"x-leaktrace-proxy-diagnostic"
_FORWARDING_HEADERS = (b"x-forwarded-for", b"x-real-ip", b"forwarded", b"cf-connecting-ip", b"true-client-ip")

logger = logging.getLogger("leaktrace.proxy")


def _is_mobile_api(path: str) -> bool:
    return path == MOBILE_API_PREFIX or path.startswith(MOBILE_API_PREFIX + "/")


class MobileResponseHeaders:
    """Pure ASGI middleware, so it also covers error responses from FastAPI's handlers."""

    ADDED = ((b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"))

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not _is_mobile_api(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                names = {name for name, _ in self.ADDED}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in names]
                message = {**message, "headers": headers + list(self.ADDED)}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class AccessLogPrivacy(logging.Filter):
    """Removes the query string from uvicorn access-log records.

    uvicorn logs `'%s - "%s %s HTTP/%s" %d'` with (client, method, path?query,
    version, status). With strip_all every path is stripped; otherwise only
    /mobile/ paths are.
    """

    def __init__(self, strip_all: bool):
        super().__init__()
        self.strip_all = strip_all

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) and "?" in args[2]:
            path = args[2].split("?", 1)[0]
            if self.strip_all or path.startswith("/mobile/"):
                record.args = (*args[:2], path, *args[3:])
        return True


def install_access_log_privacy(strip_all: bool) -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, AccessLogPrivacy) for f in access.filters):
        access.addFilter(AccessLogPrivacy(strip_all))


class ProxyDiagnostics:
    """Staging-only: logs forwarding headers of marked /health requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/health":
            headers = scope.get("headers", [])
            if any(name == PROXY_DIAGNOSTIC_HEADER for name, _ in headers):
                received = {name.decode(): [v.decode("latin-1") for n, v in headers if n == name]
                            for name in _FORWARDING_HEADERS}
                chain = received["x-forwarded-for"]
                peer = scope.get("client")[0] if scope.get("client") else None
                logger.warning("Proxy diagnostic: peer=%s headers=%s candidates=%s", peer, received,
                               {hops: forwarded_client(chain, hops) for hops in (1, 2, 3)})
        await self.app(scope, receive, send)
