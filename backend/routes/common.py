"""Helpers shared by routes that parse request bodies themselves."""

from fastapi import HTTPException, Request
from pydantic import ValidationError


async def read_limited_body(request: Request, limit: int) -> bytes:
    """Read the body, refusing anything over limit bytes (413), whether or not
    a Content-Length header was sent."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"Request body exceeds {limit} bytes.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, f"Request body exceeds {limit} bytes.")
    return bytes(body)


def require_json(request: Request) -> None:
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
        raise HTTPException(415, "Content-Type must be application/json.")


def validation_error(exc: ValidationError) -> HTTPException:
    """422 listing locations and reasons only, never the submitted values."""
    errors = exc.errors(include_input=False, include_url=False, include_context=False)
    return HTTPException(422, [{"loc": list(e["loc"]), "msg": e["msg"]} for e in errors])


TOO_MANY = HTTPException(429, "Too many attempts. Wait a while and try again.")


async def parse_json(request: Request, model, limit: int):
    """Parse a JSON body of at most `limit` bytes into `model`; errors never echo values."""
    require_json(request)
    body = await read_limited_body(request, limit)
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        raise validation_error(exc) from None
