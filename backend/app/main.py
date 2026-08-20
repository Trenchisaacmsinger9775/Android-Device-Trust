import logging
import ipaddress
import time

from fastapi import FastAPI
from fastapi import Request

from app.api.routes import router
from app.core.ids import new_request_id
from app.observability.logging import configure_logging
from app.services.runtime import runtime

configure_logging()
logger = logging.getLogger("devicecheck.requests")

app = FastAPI(title="DeviceCheck Backend", version="0.1.0")
app.include_router(router)

@app.middleware("http")
async def log_request(request: Request, call_next):
    start = time.perf_counter()
    request_id = request.headers.get("x-request-id") or new_request_id()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request_failed",
            extra={"extra": _request_log_extra(request, request_id, None, start)},
        )
        raise

    if request.url.path != "/health" or response.status_code >= 400:
        log = logger.warning if response.status_code >= 400 else logger.info
        log(
            "request_completed",
            extra={"extra": _request_log_extra(request, request_id, response.status_code, start)},
        )
    response.headers["X-Request-ID"] = request_id
    return response

@app.on_event("startup")
async def startup() -> None:
    await runtime.start()

@app.on_event("shutdown")
async def shutdown() -> None:
    await runtime.stop()

def _request_log_extra(request: Request, request_id: str, status_code: int | None, start: float) -> dict[str, object]:
    return {
        "request_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "status_code": status_code,
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "client": _client_ip(request),
        "user_agent": request.headers.get("user-agent"),
    }

def _client_ip(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    if _trusted_proxy_peer(peer):
        forwarded = (
            request.headers.get("cf-connecting-ip")
            or request.headers.get("x-real-ip")
            or request.headers.get("x-forwarded-for")
        )
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return peer

def _trusted_proxy_peer(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
        return address.is_loopback or address.is_private
    except ValueError:
        return False
