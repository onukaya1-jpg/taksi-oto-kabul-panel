"""
FastAPI Middleware — mTLS + Rate Limiting + Security Headers
=============================================================
"""

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import structlog

from app.audit import AuditLogger, AuditEventType
from app.rate_limiter import RateLimiter
from app.settings import get_settings

logger = structlog.get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting middleware."""

    def __init__(self, app, limiter: RateLimiter, audit: AuditLogger):
        super().__init__(app)
        self.limiter = limiter
        self.audit = audit

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"

        if not self.limiter.allow(client_ip):
            self.audit.log(
                AuditEventType.RATE_LIMIT,
                ip_address=client_ip,
                status_code=429,
                detail={"path": request.url.path},
            )
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "message": "Too many requests"},
            )

        return await call_next(request)


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    mTLS verification middleware.

    When MTLS_ENABLED=true, checks for valid client certificate in the
    X-SSL-Client-Cert or X-Forwarded-Client-Cert header (set by reverse proxy).

    In development (MTLS_ENABLED=false), this middleware is a no-op.
    """

    def __init__(self, app, audit: AuditLogger):
        super().__init__(app)
        self.audit = audit
        self._settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._settings.MTLS_ENABLED:
            return await call_next(request)

        # Skip health/metrics endpoints
        if request.url.path in ("/health", "/health/ready", "/health/live", "/metrics"):
            return await call_next(request)

        client_cert = (
            request.headers.get("X-SSL-Client-Cert")
            or request.headers.get("X-Forwarded-Client-Cert")
        )

        if not client_cert:
            client_ip = request.client.host if request.client else "unknown"
            self.audit.log(
                AuditEventType.MTLS_FAIL,
                ip_address=client_ip,
                status_code=403,
                detail={"reason": "missing_client_certificate", "path": request.url.path},
                is_alert=True,
            )
            return JSONResponse(
                status_code=403,
                content={"error": "mtls_required", "message": "Client certificate required"},
            )

        # Store cert info in request state for downstream handlers
        request.state.client_cert = client_cert
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security response headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log request timing and metadata."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration * 1000, 2),
            client_ip=request.client.host if request.client else "unknown",
        )
        return response
