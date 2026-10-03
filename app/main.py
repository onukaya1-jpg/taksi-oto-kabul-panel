"""
GameStore Auth Server — Application Entry Point
==================================================
FastAPI server with Ed25519 token signing, mTLS, rate limiting,
audit logging, and device HWID binding.

Usage:
  Development:  uvicorn app.main:app --reload --port 8443
  Production:   uvicorn app.main:app --host 0.0.0.0 --port 8443 --workers 4

  Or via: python -m app.main
"""

import sys
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.settings import get_settings
from app.database import init_db
from app.dependencies import (
    init_token_engine,
    init_nonce_store,
    init_audit_logger,
    init_license_service,
)
from app.middleware import (
    RateLimitMiddleware,
    MTLSMiddleware,
    SecurityHeadersMiddleware,
    RequestLoggingMiddleware,
)
from app.rate_limiter import RateLimiter
from app.routes import auth, feature, health, admin, admin_control

# ── Structlog configuration ────────────────────────────────────
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if not get_settings().is_production
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


# ── Lifespan ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    settings = get_settings()
    logger.info(
        "server_starting",
        environment=settings.ENVIRONMENT,
        port=settings.PORT,
    )

    # Validate production settings
    if settings.is_production:
        errors = settings.validate_production()
        if errors:
            for err in errors:
                logger.error("production_validation_failed", error=err)
            sys.exit(1)

    # Initialize subsystems
    await init_db()
    init_token_engine()
    init_nonce_store()
    init_audit_logger()
    init_license_service()

    # Restore licenses from GitHub backup (if DB lost data)
    try:
        from app.license_backup import restore_licenses_from_github
        result = await restore_licenses_from_github()
        logger.info("github_restore_result", **result)
    except Exception as e:
        logger.warning("github_restore_failed", error=str(e))

    logger.info("server_ready", environment=settings.ENVIRONMENT)

    yield  # ── Application runs ──

    logger.info("server_shutting_down")


# ── App Factory ─────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Build the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="GameStore Auth Server",
        version="1.0.0",
        description=(
            "Ed25519-signed token authentication server with mTLS, HWID binding, "
            "replay protection, and structured audit logging."
        ),
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters: outermost first) ──
    audit = init_audit_logger()
    limiter = RateLimiter(
        per_minute=settings.RATE_LIMIT_PER_MINUTE,
        burst=settings.RATE_LIMIT_BURST,
    )

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=limiter, audit=audit)
    app.add_middleware(MTLSMiddleware, audit=audit)

    # CORS: Allow admin panel (same-origin) and dev access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.is_development else [
            f"https://{settings.HOST}",
            "https://gamestore-auth-onrender-com.onrender.com",
        ],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["X-Admin-Key", "Content-Type"],
    )

    # ── Routes ──
    app.include_router(auth.router)
    app.include_router(feature.router)
    app.include_router(health.router)
    app.include_router(admin.router)
    app.include_router(admin_control.router)

    return app


app = create_app()

# ── Direct execution ────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    import os
    settings = get_settings()
    # Render.com injects PORT env var
    port = int(os.environ.get("PORT", settings.PORT))
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=port,
        workers=settings.WORKERS if settings.is_production else 1,
        reload=settings.is_development,
    )
