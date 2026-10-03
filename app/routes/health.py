"""
Health & Metrics Routes
========================
GET  /health        — liveness check
GET  /health/ready  — readiness check (DB connectivity)
GET  /metrics       — Prometheus metrics
GET  /public-keys   — Current Ed25519 public keys (for client pinning)
"""

import time

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database import get_db
from app.dependencies import get_token_engine
from app.token_engine import TokenEngine

router = APIRouter(tags=["health"])

_start_time = time.time()


@router.get("/health")
async def health():
    """Liveness probe — always returns ok if the process is up."""
    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - _start_time),
    }


@router.get("/health/ready")
async def health_ready(db: AsyncSession = Depends(get_db)):
    """
    Readiness probe — checks DB connectivity.
    Returns 503 if the database is unreachable.
    """
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": str(e)},
        )


@router.get("/health/live")
async def health_live():
    """Kubernetes liveness alias."""
    return {"status": "live"}


@router.get("/metrics")
async def metrics():
    """
    Prometheus-compatible metrics endpoint.
    In production, use the prometheus_client library for proper instrumentation.
    """
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return PlainTextResponse(
            content=generate_latest().decode("utf-8"),
            media_type=CONTENT_TYPE_LATEST,
        )
    except ImportError:
        # Fallback basic metrics
        uptime = int(time.time() - _start_time)
        lines = [
            f'# HELP authserver_uptime_seconds Server uptime in seconds',
            f'# TYPE authserver_uptime_seconds gauge',
            f'authserver_uptime_seconds {uptime}',
        ]
        return PlainTextResponse(content="\n".join(lines), media_type="text/plain")


@router.get("/public-keys")
async def public_keys(engine: TokenEngine = Depends(get_token_engine)):
    """
    Return current Ed25519 public keys for client-side verification.
    Clients can pin against these keys for offline token verification.
    """
    keys = engine.get_public_keys()
    return {
        "keys": [
            {"kid": kid, "public_key_hex": pk_hex, "algorithm": "Ed25519"}
            for kid, pk_hex in keys.items()
        ],
        "active_kid": engine.active_key_id,
    }
