"""
Dependency Injection — FastAPI Dependencies
=============================================
Provides singletons for TokenEngine, NonceStore, AuditLogger, LicenseService.
"""

from functools import lru_cache
from typing import Union

from app.settings import get_settings
from app.token_engine import TokenEngine
from app.nonce_store import InMemoryNonceStore, RedisNonceStore, NonceStore
from app.audit import AuditLogger
from app.licensing import LicenseService

import structlog

logger = structlog.get_logger(__name__)

_token_engine: TokenEngine | None = None
_nonce_store: Union[InMemoryNonceStore, RedisNonceStore, None] = None
_audit_logger: AuditLogger | None = None
_license_service: LicenseService | None = None


def init_token_engine() -> TokenEngine:
    """Initialize TokenEngine from settings. Called once at startup."""
    global _token_engine
    settings = get_settings()
    engine = TokenEngine(ttl_seconds=settings.TOKEN_TTL_SECONDS)

    if settings.ED25519_PRIVATE_KEY_PATH:
        engine.load_key_from_file(settings.ED25519_PRIVATE_KEY_PATH, key_id="primary")
        logger.info("token_engine_initialized", source="file")
    elif settings.ED25519_PRIVATE_KEY_HEX:
        engine.load_key_from_hex(settings.ED25519_PRIVATE_KEY_HEX, key_id="primary")
        logger.info("token_engine_initialized", source="env_hex")
    elif settings.ED25519_AUTO_GENERATE or settings.is_development:
        pub_hex = engine.generate_ephemeral_key(key_id="auto-generated")
        logger.warning(
            "token_engine_auto_generated",
            public_key=pub_hex[:16] + "...",
            hint="Set ED25519_PRIVATE_KEY_HEX for persistent keys across restarts",
        )
        # Persist the generated key so clients can verify tokens
        _persist_auto_generated_key(engine)
    else:
        raise RuntimeError(
            "No Ed25519 key configured. Set one of: "
            "ED25519_PRIVATE_KEY_PATH, ED25519_PRIVATE_KEY_HEX, or ED25519_AUTO_GENERATE=true"
        )

    _token_engine = engine
    return engine


def _persist_auto_generated_key(engine: TokenEngine) -> None:
    """Save auto-generated key to data dir so it survives within the same deploy."""
    from pathlib import Path
    key_file = Path("./data/ed25519_auto.key")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    
    if key_file.exists():
        # Load existing auto-generated key
        try:
            engine.load_key_from_file(str(key_file), key_id="auto-generated")
            logger.info("auto_generated_key_restored", path=str(key_file))
            return
        except Exception as e:
            logger.warning("auto_key_restore_failed", error=str(e))

    # Save current key for persistence
    if engine._active_key:
        try:
            raw = engine._active_key.signing_key.encode()
            key_file.write_bytes(raw)
            logger.info("auto_generated_key_saved", path=str(key_file))
        except Exception as e:
            logger.warning("auto_key_save_failed", error=str(e))


def init_nonce_store() -> Union[InMemoryNonceStore, RedisNonceStore]:
    """Initialize nonce store. Uses Redis in production if available."""
    global _nonce_store
    settings = get_settings()

    if settings.REDIS_URL and settings.is_production:
        try:
            import redis.asyncio as aioredis
            client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            _nonce_store = RedisNonceStore(client)
            logger.info("nonce_store_initialized", backend="redis")
            return _nonce_store
        except Exception as e:
            logger.warning("redis_nonce_store_fallback", error=str(e))

    _nonce_store = InMemoryNonceStore(max_size=settings.MAX_NONCE_CACHE_SIZE)
    logger.info("nonce_store_initialized", backend="in_memory", max_size=settings.MAX_NONCE_CACHE_SIZE)
    return _nonce_store


def init_audit_logger() -> AuditLogger:
    """Initialize audit logger."""
    global _audit_logger
    settings = get_settings()
    _audit_logger = AuditLogger(log_path=settings.AUDIT_LOG_PATH)
    logger.info("audit_logger_initialized", path=settings.AUDIT_LOG_PATH)
    return _audit_logger


def init_license_service() -> LicenseService:
    """Initialize the license service with all dependencies."""
    global _license_service
    engine = _token_engine or init_token_engine()
    nonce = _nonce_store or init_nonce_store()
    audit = _audit_logger or init_audit_logger()
    _license_service = LicenseService(
        token_engine=engine,
        nonce_store=nonce,
        audit=audit,
    )
    logger.info("license_service_initialized")
    return _license_service


# ---------- FastAPI Dependency Callables ----------

def get_token_engine() -> TokenEngine:
    if _token_engine is None:
        raise RuntimeError("TokenEngine not initialized — call init_token_engine() at startup")
    return _token_engine


def get_nonce_store():
    if _nonce_store is None:
        raise RuntimeError("NonceStore not initialized — call init_nonce_store() at startup")
    return _nonce_store


def get_audit_logger() -> AuditLogger:
    if _audit_logger is None:
        raise RuntimeError("AuditLogger not initialized — call init_audit_logger() at startup")
    return _audit_logger


def get_license_service() -> LicenseService:
    if _license_service is None:
        raise RuntimeError("LicenseService not initialized — call init_license_service() at startup")
    return _license_service
