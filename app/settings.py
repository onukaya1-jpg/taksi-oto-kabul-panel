"""
GameStore Auth Server — Settings
=================================
Pydantic Settings: .env → Environment → Defaults
Production secrets MUST come from vault/CI, never from code.
"""

from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8443
    WORKERS: int = 4
    ENVIRONMENT: str = "development"  # production | staging | development

    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/auth.db"

    # --- Redis ---
    REDIS_URL: str = ""  # Empty = use in-memory nonce store (set redis:// URL for multi-instance)

    # --- Ed25519 Keys ---
    ED25519_PRIVATE_KEY_PATH: str = ""
    ED25519_PUBLIC_KEY_PATH: str = ""
    ED25519_PRIVATE_KEY_HEX: str = ""  # Alternative: key as hex env var (for Render/Heroku)
    ED25519_AUTO_GENERATE: bool = True  # Auto-generate ephemeral key if none provided
    # Vault integration (production)
    VAULT_URL: str = ""
    VAULT_TOKEN: str = ""
    VAULT_KEY_PATH: str = ""

    # --- Admin ---
    ADMIN_API_KEY: str = ""  # Required for /admin/* endpoints
    COMMAND_HMAC_SECRET: str = ""  # Shared secret for signing admin commands (HMAC-SHA256)

    # --- GitHub Backup (auto-save licenses to repo) ---
    GITHUB_PAT: str = ""  # Personal access token with repo write scope
    GITHUB_REPO: str = ""

    # --- mTLS ---
    TLS_CERT_PATH: str = "./certs/server.crt"
    TLS_KEY_PATH: str = "./certs/server.key"
    TLS_CA_CERT_PATH: str = "./certs/ca.crt"
    MTLS_ENABLED: bool = False

    # --- Token ---
    TOKEN_TTL_SECONDS: int = Field(default=300, ge=60, le=600)
    NONCE_TTL_SECONDS: int = Field(default=600, ge=120, le=1800)
    MAX_NONCE_CACHE_SIZE: int = 100_000

    # --- Rate Limiting ---
    RATE_LIMIT_PER_MINUTE: int = 120
    RATE_LIMIT_BURST: int = 40

    # --- Audit ---
    AUDIT_LOG_PATH: str = "./audit_log/audit.jsonl"
    AUDIT_LOG_LEVEL: str = "INFO"
    LOKI_URL: str = ""
    ELASTICSEARCH_URL: str = ""

    # --- Alerts ---
    ALERT_WEBHOOK_URL: str = ""
    ALERT_REPEATED_AUTH_FAILURES_THRESHOLD: int = 5
    ALERT_INVALID_HWID_THRESHOLD: int = 3

    # --- Key Rotation ---
    KEY_ROTATION_DAYS: int = 7
    KEY_OVERLAP_HOURS: int = 24

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    def validate_production(self) -> list[str]:
        """Validate settings for production readiness."""
        errors = []
        # mTLS is optional for cloud PaaS (Render/Railway handle TLS)
        if not self.ED25519_PRIVATE_KEY_PATH and not self.ED25519_PRIVATE_KEY_HEX \
                and not self.VAULT_URL and not self.ED25519_AUTO_GENERATE:
            errors.append("Ed25519 key required: set ED25519_PRIVATE_KEY_PATH, ED25519_PRIVATE_KEY_HEX, or ED25519_AUTO_GENERATE=true")
        if not self.ADMIN_API_KEY:
            errors.append("ADMIN_API_KEY required in production")
        # Warnings (non-blocking)
        if "sqlite" in self.DATABASE_URL:
            import structlog
            structlog.get_logger().warning("sqlite_in_production", hint="Consider PostgreSQL for production")
        return errors


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
