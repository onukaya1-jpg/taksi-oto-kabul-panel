"""
Database Engine — Async SQLAlchemy
====================================
Supports both SQLite (development) and PostgreSQL (production/Render).
Auto-detects from DATABASE_URL scheme.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.settings import get_settings
from app.models import Base

_engine = None
_session_factory = None


def _normalize_database_url(url: str) -> str:
    """
    Normalize DATABASE_URL for async SQLAlchemy.
    Render.com provides postgres://... but asyncpg needs postgresql+asyncpg://...
    Also strips sslmode/channel_binding query params (asyncpg uses ssl=True instead).
    """
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and "+asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    # asyncpg doesn't support sslmode/channel_binding as query params
    # Strip them — SSL is handled via connect_args
    if "asyncpg" in url and "?" in url:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Remove asyncpg-incompatible params
        for key in ["sslmode", "channel_binding"]:
            params.pop(key, None)
        new_query = urlencode(params, doseq=True)
        url = urlunparse(parsed._replace(query=new_query))
    return url


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        raw_url = settings.DATABASE_URL
        use_ssl = "sslmode=require" in raw_url or "sslmode=verify" in raw_url
        db_url = _normalize_database_url(raw_url)
        
        # Connection pool settings differ by backend
        kwargs = {
            "echo": settings.is_development,
            "pool_pre_ping": True,
        }
        
        if "asyncpg" in db_url:
            # PostgreSQL connection pool. SSL only when the URL asks for it
            # (Neon and Render external URLs). Render internal URLs do not.
            kwargs.update({
                "pool_size": 2,
                "max_overflow": 2,
                "pool_timeout": 30,
            })
            if use_ssl:
                import ssl as _ssl
                ssl_ctx = _ssl.create_default_context()
                kwargs["connect_args"] = {"ssl": ssl_ctx}
        
        _engine = create_async_engine(db_url, **kwargs)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def init_db() -> None:
    """Create all tables and add missing columns for schema evolution."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Schema migration: add new columns if missing
        # (create_all won't add columns to existing tables)
        migrations = [
            ("licenses", "activated_at", "TIMESTAMP WITH TIME ZONE"),
            ("licenses", "duration_days", "INTEGER"),
            ("licenses", "duration_minutes", "INTEGER"),
            ("licenses", "product", "VARCHAR(32) NOT NULL DEFAULT 'gamestore'"),
            ("licenses", "customer_name", "VARCHAR(200)"),
            ("admin_commands", "signature", "VARCHAR(64)"),
        ]
        for table, column, col_type in migrations:
            try:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type}")
                )
            except Exception:
                pass  # column already exists or DB doesn't support IF NOT EXISTS

        try:
            await conn.execute(
                text(
                    "UPDATE licenses SET customer_name = split_part(notes, ': ', 1) "
                    "WHERE COALESCE(customer_name, '') = '' AND notes LIKE '%: %'"
                )
            )
        except Exception:
            pass

        # Lazy expiration fix: clear expires_at for keys that were never activated
        # These got expires_at from old imports before lazy system existed
        try:
            result = await conn.execute(
                text("UPDATE licenses SET expires_at = NULL WHERE activated_at IS NULL AND expires_at IS NOT NULL")
            )
            if result.rowcount and result.rowcount > 0:
                import structlog
                structlog.get_logger().info("lazy_expiration_fix", cleared=result.rowcount)
        except Exception:
            pass

        # Plan migration: rename old basic/premium → monthly
        try:
            result = await conn.execute(
                text("UPDATE licenses SET plan = 'monthly' WHERE plan IN ('basic', 'premium')")
            )
            if result.rowcount and result.rowcount > 0:
                import structlog
                structlog.get_logger().info("plan_migration", renamed=result.rowcount)
        except Exception:
            pass


async def get_db() -> AsyncSession:
    """Dependency for FastAPI — yields an async session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
