"""
Nonce Store — Replay Protection
=================================
Tracks used nonces to prevent token replay attacks.
Supports Redis (production) and in-memory (development) backends.
"""

import time
from collections import OrderedDict
from typing import Protocol

import structlog

logger = structlog.get_logger(__name__)


class NonceStore(Protocol):
    """Protocol for nonce storage backends."""

    async def is_used(self, nonce: str) -> bool:
        """Check if nonce was already used."""
        ...

    async def mark_used(self, nonce: str, ttl_seconds: int) -> None:
        """Mark nonce as used with expiry."""
        ...

    async def cleanup(self) -> int:
        """Remove expired entries. Returns count removed."""
        ...


class InMemoryNonceStore:
    """
    In-memory nonce store for development / single-instance deployments.
    Uses OrderedDict with TTL-based expiry.
    NOT suitable for multi-instance production (use Redis).
    """

    def __init__(self, max_size: int = 100_000):
        self._store: OrderedDict[str, float] = OrderedDict()  # nonce -> expiry_time
        self._max_size = max_size

    async def is_used(self, nonce: str) -> bool:
        if nonce in self._store:
            expiry = self._store[nonce]
            if time.time() < expiry:
                return True
            else:
                # Expired — remove
                del self._store[nonce]
                return False
        return False

    async def mark_used(self, nonce: str, ttl_seconds: int) -> None:
        # Evict oldest if at capacity
        while len(self._store) >= self._max_size:
            self._store.popitem(last=False)

        self._store[nonce] = time.time() + ttl_seconds

    async def cleanup(self) -> int:
        now = time.time()
        expired = [k for k, v in self._store.items() if v <= now]
        for k in expired:
            del self._store[k]
        return len(expired)

    @property
    def size(self) -> int:
        return len(self._store)


class RedisNonceStore:
    """
    Redis-backed nonce store for production multi-instance deployments.
    Uses Redis SET with EX (expiry) for automatic cleanup.
    """

    def __init__(self, redis_client: "redis.asyncio.Redis") -> None:  # type: ignore[name-defined]
        self._redis = redis_client
        self._prefix = "nonce:"

    async def is_used(self, nonce: str) -> bool:
        result = await self._redis.exists(f"{self._prefix}{nonce}")
        return bool(result)

    async def mark_used(self, nonce: str, ttl_seconds: int) -> None:
        await self._redis.set(f"{self._prefix}{nonce}", "1", ex=ttl_seconds)

    async def cleanup(self) -> int:
        # Redis handles TTL-based cleanup automatically
        return 0
