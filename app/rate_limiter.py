"""
Rate Limiter — Token Bucket per IP
=====================================
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Bucket:
    tokens: float
    last_refill: float = field(default_factory=time.time)


class RateLimiter:
    """Simple in-memory token-bucket rate limiter per IP."""

    def __init__(self, per_minute: int = 30, burst: int = 10):
        self._rate = per_minute / 60.0  # tokens per second
        self._burst = burst
        self._buckets: dict[str, Bucket] = defaultdict(lambda: Bucket(tokens=burst))

    def allow(self, key: str) -> bool:
        """Check and consume one token. Returns True if allowed."""
        bucket = self._buckets[key]
        now = time.time()

        # Refill
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rate)
        bucket.last_refill = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True

        logger.warning("rate_limit_exceeded", key=key, tokens=bucket.tokens)
        return False

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove stale buckets. Returns count removed."""
        now = time.time()
        stale = [k for k, v in self._buckets.items() if now - v.last_refill > max_age_seconds]
        for k in stale:
            del self._buckets[k]
        return len(stale)
