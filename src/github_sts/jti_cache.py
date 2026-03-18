"""
JTI (JWT ID) cache for replay attack prevention.

Tokens with the same JTI claim should only be accepted once.
This module provides interfaces and implementations for tracking seen JTIs.
"""

import asyncio
import time
from abc import ABC, abstractmethod


class JTICache(ABC):
    """Abstract interface for JTI caching backends."""

    @abstractmethod
    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        """
        Check if JTI has been seen before, and store it if new.

        Args:
            jti: JWT ID claim value
            expires_at: Unix timestamp when token expires

        Returns:
            True if JTI is new and has been stored (non-replay)
            False if JTI has been seen before (REPLAY - reject)

        Raises:
            Exception: On backend errors (fail-closed, reject request)
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources (close connections, etc)."""
        pass


class InMemoryJTICache(JTICache):
    """
    Simple in-memory JTI cache using a dictionary.

    ⚠️  WARNING: Does NOT survive process restarts.
    Best for development and single-instance deployments.
    For production multi-instance setups, use RedisJTICache.
    """

    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize in-memory cache.

        Args:
            ttl_seconds: Time-to-live for cache entries (default: 1 hour)
        """
        self.ttl_seconds = ttl_seconds
        self._seen_jtis: dict[str, int] = {}  # {jti: expiry_timestamp}
        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task | None = None

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        """Check if JTI has been seen, store if new."""
        async with self._lock:
            now = time.time()

            # Clean up expired entries (opportunistic cleanup)
            expired_jtis = [j for j, exp in self._seen_jtis.items() if exp < now]
            for j in expired_jtis:
                del self._seen_jtis[j]

            # Check if JTI has been seen
            if jti in self._seen_jtis:
                # Already seen - this is a replay attempt
                return False

            # New JTI - store it with expiry time
            self._seen_jtis[jti] = max(expires_at, now + self.ttl_seconds)
            return True

    async def cleanup(self) -> None:
        """Clean up resources."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


class RedisJTICache(JTICache):
    """
    Redis-backed JTI cache for distributed deployments.

    Advantages:
    - Shared across multiple instances
    - Automatic expiration via Redis TTL
    - Thread-safe and async-friendly

    Requires:
    - redis package: pip install redis
    """

    def __init__(self, redis_url: str, ttl_seconds: int = 3600):
        """
        Initialize Redis JTI cache.

        Args:
            redis_url: Redis connection URL, e.g., redis://localhost:6379/0
            ttl_seconds: Time-to-live for cache entries

        Raises:
            ImportError: If redis is not installed
        """
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError as e:
            raise ImportError(
                "redis package required for RedisJTICache. "
                "Install with: pip install redis"
            ) from e

        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self._redis = redis.from_url(
            redis_url,
            encoding="utf8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
        )
        self._key_prefix = "sts:jti:"

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        """Check if JTI has been seen, store if new using Redis."""
        try:
            key = f"{self._key_prefix}{jti}"
            now = time.time()

            # Use SET with NX (only if not exists) and EX (with expiry)
            # This is atomic and prevents replays
            ttl = max(self.ttl_seconds, int(expires_at - now + 1))
            result = await self._redis.set(
                key,
                "1",
                nx=True,  # Only set if not exists
                ex=ttl,  # Expire after ttl seconds
            )

            # result is True if SET succeeded (new JTI)
            # result is None if key already exists (replay)
            return result is True

        except Exception as e:
            # On Redis error, fail-closed: reject request
            # This is safer than allowing potential replays
            raise JTICacheError(f"JTI cache check failed: {e}") from e

    async def cleanup(self) -> None:
        """Close Redis connection."""
        try:
            await self._redis.close()
        except Exception:
            pass  # Already closed or connection error


class JTICacheError(Exception):
    """Raised when JTI cache operations fail."""

    pass


async def create_jti_cache(
    backend: str,
    redis_url: str | None = None,
    ttl_seconds: int = 3600,
) -> JTICache:
    """
    Factory function to create appropriate JTI cache backend.

    Args:
        backend: "memory" or "redis"
        redis_url: Redis URL (required if backend="redis")
        ttl_seconds: Cache TTL in seconds

    Returns:
        Configured JTICache instance

    Raises:
        ValueError: If backend is invalid or redis_url missing
    """
    if backend == "memory":
        return InMemoryJTICache(ttl_seconds=ttl_seconds)
    elif backend == "redis":
        if not redis_url:
            raise ValueError("redis_url required when backend='redis'")
        return RedisJTICache(redis_url=redis_url, ttl_seconds=ttl_seconds)
    else:
        raise ValueError(
            f"Unknown JTI cache backend: {backend!r}. Valid options: 'memory', 'redis'"
        )
