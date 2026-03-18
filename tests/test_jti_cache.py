"""
Tests for JTI (JWT ID) replay prevention cache.
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from github_sts.jti_cache import (
    InMemoryJTICache,
    RedisJTICache,
    create_jti_cache,
)


class TestInMemoryJTICache:
    """Unit tests for the in-memory replay-prevention cache."""

    @pytest.mark.asyncio
    async def test_new_jti_returns_true(self):
        """Intention: verify unseen JTIs are accepted.

        What is being tested:
        - `check_and_store()` stores a fresh identifier.

        Expected output:
        - The first insertion returns `True`.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)
        exp = int(time.time()) + 3600
        result = await cache.check_and_store("jti-123", exp)
        assert result is True
        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_duplicate_jti_returns_false(self):
        """Intention: verify replay detection blocks token reuse.

        What is being tested:
        - The same JTI cannot be stored twice before it expires.

        Expected output:
        - The first call returns `True`.
        - The second call returns `False`.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)
        exp = int(time.time()) + 3600
        jti = "jti-replay-test"

        # First attempt
        result1 = await cache.check_and_store(jti, exp)
        assert result1 is True

        # Second attempt (replay)
        result2 = await cache.check_and_store(jti, exp)
        assert result2 is False

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_different_jtis_both_allowed(self):
        """Intention: verify uniqueness is tracked per JTI value.

        What is being tested:
        - Two different JTIs do not interfere with one another.

        Expected output:
        - Both calls return `True`.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)
        exp = int(time.time()) + 3600

        result1 = await cache.check_and_store("jti-1", exp)
        result2 = await cache.check_and_store("jti-2", exp)

        assert result1 is True
        assert result2 is True

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_expired_jti_can_be_reused(self):
        """Intention: verify expired entries stop blocking new requests.

        What is being tested:
        - Opportunistic cleanup removes expired JTIs.

        Expected output:
        - A JTI is accepted once, expires, then is accepted again.
        """
        cache = InMemoryJTICache(ttl_seconds=1)  # 1 second TTL
        jti = "jti-expiring"
        now = int(time.time())

        # Store JTI with immediate expiry
        result1 = await cache.check_and_store(jti, now)
        assert result1 is True

        # Wait for expiry
        await asyncio.sleep(1.1)

        # Same JTI should be allowed again after expiry
        result2 = await cache.check_and_store(jti, now + 10)
        assert result2 is True

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Intention: verify concurrent callers still admit only one winner.

        What is being tested:
        - The internal lock prevents races when multiple tasks use the same JTI.

        Expected output:
        - Exactly one call returns `True` and the others return `False`.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)
        exp = int(time.time()) + 3600
        jti = "jti-concurrent"

        # Simulate concurrent access
        tasks = [
            cache.check_and_store(jti, exp),
            cache.check_and_store(jti, exp),
            cache.check_and_store(jti, exp),
        ]

        results = await asyncio.gather(*tasks)

        # Only one should succeed (the race winner)
        assert results.count(True) == 1
        assert results.count(False) == 2

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup(self):
        """Intention: verify the no-op cleanup path is safe.

        What is being tested:
        - Calling `cleanup()` on the in-memory cache does not raise.

        Expected output:
        - The coroutine completes successfully.
        """
        cache = InMemoryJTICache()
        await cache.cleanup()
        # Should not raise


class TestRedisJTICache:
    """Targeted tests for Redis cache error handling without Redis dependency."""

    def test_redis_missing_import(self):
        """Intention: verify Redis support fails clearly when dependency is absent.

        What is being tested:
        - `RedisJTICache` surfaces a helpful `ImportError` if `redis` cannot be imported.

        Expected output:
        - Construction raises `ImportError` mentioning the missing package.
        """
        with patch.dict("sys.modules", {"redis": None}):
            with pytest.raises(ImportError, match="redis package required"):
                with patch(
                    "builtins.__import__",
                    side_effect=ImportError("No module named 'redis'"),
                ):
                    RedisJTICache(redis_url="redis://localhost:6379/0")


class TestCreateJTICache:
    """Unit tests for the JTI cache factory."""

    @pytest.mark.asyncio
    async def test_create_memory_cache(self):
        """Intention: verify the factory resolves the in-memory backend.

        What is being tested:
        - `create_jti_cache("memory")` returns the expected class.

        Expected output:
        - The returned instance is `InMemoryJTICache`.
        """
        cache = await create_jti_cache("memory")
        assert isinstance(cache, InMemoryJTICache)
        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_create_redis_without_url(self):
        """Intention: verify Redis configuration is validated early.

        What is being tested:
        - The factory rejects the Redis backend when `redis_url` is missing.

        Expected output:
        - A `ValueError` is raised.
        """
        with pytest.raises(ValueError, match="redis_url required"):
            await create_jti_cache("redis")

    @pytest.mark.asyncio
    async def test_create_invalid_backend(self):
        """Intention: verify unsupported backend names are rejected.

        What is being tested:
        - The factory rejects unknown backend identifiers.

        Expected output:
        - A `ValueError` is raised with a helpful message.
        """
        with pytest.raises(ValueError, match="Unknown JTI cache backend"):
            await create_jti_cache("invalid-backend")

    @pytest.mark.asyncio
    async def test_create_with_custom_ttl(self):
        """Intention: verify factory options propagate to created caches.

        What is being tested:
        - The custom TTL reaches the in-memory cache constructor.

        Expected output:
        - The created cache reports the provided `ttl_seconds` value.
        """
        cache = await create_jti_cache("memory", ttl_seconds=1800)
        assert cache.ttl_seconds == 1800
        await cache.cleanup()


class TestJTICacheIntegration:
    """Integration-style tests for realistic replay-prevention flows."""

    @pytest.mark.asyncio
    async def test_realistic_token_flow(self):
        """Intention: verify replay prevention in a realistic workload scenario.

        What is being tested:
        - A workflow token can be exchanged once.
        - Reusing the same token is rejected.
        - A different workflow run with a new JTI is accepted.

        Expected output:
        - Results are `True`, then `False`, then `True`.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)
        now = int(time.time())

        # Simulate token exchange for GitHub Actions workload
        token_claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:owner/repo:ref:refs/heads/main",
            "jti": "workflow-run-123",
            "exp": now + 300,  # 5 minute token
        }

        jti = token_claims["jti"]
        exp = token_claims["exp"]

        # First exchange succeeds
        assert await cache.check_and_store(jti, exp) is True

        # Immediate retry with same token should fail (replay)
        assert await cache.check_and_store(jti, exp) is False

        # Different JTI (different workflow run) should succeed
        token_claims["jti"] = "workflow-run-456"
        assert await cache.check_and_store(token_claims["jti"], exp) is True

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_jti_expiry_cleanup(self):
        """Intention: verify opportunistic cleanup removes expired cache entries.

        What is being tested:
        - Expired JTIs disappear after a later cache access.

        Expected output:
        - The internal cache size decreases after expiry and a new insertion.
        """
        cache = InMemoryJTICache(ttl_seconds=1)
        now = int(time.time())

        # Store multiple JTIs
        for i in range(5):
            jti = f"jti-{i}"
            await cache.check_and_store(jti, now + 1)

        initial_count = len(cache._seen_jtis)
        assert initial_count == 5

        # Wait for expiry
        await asyncio.sleep(1.1)

        # Access cache to trigger cleanup
        await cache.check_and_store("new-jti", now + 3600)

        # Expired entries should be removed
        final_count = len(cache._seen_jtis)
        assert final_count < initial_count

        await cache.cleanup()

    @pytest.mark.asyncio
    async def test_jti_with_missing_exp(self):
        """Intention: verify callers without a usable `exp` still get replay protection.

        What is being tested:
        - The cache falls back to its TTL when `expires_at` is zero.

        Expected output:
        - The first insertion succeeds and the second is rejected as a replay.
        """
        cache = InMemoryJTICache(ttl_seconds=3600)

        # No exp provided
        result = await cache.check_and_store("jti-no-exp", 0)
        assert result is True

        # Should still prevent replay
        result = await cache.check_and_store("jti-no-exp", 0)
        assert result is False

        await cache.cleanup()
