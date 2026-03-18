"""
Dynamic policy storage backends.

Each backend implements `PolicyLoader`, which resolves
(scope, app_name, identity) → TrustPolicy.

scope    = "org/repo"  (the repo whose policy file is consulted)
app_name = "my-app"    (GitHub App name; maps to a directory under base_path)
identity = "ci"        (filename stem under app_name directory)

Policy file path in repo:
  {base_path}/{app_name}/{identity}.sts.yaml
  e.g. .github/sts/my-app/ci.sts.yaml
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod

import httpx
import yaml
from pydantic import ValidationError

from . import metrics
from .config import get_settings
from .policy import TrustPolicy

logger = logging.getLogger(__name__)

# ── Simple in-memory TTL cache ────────────────────────────────────────────────


class _CacheEntry:
    __slots__ = ("expires_at", "policy")

    def __init__(self, policy: TrustPolicy | None, ttl: int):
        self.policy = policy
        self.expires_at = time.monotonic() + ttl


_policy_cache: dict[str, _CacheEntry] = {}
_cache_lock = asyncio.Lock()


async def _get_cached(key: str) -> tuple[bool, TrustPolicy | None] | None:
    """Returns (hit, policy) or None if not in cache."""
    async with _cache_lock:
        entry = _policy_cache.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del _policy_cache[key]
            return None
        return True, entry.policy


async def _set_cached(key: str, policy: TrustPolicy | None, ttl: int):
    async with _cache_lock:
        _policy_cache[key] = _CacheEntry(policy, ttl)


# ── Abstract base ─────────────────────────────────────────────────────────────


class PolicyLoader(ABC):
    """Base class for all policy backends."""

    @abstractmethod
    async def load(
        self, scope: str, app_name: str, identity: str
    ) -> TrustPolicy | None:
        """Load and return a TrustPolicy, or None if not found."""
        ...

    def _parse(
        self, raw_yaml: str, source: str, backend: str, app_name: str
    ) -> TrustPolicy | None:
        try:
            data = yaml.safe_load(raw_yaml)
            policy = TrustPolicy(**data)
            metrics.POLICY_LOADS_TOTAL.labels(
                app=app_name, backend=backend, result="ok"
            ).inc()
            return policy
        except (yaml.YAMLError, ValidationError, TypeError) as exc:
            logger.warning("Failed to parse policy from %s: %s", source, exc)
            metrics.POLICY_LOADS_TOTAL.labels(
                app=app_name, backend=backend, result="parse_error"
            ).inc()
            return None


# ── GitHub backend ────────────────────────────────────────────────────────────


class GitHubPolicyLoader(PolicyLoader):
    """
    Fetches trust policies directly from GitHub repos.

    Policy path:
      {base_path}/{app_name}/{identity}.sts.yaml
      e.g. .github/sts/my-app/ci.sts.yaml

    Uses a GitHub App installation token for private repos.
    """

    GITHUB_API = "https://api.github.com"

    def __init__(self, app_token_provider):
        self._token_provider = app_token_provider

    async def load(
        self, scope: str, app_name: str, identity: str
    ) -> TrustPolicy | None:
        settings = get_settings()
        cache_key = f"github:{scope}:{app_name}:{identity}"
        ttl = settings.policy.cache_ttl_seconds

        if ttl > 0:
            cached = await _get_cached(cache_key)
            if cached is not None:
                metrics.POLICY_CACHE_HITS.labels(app=app_name).inc()
                _, policy = cached
                return policy
            metrics.POLICY_CACHE_MISSES.labels(app=app_name).inc()

        policy = await self._fetch_from_github(scope, app_name, identity)

        if ttl > 0:
            await _set_cached(cache_key, policy, ttl)

        return policy

    async def _fetch_from_github(
        self, scope: str, app_name: str, identity: str
    ) -> TrustPolicy | None:
        settings = get_settings()
        base_path = settings.policy.base_path.rstrip("/")
        path = f"{base_path}/{app_name}/{identity}.sts.yaml"
        url = f"{self.GITHUB_API}/repos/{scope}/contents/{path}"

        try:
            token = await self._token_provider.get_installation_token(scope)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    url,
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.raw+json",
                    },
                )
                if resp.status_code == 404:
                    metrics.POLICY_LOADS_TOTAL.labels(
                        app=app_name, backend="github", result="not_found"
                    ).inc()
                    return None
                resp.raise_for_status()
                return self._parse(resp.text, url, "github", app_name)
        except httpx.HTTPError as exc:
            logger.error(
                "GitHub API error fetching policy %s/%s/%s: %s",
                scope,
                app_name,
                identity,
                exc,
            )
            metrics.POLICY_LOADS_TOTAL.labels(
                app=app_name, backend="github", result="http_error"
            ).inc()
            return None


# ── Database backend ──────────────────────────────────────────────────────────


class DatabasePolicyLoader(PolicyLoader):
    """
    Loads policies from a relational database.

    Schema (SQL):
        CREATE TABLE trust_policies (
            scope     TEXT NOT NULL,       -- e.g. "org/repo"
            app_name  TEXT NOT NULL,       -- e.g. "my-app"
            identity  TEXT NOT NULL,       -- e.g. "ci"
            policy    TEXT NOT NULL,       -- YAML content
            enabled   BOOLEAN DEFAULT TRUE,
            updated_at TIMESTAMP DEFAULT now(),
            PRIMARY KEY (scope, app_name, identity)
        );
    """

    def __init__(self, db_pool=None):
        self._pool = db_pool  # asyncpg or aiosqlite pool, injected at startup

    async def load(
        self, scope: str, app_name: str, identity: str
    ) -> TrustPolicy | None:
        settings = get_settings()
        cache_key = f"db:{scope}:{app_name}:{identity}"
        ttl = settings.policy.cache_ttl_seconds

        if ttl > 0:
            cached = await _get_cached(cache_key)
            if cached is not None:
                metrics.POLICY_CACHE_HITS.labels(app=app_name).inc()
                _, policy = cached
                return policy
            metrics.POLICY_CACHE_MISSES.labels(app=app_name).inc()

        policy = await self._query(scope, app_name, identity)

        if ttl > 0:
            await _set_cached(cache_key, policy, ttl)

        return policy

    async def _query(
        self, scope: str, app_name: str, identity: str
    ) -> TrustPolicy | None:
        if self._pool is None:
            logger.error("DatabasePolicyLoader: no db pool configured")
            metrics.POLICY_LOADS_TOTAL.labels(
                app=app_name, backend="database", result="no_pool"
            ).inc()
            return None

        try:
            row = await self._pool.fetchrow(
                "SELECT policy FROM trust_policies "
                "WHERE scope = $1 AND app_name = $2 AND identity = $3 AND enabled = TRUE",
                scope,
                app_name,
                identity,
            )
            if row is None:
                metrics.POLICY_LOADS_TOTAL.labels(
                    app=app_name, backend="database", result="not_found"
                ).inc()
                return None
            return self._parse(
                row["policy"], f"db:{scope}/{app_name}/{identity}", "database", app_name
            )
        except Exception as exc:
            logger.error(
                "DB error loading policy %s/%s/%s: %s",
                scope,
                app_name,
                identity,
                exc,
            )
            metrics.POLICY_LOADS_TOTAL.labels(
                app=app_name, backend="database", result="db_error"
            ).inc()
            return None


# ── Factory ───────────────────────────────────────────────────────────────────


def get_policy_loader(app_token_provider=None, db_pool=None) -> PolicyLoader:
    """Return the configured policy loader."""
    settings = get_settings()
    backend = settings.policy.backend

    if backend == "github":
        if app_token_provider is None:
            raise ValueError("GitHubPolicyLoader requires app_token_provider")
        return GitHubPolicyLoader(app_token_provider)

    if backend == "database":
        return DatabasePolicyLoader(db_pool)

    raise ValueError(f"Unknown policy backend: {backend!r}")
