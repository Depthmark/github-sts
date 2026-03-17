"""
GitHub API rate limit tracking and reachability probing.

Provides:
  - Passive rate limit header extraction from any httpx response
  - Active background poller calling GET /rate_limit
  - Background reachability prober for GitHub API health monitoring
"""

import asyncio
import logging
import re
import time

import httpx
import jwt as pyjwt

from . import metrics
from .config import AppConfig

logger = logging.getLogger(__name__)

# GitHub API rate limit response header names
_HEADER_LIMIT = "x-ratelimit-limit"
_HEADER_REMAINING = "x-ratelimit-remaining"
_HEADER_USED = "x-ratelimit-used"
_HEADER_RESET = "x-ratelimit-reset"
_HEADER_RESOURCE = "x-ratelimit-resource"
_HEADER_RETRY_AFTER = "retry-after"

GITHUB_API = "https://api.github.com"

# Regex to extract the "next" URL from GitHub's Link header
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _parse_next_link(link_header: str) -> str | None:
    """Extract the 'next' URL from a GitHub Link header, or None."""
    m = _LINK_NEXT_RE.search(link_header)
    return m.group(1) if m else None


def extract_rate_limit_headers(
    response: httpx.Response,
    app_name: str,
    caller: str = "",
) -> None:
    """
    Parse GitHub rate limit headers from an httpx response and update
    Prometheus gauges.

    Also detects primary rate limit exceeded (403 + rate limit message)
    and secondary/abuse rate limits (403 + retry-after header).

    Args:
        response: The httpx response to extract headers from.
        app_name: The GitHub App name for metric labels.
        caller: The caller identifier (iss:sub) for rate limit exceeded events.
    """
    headers = response.headers

    # Determine the resource type from the header (default to "core")
    resource = headers.get(_HEADER_RESOURCE, "core")

    # Extract standard rate limit headers
    limit_str = headers.get(_HEADER_LIMIT)
    remaining_str = headers.get(_HEADER_REMAINING)
    used_str = headers.get(_HEADER_USED)
    reset_str = headers.get(_HEADER_RESET)

    if limit_str is not None:
        try:
            limit_val = int(limit_str)
            metrics.GITHUB_RATE_LIMIT_LIMIT.labels(app=app_name, resource=resource).set(
                limit_val
            )
        except ValueError:
            pass

    if remaining_str is not None:
        try:
            remaining_val = int(remaining_str)
            metrics.GITHUB_RATE_LIMIT_REMAINING.labels(
                app=app_name, resource=resource
            ).set(remaining_val)
        except ValueError:
            pass

    if used_str is not None:
        try:
            used_val = int(used_str)
            metrics.GITHUB_RATE_LIMIT_USED.labels(app=app_name, resource=resource).set(
                used_val
            )
        except ValueError:
            pass

    if reset_str is not None:
        try:
            reset_val = int(reset_str)
            metrics.GITHUB_RATE_LIMIT_RESET_TIMESTAMP.labels(
                app=app_name, resource=resource
            ).set(reset_val)
        except ValueError:
            pass

    # Compute remaining percentage
    if limit_str is not None and remaining_str is not None:
        try:
            limit_val = int(limit_str)
            remaining_val = int(remaining_str)
            if limit_val > 0:
                pct = (remaining_val / limit_val) * 100
                metrics.GITHUB_RATE_LIMIT_REMAINING_PERCENT.labels(
                    app=app_name, resource=resource
                ).set(pct)
        except ValueError:
            pass

    # Detect rate limit exceeded (HTTP 403)
    if response.status_code == 403:
        retry_after = headers.get(_HEADER_RETRY_AFTER)

        if retry_after is not None:
            # Secondary / abuse rate limit
            metrics.GITHUB_SECONDARY_RATE_LIMIT_TOTAL.labels(
                app=app_name, caller=caller
            ).inc()
            try:
                retry_seconds = int(retry_after)
                metrics.GITHUB_SECONDARY_RATE_LIMIT_RETRY_AFTER.labels(
                    app=app_name
                ).set(retry_seconds)
            except ValueError:
                pass
            logger.warning(
                "GitHub secondary rate limit hit: app=%s caller=%s retry_after=%s",
                app_name,
                caller,
                retry_after,
            )
        elif remaining_str is not None:
            try:
                if int(remaining_str) == 0:
                    # Primary rate limit exceeded
                    metrics.GITHUB_RATE_LIMIT_EXCEEDED_TOTAL.labels(
                        app=app_name, resource=resource, caller=caller
                    ).inc()
                    logger.warning(
                        "GitHub primary rate limit exceeded: app=%s resource=%s caller=%s",
                        app_name,
                        resource,
                        caller,
                    )
            except ValueError:
                pass


def _generate_app_jwt(app_config: AppConfig) -> str:
    """Generate a signed JWT to authenticate as the GitHub App."""
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": str(app_config.app_id),
    }
    return pyjwt.encode(
        payload,
        app_config.private_key,
        algorithm="RS256",
    )


class RateLimitPoller:
    """
    Periodically polls GET /rate_limit for every installation of each
    configured GitHub App and updates Prometheus gauges.

    Self-manages its own installation tokens:
      1. Discovers installations via GET /app/installations (App JWT auth)
      2. Creates installation tokens via POST /app/installations/{id}/access_tokens
      3. Caches and renews tokens automatically (5 min expiry buffer)
      4. Calls GET /rate_limit with the installation token

    This ensures the rate limits shown are from the installation-level pool
    (the same pool consumed by tokens issued to callers) and does not
    depend on user traffic or steal user-facing tokens.
    """

    def __init__(
        self,
        apps: dict[str, AppConfig],
        interval_seconds: int = 60,
    ):
        self._apps = apps
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None
        # Internal token cache: "{app_name}:{installation_id}" → (token, expires_epoch)
        self._token_cache: dict[str, tuple[str, float]] = {}
        # Installation list cache: app_name → ([installation_ids], fetched_at)
        self._installation_cache: dict[str, tuple[list[int], float]] = {}
        # Re-discover installations every 10 minutes
        self._installation_ttl = 600

    async def start(self) -> None:
        """Start the background polling task."""
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(
            "Rate limit poller started: interval=%ds, apps=%s",
            self._interval,
            list(self._apps.keys()),
        )

    async def stop(self) -> None:
        """Cancel the background polling task."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("Rate limit poller stopped")

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while True:
            try:
                await self._poll_all_apps()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Rate limit poll cycle failed: %s", exc)
            await asyncio.sleep(self._interval)

    async def _poll_all_apps(self) -> None:
        """Discover installations for every app and poll rate limits."""
        for app_name, app_config in self._apps.items():
            try:
                installation_ids = await self._get_installations(app_name, app_config)
                for install_id in installation_ids:
                    try:
                        token = await self._get_token(app_name, app_config, install_id)
                        await self._poll_with_token(app_name, install_id, token)
                    except Exception as exc:
                        logger.error(
                            "Rate limit poll failed: app=%s installation=%s error=%s",
                            app_name,
                            install_id,
                            exc,
                        )
            except Exception as exc:
                logger.error(
                    "Failed to list installations: app=%s error=%s",
                    app_name,
                    exc,
                )

    async def _get_installations(
        self, app_name: str, app_config: AppConfig
    ) -> list[int]:
        """List installation IDs for a GitHub App, with caching and pagination."""
        cached = self._installation_cache.get(app_name)
        if cached:
            ids, fetched_at = cached
            if time.time() - fetched_at < self._installation_ttl:
                return ids

        app_jwt = _generate_app_jwt(app_config)
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        }

        ids: list[int] = []
        async with httpx.AsyncClient(timeout=10) as client:
            url: str | None = f"{GITHUB_API}/app/installations?per_page=100"
            while url is not None:
                resp = await client.get(url, headers=headers)
                extract_rate_limit_headers(resp, app_name)

                if resp.status_code != 200:
                    logger.warning(
                        "Failed to list installations: app=%s status=%d",
                        app_name,
                        resp.status_code,
                    )
                    # Fall back to previously cached list if available
                    if cached:
                        return cached[0]
                    return []

                for installation in resp.json():
                    install_id = installation.get("id")
                    if install_id is not None:
                        ids.append(install_id)

                # Follow GitHub pagination via Link header
                url = _parse_next_link(resp.headers.get("link", ""))

        self._installation_cache[app_name] = (ids, time.time())
        logger.debug(
            "Discovered %d installations for app=%s",
            len(ids),
            app_name,
        )
        return ids

    async def _get_token(
        self, app_name: str, app_config: AppConfig, installation_id: int
    ) -> str:
        """Get or create an installation token for rate limit polling."""
        cache_key = f"{app_name}:{installation_id}"
        cached = self._token_cache.get(cache_key)
        if cached:
            token, expires_at = cached
            if time.time() < expires_at - 300:  # 5 min buffer
                return token

        app_jwt = _generate_app_jwt(app_config)
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
                headers=headers,
                json={},  # no special permissions needed
            )
            extract_rate_limit_headers(resp, app_name)
            resp.raise_for_status()

        data = resp.json()
        token = data["token"]
        from datetime import datetime

        expires_dt = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        expires_epoch = expires_dt.timestamp()
        self._token_cache[cache_key] = (token, expires_epoch)

        logger.debug(
            "Created poller token: app=%s installation=%s",
            app_name,
            installation_id,
        )
        return token

    async def _poll_with_token(
        self, app_name: str, installation_id: int, token: str
    ) -> None:
        """Poll rate limits using an installation access token."""
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{GITHUB_API}/rate_limit",
                headers=headers,
            )

            # Extract headers from the response itself
            extract_rate_limit_headers(resp, app_name)

            if resp.status_code != 200:
                logger.warning(
                    "Rate limit API returned %d for app=%s installation=%s",
                    resp.status_code,
                    app_name,
                    installation_id,
                )
                return

            data = resp.json()
            resources = data.get("resources", {})

            for resource_name, resource_data in resources.items():
                limit = resource_data.get("limit", 0)
                remaining = resource_data.get("remaining", 0)
                used = resource_data.get("used", 0)
                reset_ts = resource_data.get("reset", 0)

                metrics.GITHUB_RATE_LIMIT_LIMIT.labels(
                    app=app_name, resource=resource_name
                ).set(limit)
                metrics.GITHUB_RATE_LIMIT_REMAINING.labels(
                    app=app_name, resource=resource_name
                ).set(remaining)
                metrics.GITHUB_RATE_LIMIT_USED.labels(
                    app=app_name, resource=resource_name
                ).set(used)
                metrics.GITHUB_RATE_LIMIT_RESET_TIMESTAMP.labels(
                    app=app_name, resource=resource_name
                ).set(reset_ts)

                if limit > 0:
                    pct = (remaining / limit) * 100
                    metrics.GITHUB_RATE_LIMIT_REMAINING_PERCENT.labels(
                        app=app_name, resource=resource_name
                    ).set(pct)

        metrics.GITHUB_API_CALLS.labels(
            app=app_name, endpoint="get_rate_limit", result="ok"
        ).inc()

        logger.debug(
            "Rate limit poll complete: app=%s installation=%s",
            app_name,
            installation_id,
        )


class ReachabilityProber:
    """
    Periodically probes GitHub API reachability for each configured App.

    Sets the pygithubsts_github_reachable gauge to 1 (Up) or 0 (Down)
    and tracks probe latency and failure reasons.

    Uses GET /rate_limit as the health probe endpoint (lightweight,
    authenticated, and provides useful data as a side-effect).
    """

    def __init__(
        self,
        apps: dict[str, AppConfig],
        interval_seconds: int = 30,
    ):
        self._apps = apps
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the background probing task."""
        self._task = asyncio.create_task(self._probe_loop())
        logger.info(
            "Reachability prober started: interval=%ds, apps=%s",
            self._interval,
            list(self._apps.keys()),
        )

    async def stop(self) -> None:
        """Cancel the background probing task."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("Reachability prober stopped")

    async def _probe_loop(self) -> None:
        """Main probing loop."""
        while True:
            try:
                for app_name, app_config in self._apps.items():
                    await self._probe_app(app_name, app_config)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Reachability probe cycle failed: %s", exc)
            await asyncio.sleep(self._interval)

    async def _probe_app(self, app_name: str, app_config: AppConfig) -> None:
        """Probe reachability for a single GitHub App."""
        start = time.time()
        try:
            app_jwt = _generate_app_jwt(app_config)
            headers = {
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            }

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{GITHUB_API}/rate_limit",
                    headers=headers,
                )

            elapsed = time.time() - start
            metrics.GITHUB_REACHABILITY_CHECK_DURATION.labels(app=app_name).observe(
                elapsed
            )

            if resp.status_code == 401:
                # The App JWT is rejected — GitHub is reachable but auth fails
                metrics.GITHUB_REACHABLE.labels(app=app_name).set(1)
                metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
                    app=app_name, reason="auth_error"
                ).inc()
                logger.warning(
                    "GitHub reachable but auth failed: app=%s status=%d",
                    app_name,
                    resp.status_code,
                )
            elif resp.status_code >= 500:
                metrics.GITHUB_REACHABLE.labels(app=app_name).set(0)
                metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
                    app=app_name, reason="http_error"
                ).inc()
                logger.warning(
                    "GitHub API server error: app=%s status=%d",
                    app_name,
                    resp.status_code,
                )
            else:
                # 200, 304, 403 (rate limited) — GitHub is reachable
                metrics.GITHUB_REACHABLE.labels(app=app_name).set(1)
                logger.debug(
                    "GitHub reachable: app=%s latency=%.3fs",
                    app_name,
                    elapsed,
                )

        except httpx.TimeoutException:
            elapsed = time.time() - start
            metrics.GITHUB_REACHABILITY_CHECK_DURATION.labels(app=app_name).observe(
                elapsed
            )
            metrics.GITHUB_REACHABLE.labels(app=app_name).set(0)
            metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
                app=app_name, reason="timeout"
            ).inc()
            logger.warning("GitHub reachability probe timed out: app=%s", app_name)

        except httpx.ConnectError:
            elapsed = time.time() - start
            metrics.GITHUB_REACHABILITY_CHECK_DURATION.labels(app=app_name).observe(
                elapsed
            )
            metrics.GITHUB_REACHABLE.labels(app=app_name).set(0)
            metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
                app=app_name, reason="connection_error"
            ).inc()
            logger.warning(
                "GitHub reachability probe connection error: app=%s", app_name
            )

        except Exception as exc:
            elapsed = time.time() - start
            metrics.GITHUB_REACHABILITY_CHECK_DURATION.labels(app=app_name).observe(
                elapsed
            )
            metrics.GITHUB_REACHABLE.labels(app=app_name).set(0)
            metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
                app=app_name, reason="connection_error"
            ).inc()
            logger.error(
                "GitHub reachability probe failed: app=%s error=%s",
                app_name,
                exc,
            )
