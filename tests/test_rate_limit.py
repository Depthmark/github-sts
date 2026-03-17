"""
Tests for GitHub API rate limit tracking and reachability probing.
Run with: pytest tests/test_rate_limit.py
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from github_sts.rate_limit import (
    RateLimitPoller,
    ReachabilityProber,
    extract_rate_limit_headers,
)


def _make_response(
    status_code: int = 200,
    headers: dict | None = None,
    json_data: dict | None = None,
) -> httpx.Response:
    """
    Create a mock httpx.Response with the given status, headers, and JSON body.
    """
    resp = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        json=json_data,
        request=httpx.Request("GET", "https://api.github.com/rate_limit"),
    )
    return resp


@pytest.fixture
def mock_app_config():
    """Create a mock AppConfig for testing (shared across all test classes)."""
    config = MagicMock()
    config.app_id = 12345
    config.private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
    )
    return config


class TestExtractRateLimitHeaders:
    """Unit tests for passive rate limit header extraction."""

    def test_extracts_standard_headers(self):
        """Intention: verify standard rate limit headers are parsed and update gauges.

        What is being tested:
        - `extract_rate_limit_headers()` correctly reads x-ratelimit-* headers
          and updates all 5 Prometheus gauges.

        Expected output:
        - All gauge values are set from the response headers.
        """
        resp = _make_response(
            status_code=200,
            headers={
                "x-ratelimit-limit": "5000",
                "x-ratelimit-remaining": "4990",
                "x-ratelimit-used": "10",
                "x-ratelimit-reset": "1700000000",
                "x-ratelimit-resource": "core",
            },
        )

        extract_rate_limit_headers(resp, app_name="default")

        from github_sts import metrics

        assert (
            metrics.GITHUB_RATE_LIMIT_LIMIT.labels(
                app="default", resource="core"
            )._value.get()
            == 5000.0
        )
        assert (
            metrics.GITHUB_RATE_LIMIT_REMAINING.labels(
                app="default", resource="core"
            )._value.get()
            == 4990.0
        )
        assert (
            metrics.GITHUB_RATE_LIMIT_USED.labels(
                app="default", resource="core"
            )._value.get()
            == 10.0
        )
        assert (
            metrics.GITHUB_RATE_LIMIT_RESET_TIMESTAMP.labels(
                app="default", resource="core"
            )._value.get()
            == 1700000000.0
        )
        pct = metrics.GITHUB_RATE_LIMIT_REMAINING_PERCENT.labels(
            app="default", resource="core"
        )._value.get()
        assert abs(pct - 99.8) < 0.1

    def test_defaults_to_core_resource(self):
        """Intention: verify missing x-ratelimit-resource defaults to 'core'.

        What is being tested:
        - When the resource header is absent, 'core' is used as default.

        Expected output:
        - Gauge update uses resource='core'.
        """
        resp = _make_response(
            status_code=200,
            headers={
                "x-ratelimit-limit": "5000",
                "x-ratelimit-remaining": "5000",
            },
        )

        extract_rate_limit_headers(resp, app_name="my-app")

        from github_sts import metrics

        assert (
            metrics.GITHUB_RATE_LIMIT_LIMIT.labels(
                app="my-app", resource="core"
            )._value.get()
            == 5000.0
        )

    def test_no_headers_is_safe(self):
        """Intention: verify no crash when rate limit headers are missing.

        What is being tested:
        - Calling extract_rate_limit_headers with no rate limit headers
          does not raise an exception.

        Expected output:
        - No exception raised.
        """
        resp = _make_response(status_code=200, headers={})
        extract_rate_limit_headers(resp, app_name="default")

    def test_detects_primary_rate_limit_exceeded(self):
        """Intention: verify HTTP 403 with remaining=0 triggers exceeded counter.

        What is being tested:
        - When GitHub returns 403 and x-ratelimit-remaining is 0,
          the primary rate limit exceeded counter is incremented.

        Expected output:
        - GITHUB_RATE_LIMIT_EXCEEDED_TOTAL counter is incremented.
        """
        resp = _make_response(
            status_code=403,
            headers={
                "x-ratelimit-limit": "5000",
                "x-ratelimit-remaining": "0",
                "x-ratelimit-used": "5000",
                "x-ratelimit-resource": "core",
            },
        )

        from github_sts import metrics

        before = metrics.GITHUB_RATE_LIMIT_EXCEEDED_TOTAL.labels(
            app="test-app", resource="core", caller="iss:sub"
        )._value.get()

        extract_rate_limit_headers(resp, app_name="test-app", caller="iss:sub")

        after = metrics.GITHUB_RATE_LIMIT_EXCEEDED_TOTAL.labels(
            app="test-app", resource="core", caller="iss:sub"
        )._value.get()
        assert after == before + 1

    def test_detects_secondary_rate_limit(self):
        """Intention: verify HTTP 403 with retry-after triggers secondary counter.

        What is being tested:
        - When GitHub returns 403 with a retry-after header (abuse limit),
          the secondary rate limit counter is incremented and retry-after
          gauge is set.

        Expected output:
        - GITHUB_SECONDARY_RATE_LIMIT_TOTAL counter is incremented.
        - GITHUB_SECONDARY_RATE_LIMIT_RETRY_AFTER gauge is set.
        """
        resp = _make_response(
            status_code=403,
            headers={
                "retry-after": "120",
                "x-ratelimit-limit": "5000",
                "x-ratelimit-remaining": "100",
                "x-ratelimit-resource": "core",
            },
        )

        from github_sts import metrics

        before = metrics.GITHUB_SECONDARY_RATE_LIMIT_TOTAL.labels(
            app="sec-app", caller="iss:sub"
        )._value.get()

        extract_rate_limit_headers(resp, app_name="sec-app", caller="iss:sub")

        after = metrics.GITHUB_SECONDARY_RATE_LIMIT_TOTAL.labels(
            app="sec-app", caller="iss:sub"
        )._value.get()
        assert after == before + 1

        retry = metrics.GITHUB_SECONDARY_RATE_LIMIT_RETRY_AFTER.labels(
            app="sec-app"
        )._value.get()
        assert retry == 120.0

    def test_invalid_header_values_ignored(self):
        """Intention: verify non-integer header values are silently ignored.

        What is being tested:
        - Headers with non-numeric values do not raise exceptions.

        Expected output:
        - No exception raised.
        """
        resp = _make_response(
            status_code=200,
            headers={
                "x-ratelimit-limit": "not-a-number",
                "x-ratelimit-remaining": "bad",
            },
        )
        extract_rate_limit_headers(resp, app_name="default")


class TestRateLimitPoller:
    """Unit tests for the active rate limit polling background task."""

    @pytest.mark.asyncio
    async def test_poller_creates_task(self, mock_app_config):
        """Intention: verify the poller starts a background task.

        What is being tested:
        - `RateLimitPoller.start()` creates an asyncio task.

        Expected output:
        - The internal _task attribute is set and not None.
        """
        poller = RateLimitPoller(
            apps={"default": mock_app_config},
            interval_seconds=60,
        )

        with patch.object(poller, "_poll_loop", new_callable=AsyncMock):
            await poller.start()
            assert poller._task is not None
            await poller.stop()

    @pytest.mark.asyncio
    async def test_poller_stop_cancels_task(self, mock_app_config):
        """Intention: verify the poller stops and cleans up.

        What is being tested:
        - `RateLimitPoller.stop()` cancels the background task.

        Expected output:
        - The internal _task attribute is set to None after stop.
        """
        poller = RateLimitPoller(
            apps={"default": mock_app_config},
            interval_seconds=60,
        )

        with patch.object(poller, "_poll_loop", new_callable=AsyncMock):
            await poller.start()
            await poller.stop()
            assert poller._task is None

    @pytest.mark.asyncio
    async def test_poll_with_token_updates_gauges(self, mock_app_config):
        """Intention: verify polling with an installation token updates all resource gauges.

        What is being tested:
        - `_poll_with_token()` uses the given installation token to call
          GET /rate_limit and sets gauges for each resource category.

        Expected output:
        - Gauges for 'core' and 'search' resources are set correctly.
        """
        rate_limit_response = {
            "resources": {
                "core": {
                    "limit": 5000,
                    "remaining": 4990,
                    "used": 10,
                    "reset": 1700000000,
                },
                "search": {
                    "limit": 30,
                    "remaining": 28,
                    "used": 2,
                    "reset": 1700000060,
                },
            },
        }

        mock_resp = _make_response(
            status_code=200,
            headers={
                "x-ratelimit-limit": "5000",
                "x-ratelimit-remaining": "4990",
                "x-ratelimit-used": "10",
                "x-ratelimit-reset": "1700000000",
                "x-ratelimit-resource": "core",
            },
            json_data=rate_limit_response,
        )

        poller = RateLimitPoller(
            apps={"default": mock_app_config},
            interval_seconds=60,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            await poller._poll_with_token("default", 99999, "fake-install-token")

            # Verify the installation token was used, not an App JWT
            call_kwargs = mock_client.get.call_args
            assert (
                call_kwargs[1]["headers"]["Authorization"] == "token fake-install-token"
            )

        from github_sts import metrics

        assert (
            metrics.GITHUB_RATE_LIMIT_LIMIT.labels(
                app="default", resource="core"
            )._value.get()
            == 5000.0
        )
        assert (
            metrics.GITHUB_RATE_LIMIT_REMAINING.labels(
                app="default", resource="search"
            )._value.get()
            == 28.0
        )

    @pytest.mark.asyncio
    async def test_get_installations_caches_result(self, mock_app_config):
        """Intention: verify installation list is fetched and cached.

        What is being tested:
        - `_get_installations()` calls GET /app/installations and caches
          the result so subsequent calls don't hit the API.

        Expected output:
        - First call returns the installation IDs.
        - Second call returns the same list without an API call.
        """
        installations_response = [
            {"id": 111, "account": {"login": "org1"}},
            {"id": 222, "account": {"login": "org2"}},
        ]

        mock_resp = _make_response(
            status_code=200,
            headers={},
            json_data=installations_response,
        )

        poller = RateLimitPoller(
            apps={"default": mock_app_config},
            interval_seconds=60,
        )

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                ids = await poller._get_installations("default", mock_app_config)
                assert ids == [111, 222]
                assert mock_client.get.call_count == 1

                # Second call should use cache (no new API call)
                ids2 = await poller._get_installations("default", mock_app_config)
                assert ids2 == [111, 222]
                assert mock_client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_get_token_creates_and_caches(self, mock_app_config):
        """Intention: verify installation token is created and cached.

        What is being tested:
        - `_get_token()` creates an installation token via the GitHub API
          and caches it for reuse.

        Expected output:
        - Returns the token string.
        - Second call returns cached token without API call.
        """
        token_response = {
            "token": "ghs_poller_token_abc",
            "expires_at": "2099-01-01T00:00:00Z",
        }

        mock_resp = _make_response(
            status_code=201,
            headers={},
            json_data=token_response,
        )

        poller = RateLimitPoller(
            apps={"default": mock_app_config},
            interval_seconds=60,
        )

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                token = await poller._get_token("default", mock_app_config, 111)
                assert token == "ghs_poller_token_abc"

                # Cached — no new API call
                token2 = await poller._get_token("default", mock_app_config, 111)
                assert token2 == "ghs_poller_token_abc"
                assert mock_client.post.call_count == 1


class TestReachabilityProber:
    """Unit tests for the GitHub reachability background probe."""

    @pytest.mark.asyncio
    async def test_prober_creates_task(self, mock_app_config):
        """Intention: verify the prober starts a background task.

        What is being tested:
        - `ReachabilityProber.start()` creates an asyncio task.

        Expected output:
        - The internal _task attribute is set and not None.
        """
        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        with patch.object(prober, "_probe_loop", new_callable=AsyncMock):
            await prober.start()
            assert prober._task is not None
            await prober.stop()

    @pytest.mark.asyncio
    async def test_probe_success_sets_reachable(self, mock_app_config):
        """Intention: verify a successful probe sets gauge to 1.

        What is being tested:
        - When GitHub API returns 200, the reachable gauge is set to 1.

        Expected output:
        - GITHUB_REACHABLE gauge is 1.0.
        """
        mock_resp = _make_response(status_code=200, headers={})

        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                await prober._probe_app("reach-default", mock_app_config)

        from github_sts import metrics

        assert metrics.GITHUB_REACHABLE.labels(app="reach-default")._value.get() == 1.0

    @pytest.mark.asyncio
    async def test_probe_timeout_sets_unreachable(self, mock_app_config):
        """Intention: verify a timeout sets the gauge to 0.

        What is being tested:
        - When the HTTP request times out, the reachable gauge is set to 0
          and the timeout failure counter is incremented.

        Expected output:
        - GITHUB_REACHABLE gauge is 0.0.
        - GITHUB_REACHABILITY_FAILURES_TOTAL with reason='timeout' is incremented.
        """
        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        from github_sts import metrics

        before = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="timeout-app", reason="timeout"
        )._value.get()

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(
                    side_effect=httpx.TimeoutException("timed out")
                )
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                await prober._probe_app("timeout-app", mock_app_config)

        assert metrics.GITHUB_REACHABLE.labels(app="timeout-app")._value.get() == 0.0
        after = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="timeout-app", reason="timeout"
        )._value.get()
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_probe_connection_error_sets_unreachable(self, mock_app_config):
        """Intention: verify a connection error sets the gauge to 0.

        What is being tested:
        - When the HTTP request fails with a connection error, the reachable
          gauge is set to 0 and the connection_error counter is incremented.

        Expected output:
        - GITHUB_REACHABLE gauge is 0.0.
        - GITHUB_REACHABILITY_FAILURES_TOTAL with reason='connection_error' is incremented.
        """
        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        from github_sts import metrics

        before = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="conn-app", reason="connection_error"
        )._value.get()

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(
                    side_effect=httpx.ConnectError("connection refused")
                )
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                await prober._probe_app("conn-app", mock_app_config)

        assert metrics.GITHUB_REACHABLE.labels(app="conn-app")._value.get() == 0.0
        after = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="conn-app", reason="connection_error"
        )._value.get()
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_probe_server_error_sets_unreachable(self, mock_app_config):
        """Intention: verify a 5xx response sets the gauge to 0.

        What is being tested:
        - When GitHub API returns a 5xx status code, the reachable gauge is
          set to 0 and the http_error counter is incremented.

        Expected output:
        - GITHUB_REACHABLE gauge is 0.0.
        - GITHUB_REACHABILITY_FAILURES_TOTAL with reason='http_error' is incremented.
        """
        mock_resp = _make_response(status_code=503, headers={})

        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        from github_sts import metrics

        before = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="5xx-app", reason="http_error"
        )._value.get()

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                await prober._probe_app("5xx-app", mock_app_config)

        assert metrics.GITHUB_REACHABLE.labels(app="5xx-app")._value.get() == 0.0
        after = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="5xx-app", reason="http_error"
        )._value.get()
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_probe_auth_error_still_reachable(self, mock_app_config):
        """Intention: verify a 401 counts as reachable but logs auth_error.

        What is being tested:
        - When GitHub API returns 401 (bad credentials), the reachable gauge
          is still set to 1 (GitHub is up) but an auth_error failure is counted.

        Expected output:
        - GITHUB_REACHABLE gauge is 1.0.
        - GITHUB_REACHABILITY_FAILURES_TOTAL with reason='auth_error' is incremented.
        """
        mock_resp = _make_response(status_code=401, headers={})

        prober = ReachabilityProber(
            apps={"default": mock_app_config},
            interval_seconds=30,
        )

        from github_sts import metrics

        before = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="auth-app", reason="auth_error"
        )._value.get()

        with patch("github_sts.rate_limit._generate_app_jwt", return_value="fake-jwt"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                await prober._probe_app("auth-app", mock_app_config)

        assert metrics.GITHUB_REACHABLE.labels(app="auth-app")._value.get() == 1.0
        after = metrics.GITHUB_REACHABILITY_FAILURES_TOTAL.labels(
            app="auth-app", reason="auth_error"
        )._value.get()
        assert after == before + 1
