"""
Tests for multi-app GitHub App support.

Validates that metrics include the `app` label for all app-specific operations,
enabling proper per-app observability in multi-app deployments.

Run with: pytest tests/test_multi_app.py
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from github_sts import metrics
from github_sts.policy_loader import (
    DatabasePolicyLoader,
    GitHubPolicyLoader,
    _policy_cache,
)

VALID_POLICY_YAML = """
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
permissions:
  contents: read
"""


def _make_github_response(
    status_code: int = 200,
    text: str = VALID_POLICY_YAML,
    json_data: dict | None = None,
) -> httpx.Response:
    """Create a mock httpx.Response for GitHub API calls."""
    if json_data is not None:
        return httpx.Response(
            status_code=status_code,
            json=json_data,
            request=httpx.Request("GET", "https://api.github.com/test"),
        )
    return httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("GET", "https://api.github.com/test"),
    )


class TestPolicyLoaderMetricsAppLabel:
    """Verify that policy loader metrics include the `app` label."""

    async def test_github_loader_cache_miss_includes_app_label(self):
        """Intention: verify POLICY_CACHE_MISSES carries the app label on a cache miss.

        What is being tested:
        - `GitHubPolicyLoader.load()` records a cache miss with app=<app_name>
          when no cached policy is present.

        Expected output:
        - POLICY_CACHE_MISSES metric incremented with app="test-app".
        """
        _policy_cache.clear()

        mock_provider = AsyncMock()
        mock_provider.get_installation_token = AsyncMock(return_value="fake-token")

        loader = GitHubPolicyLoader(mock_provider)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get = AsyncMock(
                return_value=_make_github_response(
                    status_code=200, text=VALID_POLICY_YAML
                )
            )

            before = metrics.POLICY_CACHE_MISSES.labels(app="test-app")._value.get()
            await loader.load("org/repo", "test-app", "ci")
            after = metrics.POLICY_CACHE_MISSES.labels(app="test-app")._value.get()

        assert after == before + 1, "Expected one cache miss for app=test-app"

    async def test_github_loader_cache_hit_includes_app_label(self):
        """Intention: verify POLICY_CACHE_HITS carries the app label on a cache hit.

        What is being tested:
        - `GitHubPolicyLoader.load()` records a cache hit with app=<app_name>
          when a valid policy is already cached.

        Expected output:
        - POLICY_CACHE_HITS metric incremented with app="cached-app".
        """
        _policy_cache.clear()

        mock_provider = AsyncMock()
        mock_provider.get_installation_token = AsyncMock(return_value="fake-token")

        loader = GitHubPolicyLoader(mock_provider)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get = AsyncMock(
                return_value=_make_github_response(
                    status_code=200, text=VALID_POLICY_YAML
                )
            )
            # First load populates the cache
            await loader.load("org/repo", "cached-app", "ci")

            # Second load should hit cache
            before = metrics.POLICY_CACHE_HITS.labels(app="cached-app")._value.get()
            await loader.load("org/repo", "cached-app", "ci")
            after = metrics.POLICY_CACHE_HITS.labels(app="cached-app")._value.get()

        assert after == before + 1, "Expected one cache hit for app=cached-app"

    async def test_github_loader_success_includes_app_label(self):
        """Intention: verify POLICY_LOADS_TOTAL carries the app label on success.

        What is being tested:
        - `GitHubPolicyLoader.load()` records a successful load with app=<app_name>.

        Expected output:
        - POLICY_LOADS_TOTAL metric incremented with app="load-app", result="ok".
        """
        _policy_cache.clear()

        mock_provider = AsyncMock()
        mock_provider.get_installation_token = AsyncMock(return_value="fake-token")

        loader = GitHubPolicyLoader(mock_provider)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get = AsyncMock(
                return_value=_make_github_response(
                    status_code=200, text=VALID_POLICY_YAML
                )
            )

            before = metrics.POLICY_LOADS_TOTAL.labels(
                app="load-app", backend="github", result="ok"
            )._value.get()
            await loader.load("org/repo", "load-app", "ci")
            after = metrics.POLICY_LOADS_TOTAL.labels(
                app="load-app", backend="github", result="ok"
            )._value.get()

        assert after == before + 1, "Expected one successful load for app=load-app"

    async def test_github_loader_not_found_includes_app_label(self):
        """Intention: verify POLICY_LOADS_TOTAL carries app label on 404.

        What is being tested:
        - `GitHubPolicyLoader.load()` records a not_found result with app=<app_name>
          when GitHub returns 404.

        Expected output:
        - POLICY_LOADS_TOTAL metric incremented with app="missing-app", result="not_found".
        """
        _policy_cache.clear()

        mock_provider = AsyncMock()
        mock_provider.get_installation_token = AsyncMock(return_value="fake-token")

        loader = GitHubPolicyLoader(mock_provider)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get = AsyncMock(
                return_value=_make_github_response(status_code=404, text="not found")
            )

            before = metrics.POLICY_LOADS_TOTAL.labels(
                app="missing-app", backend="github", result="not_found"
            )._value.get()
            result = await loader.load("org/repo", "missing-app", "ci")
            after = metrics.POLICY_LOADS_TOTAL.labels(
                app="missing-app", backend="github", result="not_found"
            )._value.get()

        assert result is None
        assert after == before + 1, "Expected one not_found for app=missing-app"

    async def test_database_loader_cache_miss_includes_app_label(self):
        """Intention: verify DatabasePolicyLoader cache miss includes app label.

        What is being tested:
        - `DatabasePolicyLoader.load()` records cache misses with app=<app_name>.

        Expected output:
        - POLICY_CACHE_MISSES metric incremented with app="db-app".
        """
        _policy_cache.clear()

        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value=None)

        loader = DatabasePolicyLoader(db_pool=mock_pool)

        before = metrics.POLICY_CACHE_MISSES.labels(app="db-app")._value.get()
        await loader.load("org/repo", "db-app", "ci")
        after = metrics.POLICY_CACHE_MISSES.labels(app="db-app")._value.get()

        assert after == before + 1, "Expected one cache miss for db-app"

    async def test_database_loader_not_found_includes_app_label(self):
        """Intention: verify DatabasePolicyLoader not_found metric includes app label.

        What is being tested:
        - `DatabasePolicyLoader.load()` records not_found with app=<app_name>
          when the database returns no matching row.

        Expected output:
        - POLICY_LOADS_TOTAL metric incremented with app="db-not-found", result="not_found".
        """
        _policy_cache.clear()

        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value=None)

        loader = DatabasePolicyLoader(db_pool=mock_pool)

        before = metrics.POLICY_LOADS_TOTAL.labels(
            app="db-not-found", backend="database", result="not_found"
        )._value.get()
        result = await loader.load("org/repo", "db-not-found", "ci")
        after = metrics.POLICY_LOADS_TOTAL.labels(
            app="db-not-found", backend="database", result="not_found"
        )._value.get()

        assert result is None
        assert after == before + 1, "Expected one not_found for db-not-found app"

    async def test_different_apps_have_separate_metric_counts(self):
        """Intention: verify that metrics for different apps are independently tracked.

        What is being tested:
        - Loading policies for two different apps results in separate metric time series,
          so each app can be monitored independently.

        Expected output:
        - POLICY_CACHE_MISSES for app="app-alpha" and app="app-beta" are each incremented
          once, independently of each other.
        """
        _policy_cache.clear()

        mock_provider = AsyncMock()
        mock_provider.get_installation_token = AsyncMock(return_value="fake-token")

        loader = GitHubPolicyLoader(mock_provider)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get = AsyncMock(
                return_value=_make_github_response(
                    status_code=200, text=VALID_POLICY_YAML
                )
            )

            before_alpha = metrics.POLICY_CACHE_MISSES.labels(
                app="app-alpha"
            )._value.get()
            before_beta = metrics.POLICY_CACHE_MISSES.labels(
                app="app-beta"
            )._value.get()

            await loader.load("org/repo", "app-alpha", "ci")
            await loader.load("org/repo", "app-beta", "ci")

            after_alpha = metrics.POLICY_CACHE_MISSES.labels(
                app="app-alpha"
            )._value.get()
            after_beta = metrics.POLICY_CACHE_MISSES.labels(app="app-beta")._value.get()

        assert after_alpha == before_alpha + 1, "app-alpha should have 1 cache miss"
        assert after_beta == before_beta + 1, "app-beta should have 1 cache miss"


class TestGitHubAppTokenProviderMetricsAppLabel:
    """Verify that GitHubAppTokenProvider metrics include the `app` label."""

    @pytest.fixture
    def mock_app_config(self):
        config = MagicMock()
        config.app_id = 12345
        config.private_key = (
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        )
        return config

    async def test_get_installation_token_api_call_includes_app_label(
        self, mock_app_config
    ):
        """Intention: verify GITHUB_API_CALLS for token creation includes app label.

        What is being tested:
        - `GitHubAppTokenProvider.get_installation_token()` increments GITHUB_API_CALLS
          with the correct app label.

        Expected output:
        - GITHUB_API_CALLS with app="token-app", endpoint="create_installation_token",
          result="ok" is incremented.
        - GITHUB_TOKEN_ISSUED with app="token-app" is incremented.
        """
        from github_sts.github_app import (
            GitHubAppTokenProvider,
            _installation_id_cache,
        )

        # Pre-populate installation ID cache to skip that API call
        _installation_id_cache["token-app:org/repo"] = 999

        provider = GitHubAppTokenProvider("token-app", mock_app_config)

        mock_token_response = {
            "token": "ghs_fake_token_12345",
            "expires_at": "2099-01-01T00:00:00Z",
        }

        with patch("jwt.encode", return_value="fake.jwt.token"):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__.return_value = mock_client
                mock_client.post = AsyncMock(
                    return_value=httpx.Response(
                        status_code=201,
                        json=mock_token_response,
                        request=httpx.Request(
                            "POST",
                            "https://api.github.com/app/installations/999/access_tokens",
                        ),
                    )
                )

                before_api = metrics.GITHUB_API_CALLS.labels(
                    app="token-app",
                    endpoint="create_installation_token",
                    result="ok",
                )._value.get()
                before_issued = metrics.GITHUB_TOKEN_ISSUED.labels(
                    app="token-app",
                    scope="org/repo",
                    permissions="contents:read",
                )._value.get()

                await provider.get_installation_token(
                    "org/repo", {"contents": "read"}, "test-caller"
                )

                after_api = metrics.GITHUB_API_CALLS.labels(
                    app="token-app",
                    endpoint="create_installation_token",
                    result="ok",
                )._value.get()
                after_issued = metrics.GITHUB_TOKEN_ISSUED.labels(
                    app="token-app",
                    scope="org/repo",
                    permissions="contents:read",
                )._value.get()

        assert after_api == before_api + 1, (
            "Expected GITHUB_API_CALLS to be incremented"
        )
        assert after_issued == before_issued + 1, (
            "Expected GITHUB_TOKEN_ISSUED to be incremented"
        )
