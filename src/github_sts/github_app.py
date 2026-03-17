"""
GitHub App token provider.

Generates short-lived installation tokens scoped to a repo (scope)
with only the permissions defined in the trust policy.

Supports multiple GitHub Apps — each identified by name in the config.
"""

import logging
import time

import httpx
import jwt as pyjwt  # PyJWT (not python-jose) for signing App JWTs

from . import metrics
from .config import AppConfig, get_settings
from .rate_limit import extract_rate_limit_headers

logger = logging.getLogger(__name__)

# Cache: (app_name, scope) → installation_id
_installation_id_cache: dict[str, int] = {}


class GitHubAppTokenProvider:
    """
    Issues short-lived GitHub installation tokens with fine-grained permissions.

    Each instance is bound to a specific GitHub App (by name in config).
    """

    GITHUB_API = "https://api.github.com"

    def __init__(self, app_name: str, app_config: AppConfig):
        self._app_name = app_name
        self._app_config = app_config

    def _generate_app_jwt(self) -> str:
        """Generate a signed JWT to authenticate as the GitHub App itself."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # issued 60s ago (clock skew)
            "exp": now + 600,  # valid for 10 minutes
            "iss": str(self._app_config.app_id),
        }
        return pyjwt.encode(
            payload,
            self._app_config.private_key,
            algorithm="RS256",
        )

    async def _get_installation_id(self, scope: str, caller: str = "") -> int:
        """
        Resolve a scope ("org/repo" or "org") to a GitHub App installation ID.
        Results are cached indefinitely (installations rarely change).
        """
        id_cache_key = f"{self._app_name}:{scope}"
        if id_cache_key in _installation_id_cache:
            return _installation_id_cache[id_cache_key]

        app_jwt = self._generate_app_jwt()
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        }

        # Try repo installation first, then org
        parts = scope.split("/", 1)
        urls = []
        if len(parts) == 2:
            urls.append(f"{self.GITHUB_API}/repos/{scope}/installation")
        urls.append(f"{self.GITHUB_API}/orgs/{parts[0]}/installation")

        async with httpx.AsyncClient(timeout=10) as client:
            for url in urls:
                try:
                    resp = await client.get(url, headers=headers)
                    extract_rate_limit_headers(resp, self._app_name, caller)
                    if resp.status_code == 200:
                        installation_id = resp.json()["id"]
                        _installation_id_cache[id_cache_key] = installation_id
                        metrics.GITHUB_API_CALLS.labels(
                            app=self._app_name, endpoint="get_installation", result="ok"
                        ).inc()
                        return installation_id
                except httpx.HTTPError:
                    continue

        metrics.GITHUB_API_CALLS.labels(
            app=self._app_name, endpoint="get_installation", result="not_found"
        ).inc()
        raise ValueError(
            f"GitHub App {self._app_name!r} not installed for scope {scope!r}"
        )

    async def get_installation_token(
        self,
        scope: str,
        permissions: dict[str, str] | None = None,
        caller: str = "",
    ) -> str:
        """
        Get a short-lived installation access token.

        If permissions are provided, the token will be scoped to exactly
        those permissions (subset of what the app has installed).
        """
        installation_id = await self._get_installation_id(scope, caller=caller)

        # Create new token
        app_jwt = self._generate_app_jwt()
        body: dict = {}
        if scope and "/" in scope:
            body["repositories"] = [scope.split("/", 1)[1]]
        if permissions:
            body["permissions"] = permissions

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{self.GITHUB_API}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                },
                json=body,
            )
            extract_rate_limit_headers(resp, self._app_name, caller)
            resp.raise_for_status()

        data = resp.json()
        token = data["token"]

        perm_str = ",".join(f"{k}:{v}" for k, v in (permissions or {}).items())
        metrics.GITHUB_TOKEN_ISSUED.labels(
            app=self._app_name, scope=scope, permissions=perm_str
        ).inc()
        metrics.GITHUB_API_CALLS.labels(
            app=self._app_name, endpoint="create_installation_token", result="ok"
        ).inc()

        # SECURITY: Never log token values — only metadata (app, scope, permissions)
        logger.info(
            "Issued GitHub token: app=%s scope=%s permissions=%s",
            self._app_name,
            scope,
            perm_str,
        )
        return token  # SECURITY: token must not be logged at any level


def get_token_provider(app_name: str) -> GitHubAppTokenProvider:
    """
    Factory: get a GitHubAppTokenProvider for a named app.

    Raises KeyError if the app is not configured.
    """
    settings = get_settings()
    app_config = settings.get_app(app_name)
    return GitHubAppTokenProvider(app_name, app_config)
