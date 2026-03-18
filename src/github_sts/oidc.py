"""
OIDC token validation.

Supports any OIDC-compliant issuer:
  - GitHub Actions  (https://token.actions.githubusercontent.com)
  - Google          (https://accounts.google.com)
  - Azure AD        (https://login.microsoftonline.com/{tenant}/v2.0)
  - Keycloak, Okta, etc.

Fetches JWKS from the issuer's discovery document and caches it.
"""

import logging
import time
from typing import Any

import httpx
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError

from . import metrics

logger = logging.getLogger(__name__)

# JWKS cache: issuer → (jwks_dict, fetched_at)
_jwks_cache: dict[str, tuple[dict, float]] = {}
JWKS_CACHE_TTL = 3600  # 1 hour


async def _get_jwks(issuer: str) -> dict:
    """Fetch and cache JWKS for an OIDC issuer."""
    now = time.time()
    cached = _jwks_cache.get(issuer)
    if cached and (now - cached[1]) < JWKS_CACHE_TTL:
        return cached[0]

    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        disc = await client.get(discovery_url)
        disc.raise_for_status()
        jwks_uri = disc.json()["jwks_uri"]

        jwks_resp = await client.get(jwks_uri)
        jwks_resp.raise_for_status()
        jwks = jwks_resp.json()

    _jwks_cache[issuer] = (jwks, now)
    logger.debug("Refreshed JWKS for issuer %s", issuer)
    return jwks


async def validate_oidc_token(
    token: str,
    expected_audience: str | None = None,
    allowed_issuers: list[str] | None = None,
) -> dict[str, Any]:
    """
    Validate an OIDC/JWT token and return its claims.

    Raises ValueError with a human-readable reason on failure.
    """
    # Decode header to find issuer without verification first
    try:
        unverified = jwt.get_unverified_claims(token)
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        metrics.OIDC_VALIDATION_ERRORS.labels(
            issuer="unknown", reason="malformed"
        ).inc()
        raise ValueError(f"Malformed JWT: {exc}") from exc

    issuer = unverified.get("iss", "")

    if not allowed_issuers:
        logger.warning(
            "No allowed_issuers configured — accepting token from issuer %s without restriction",
            issuer,
        )
    elif issuer not in allowed_issuers:
        metrics.OIDC_VALIDATION_ERRORS.labels(
            issuer=issuer, reason="issuer_not_allowed"
        ).inc()
        raise ValueError(f"Issuer {issuer!r} is not in the allowed list")

    # Fetch JWKS and validate
    try:
        jwks = await _get_jwks(issuer)
    except Exception as exc:
        metrics.OIDC_VALIDATION_ERRORS.labels(
            issuer=issuer, reason="jwks_fetch_failed"
        ).inc()
        raise ValueError(f"Could not fetch JWKS for issuer {issuer!r}: {exc}") from exc

    options = {
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_aud": expected_audience is not None,
    }

    try:
        claims = jwt.decode(
            token,
            jwks,
            algorithms=unverified_header.get("alg", "RS256"),
            audience=expected_audience,
            options=options,
        )
        logger.debug(
            "OIDC token validated for sub=%s iss=%s",
            claims.get("sub"),
            claims.get("iss"),
        )
        return claims

    except ExpiredSignatureError as err:
        metrics.OIDC_VALIDATION_ERRORS.labels(issuer=issuer, reason="expired").inc()
        raise ValueError("OIDC token has expired") from err

    except JWTClaimsError as exc:
        metrics.OIDC_VALIDATION_ERRORS.labels(issuer=issuer, reason="claims").inc()
        raise ValueError(f"OIDC token claims invalid: {exc}") from exc

    except JWTError as exc:
        metrics.OIDC_VALIDATION_ERRORS.labels(issuer=issuer, reason="signature").inc()
        raise ValueError(f"OIDC token signature invalid: {exc}") from exc
