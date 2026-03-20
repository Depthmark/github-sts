"""
Token exchange route.

  GET /sts/exchange?scope=org/repo&app=my-app&identity=ci
  Authorization: Bearer <oidc-token>

Policy is resolved from:
  {base_path}/{app}/{identity}.sts.yaml
  e.g. .github/sts/my-app/ci.sts.yaml
"""

import hashlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .. import metrics
from ..audit import AuditEvent, ExchangeResult
from ..config import get_settings
from ..github_app import get_token_provider
from ..jti_cache import JTICacheError
from ..oidc import validate_oidc_token
from ..policy_loader import get_policy_loader

logger = logging.getLogger(__name__)
router = APIRouter()
security = HTTPBearer()


# Response Models for OpenAPI Documentation
class TokenExchangeResponse(BaseModel):
    """Successful token exchange response."""

    token: str = Field(..., description="Short-lived GitHub installation token")
    scope: str = Field(..., description="Target repository or organization scope")
    app: str = Field(..., description="GitHub App name used for this exchange")
    identity: str = Field(..., description="Trust policy identity that was evaluated")
    permissions: dict[str, str] = Field(
        ..., description="Permissions granted in the token"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "token": "ghu_16C7e42F292c6912E7710c838347Ae178B4a",
                    "scope": "octocat/Hello-World",
                    "app": "default",
                    "identity": "ci",
                    "permissions": {
                        "contents": "read",
                        "pull_requests": "write",
                    },
                }
            ]
        }
    )


class ErrorResponse(BaseModel):
    """Error response."""

    detail: str = Field(..., description="Error description")


def _resolve_app_name(app_param: str | None) -> str:
    """
    Resolve the app name from query param or default.

    If no app param is given and exactly one app is configured, use it.
    Otherwise raise an HTTPException.
    """
    settings = get_settings()

    if app_param:
        # Validate it exists
        if app_param not in settings.apps:
            available = ", ".join(settings.app_names) or "(none)"
            raise HTTPException(
                status_code=400,
                detail=f"Unknown app {app_param!r}. Available: {available}",
            )
        return app_param

    # No app param — try default
    default = settings.default_app_name
    if default:
        return default

    if not settings.apps:
        raise HTTPException(
            status_code=500,
            detail="No GitHub Apps configured. Set apps in config or PYGITHUBSTS_GITHUB_APP_ID env var.",
        )

    available = ", ".join(settings.app_names)
    raise HTTPException(
        status_code=400,
        detail=f"Multiple apps configured — 'app' query parameter required. Available: {available}",
    )


@router.get(
    "/exchange",
    response_model=TokenExchangeResponse,
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Missing or invalid app parameter",
        },
        401: {
            "model": ErrorResponse,
            "description": "OIDC token invalid or expired",
        },
        403: {
            "model": ErrorResponse,
            "description": "OIDC claims do not satisfy trust policy",
        },
        404: {
            "model": ErrorResponse,
            "description": "Trust policy not found for scope/app/identity",
        },
        409: {
            "model": ErrorResponse,
            "description": "JTI replay attack detected - token already used",
        },
        500: {
            "model": ErrorResponse,
            "description": "Internal server error",
        },
    },
    summary="Exchange OIDC Token for GitHub Token",
    description="Exchange a workload OIDC token for a short-lived, scoped GitHub installation token. "
    "Supports any OIDC-compliant issuer. Validates token claims against a trust policy "
    "located at {base_path}/{app}/{identity}.sts.yaml in the target repository.",
)
async def exchange_token(
    scope: str = Query(
        ..., description="Target repo (org/repo) or org", examples=["octocat/Hello-World"]
    ),
    identity: str = Query(
        ..., description="Trust policy identity to evaluate", examples=["ci"]
    ),
    app: str | None = Query(
        None,
        description="GitHub App name (optional if only one app is configured)",
        examples=["default"],
    ),
    credentials: HTTPAuthorizationCredentials = Depends(security),  # noqa: B008
    request: Request = None,
):
    """
    Exchange an OIDC token for a short-lived GitHub installation token.

    **Process:**
    1. Validates the bearer OIDC token (signature, expiry, issuer)
    2. Checks JTI claim for replay attacks
    3. Resolves the GitHub App by name
    4. Loads the trust policy from {base_path}/{app}/{identity}.sts.yaml
    5. Evaluates the policy against the OIDC token's claims
    6. If approved, issues a GitHub installation token with exact permissions

    **Authentication:**
    - Bearer token in Authorization header (OIDC token)
    - Token will be validated against issuer's JWKS

    **Returns:**
    - Short-lived GitHub installation token
    - Scoped to repository/organization
    - With fine-grained permissions from trust policy
    """
    settings = get_settings()
    start = time.time()
    audit_logger = getattr(request.app.state, "audit_logger", None) if request else None
    user_agent = request.headers.get("user-agent", "") if request else ""
    remote_ip = request.client.host if request and request.client else ""

    # Resolve app name (may raise 400)
    app_name = _resolve_app_name(app)

    try:
        # ── Step 1: Validate OIDC token ───────────────────────────────────────
        try:
            # Audience is validated after policy load (policy may specify expected audience).
            claims = await validate_oidc_token(
                credentials.credentials,
                allowed_issuers=settings.allowed_issuers_list,
            )
        except ValueError as exc:
            metrics.TOKEN_EXCHANGES_TOTAL.labels(
                app=app_name,
                scope=scope,
                identity=identity,
                caller="unknown",
                result="oidc_invalid",
            ).inc()
            error_msg = str(exc)[:100]
            if audit_logger:
                await audit_logger.log_event(
                    AuditEvent(
                        scope=scope,
                        identity=identity,
                        issuer="unknown",
                        subject="unknown",
                        result=ExchangeResult.OIDC_INVALID,
                        error_reason=error_msg,
                        duration_ms=(time.time() - start) * 1000,
                        user_agent=user_agent[:100],
                        remote_ip=remote_ip,
                    )
                )
                metrics.AUDIT_EVENTS_LOGGED.labels(result="oidc_invalid").inc()
            raise HTTPException(status_code=401, detail=error_msg) from exc

        issuer = claims.get("iss", "unknown")
        subject = claims.get("sub", "unknown")
        # Use only issuer for the Prometheus label to avoid unbounded
        # cardinality (sub is issuer-controlled and can be very high-cardinality).
        # The full iss:sub is still captured in structured logs / audit events.
        caller = issuer
        policy_path = f"{settings.policy.base_path}/{app_name}/{identity}.sts.yaml"

        # Log all OIDC claims as a structured JSON object at DEBUG level.
        # This preserves the original claim shape from any provider
        # (GitHub Actions, Azure AD, GCP, Kubernetes, Okta, etc.)
        # for easy parsing with jq, Loki, Datadog, etc.
        logger.debug(
            "OIDC token validated — all claims attached",
            extra={"oidc_claims": dict(claims.items())},
        )

        logger.info(
            "Incoming exchange: scope=%s app=%s identity=%s iss=%s sub=%s policy_path=%s",
            scope,
            app_name,
            identity,
            issuer,
            subject,
            policy_path,
        )

        # ── Step 1.5: Check JTI (replay prevention) ───────────────────────────
        # Use the jti claim if present; otherwise fall back to a SHA-256 hash
        # of the raw bearer token so replay prevention works for issuers
        # (e.g. Azure AD) that don't emit a jti claim.
        jti = claims.get("jti")
        if not jti:
            jti = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        exp = claims.get("exp")
        if request:
            jti_cache = getattr(request.app.state, "jti_cache", None)
            if jti_cache:
                try:
                    is_new = await jti_cache.check_and_store(jti, exp)
                    if not is_new:
                        metrics.JTI_REPLAY_ATTEMPTS.inc()
                        logger.warning(
                            "JTI replay attempt: jti=%s iss=%s sub=%s scope=%s app=%s",
                            jti,
                            issuer,
                            subject,
                            scope,
                            app_name,
                        )
                        if audit_logger:
                            await audit_logger.log_event(
                                AuditEvent(
                                    scope=scope,
                                    identity=identity,
                                    issuer=issuer,
                                    subject=subject,
                                    jti=jti[:50],
                                    result=ExchangeResult.JTI_REPLAY,
                                    error_reason="Token already used",
                                    duration_ms=(time.time() - start) * 1000,
                                    user_agent=user_agent[:100],
                                    remote_ip=remote_ip,
                                )
                            )
                            metrics.AUDIT_EVENTS_LOGGED.labels(
                                result="jti_replay"
                            ).inc()
                        raise HTTPException(
                            status_code=409,
                            detail="OIDC token has already been used (replay)",
                        )
                except JTICacheError as exc:
                    logger.error("JTI cache error: %s", exc)
                    metrics.JTI_CACHE_ERRORS.labels(error_type="cache_check").inc()
                    if audit_logger:
                        await audit_logger.log_event(
                            AuditEvent(
                                scope=scope,
                                identity=identity,
                                issuer=issuer,
                                subject=subject,
                                jti=jti[:50] if jti else None,
                                result=ExchangeResult.CACHE_ERROR,
                                error_reason="JTI cache unavailable",
                                duration_ms=(time.time() - start) * 1000,
                                user_agent=user_agent[:100],
                                remote_ip=remote_ip,
                            )
                        )
                        metrics.AUDIT_EVENTS_LOGGED.labels(result="cache_error").inc()
                    raise HTTPException(
                        status_code=500,
                        detail="JTI validation service unavailable",
                    ) from exc
            else:
                logger.warning("No JTI cache available for replay prevention")

        # ── Step 2: Load trust policy ─────────────────────────────────────────
        provider = get_token_provider(app_name)
        loader = get_policy_loader(app_token_provider=provider)
        policy = await loader.load(scope, app_name, identity)

        if policy is None:
            metrics.TOKEN_EXCHANGES_TOTAL.labels(
                app=app_name,
                scope=scope,
                identity=identity,
                caller=caller,
                result="policy_not_found",
            ).inc()
            if audit_logger:
                await audit_logger.log_event(
                    AuditEvent(
                        scope=scope,
                        identity=identity,
                        issuer=issuer,
                        subject=subject,
                        jti=jti[:50] if jti else None,
                        result=ExchangeResult.POLICY_NOT_FOUND,
                        error_reason=(
                            f"No policy at {settings.policy.base_path}/{app_name}/{identity}.sts.yaml"
                        ),
                        duration_ms=(time.time() - start) * 1000,
                        user_agent=user_agent[:100],
                        remote_ip=remote_ip,
                    )
                )
                metrics.AUDIT_EVENTS_LOGGED.labels(result="policy_not_found").inc()
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No trust policy found at "
                    f"{settings.policy.base_path}/{app_name}/{identity}.sts.yaml "
                    f"in {scope!r}"
                ),
            )

        # ── Step 2b: Validate audience if policy requires it ─────────────────
        if policy.audience:
            token_aud = claims.get("aud")
            # aud can be a string or a list of strings per JWT spec
            aud_list = [token_aud] if isinstance(token_aud, str) else (token_aud or [])
            if policy.audience not in aud_list:
                metrics.TOKEN_EXCHANGES_TOTAL.labels(
                    app=app_name,
                    scope=scope,
                    identity=identity,
                    caller=caller,
                    result="denied",
                ).inc()
                error_reason = f"Audience mismatch: policy requires {policy.audience!r}"
                logger.warning(
                    "Audience denied: scope=%s app=%s identity=%s expected_aud=%s actual_aud=%s",
                    scope,
                    app_name,
                    identity,
                    policy.audience,
                    token_aud,
                )
                if audit_logger:
                    await audit_logger.log_event(
                        AuditEvent(
                            scope=scope,
                            identity=identity,
                            issuer=issuer,
                            subject=subject,
                            jti=jti[:50] if jti else None,
                            result=ExchangeResult.POLICY_DENIED,
                            error_reason=error_reason,
                            duration_ms=(time.time() - start) * 1000,
                            user_agent=user_agent[:100],
                            remote_ip=remote_ip,
                        )
                    )
                    metrics.AUDIT_EVENTS_LOGGED.labels(result="policy_denied").inc()
                raise HTTPException(
                    status_code=403,
                    detail="OIDC token audience does not match trust policy",
                )

        # ── Step 3: Evaluate policy ───────────────────────────────────────────
        if not policy.evaluate(claims):
            metrics.TOKEN_EXCHANGES_TOTAL.labels(
                app=app_name,
                scope=scope,
                identity=identity,
                caller=caller,
                result="denied",
            ).inc()
            logger.warning(
                "Policy denied: scope=%s app=%s identity=%s iss=%s sub=%s",
                scope,
                app_name,
                identity,
                issuer,
                subject,
            )
            if audit_logger:
                await audit_logger.log_event(
                    AuditEvent(
                        scope=scope,
                        identity=identity,
                        issuer=issuer,
                        subject=subject,
                        jti=jti[:50] if jti else None,
                        result=ExchangeResult.POLICY_DENIED,
                        error_reason="OIDC claims do not satisfy trust policy",
                        duration_ms=(time.time() - start) * 1000,
                        user_agent=user_agent[:100],
                        remote_ip=remote_ip,
                    )
                )
                metrics.AUDIT_EVENTS_LOGGED.labels(result="policy_denied").inc()
            raise HTTPException(
                status_code=403,
                detail="OIDC token claims do not satisfy the trust policy",
            )

        # ── Step 4: Issue GitHub token ────────────────────────────────────────
        github_token = await provider.get_installation_token(
            scope=scope,
            permissions=policy.permissions,
            caller=caller,
        )

        metrics.TOKEN_EXCHANGES_TOTAL.labels(
            app=app_name,
            scope=scope,
            identity=identity,
            caller=caller,
            result="success",
        ).inc()

        elapsed = time.time() - start
        metrics.TOKEN_EXCHANGE_LATENCY.labels(
            app=app_name, scope=scope, identity=identity, caller=caller
        ).observe(elapsed)

        logger.info(
            "Token issued: scope=%s app=%s identity=%s permissions=%s latency=%.3fs",
            scope,
            app_name,
            identity,
            policy.permissions,
            elapsed,
        )

        if audit_logger:
            await audit_logger.log_event(
                AuditEvent(
                    scope=scope,
                    identity=identity,
                    issuer=issuer,
                    subject=subject,
                    jti=jti[:50] if jti else None,
                    result=ExchangeResult.SUCCESS,
                    duration_ms=elapsed * 1000,
                    user_agent=user_agent[:100],
                    remote_ip=remote_ip,
                )
            )
            metrics.AUDIT_EVENTS_LOGGED.labels(result="success").inc()

        # SECURITY: github_token is returned to the caller but must never be logged
        return {
            "token": github_token,
            "scope": scope,
            "app": app_name,
            "identity": identity,
            "permissions": policy.permissions,
        }

    except HTTPException:
        raise
    except Exception as exc:
        metrics.TOKEN_EXCHANGES_TOTAL.labels(
            app=app_name,
            scope=scope,
            identity=identity,
            caller=caller if "caller" in locals() else "unknown",
            result="error",
        ).inc()
        logger.error("Unexpected error during exchange: %s", exc, exc_info=True)
        if audit_logger:
            try:
                await audit_logger.log_event(
                    AuditEvent(
                        scope=scope,
                        identity=identity,
                        issuer=issuer if "issuer" in locals() else "unknown",
                        subject=subject if "subject" in locals() else "unknown",
                        jti=jti[:50] if "jti" in locals() and jti else None,
                        result=ExchangeResult.UNKNOWN_ERROR,
                        error_reason=type(exc).__name__[:100],
                        duration_ms=(time.time() - start) * 1000,
                        user_agent=user_agent[:100],
                        remote_ip=remote_ip,
                    )
                )
                metrics.AUDIT_EVENTS_LOGGED.labels(result="unknown_error").inc()
            except Exception as log_exc:
                logger.error("Failed to log audit event: %s", log_exc)
                metrics.AUDIT_LOG_ERRORS.labels(backend="file").inc()
        raise HTTPException(status_code=500, detail="Internal server error") from exc
