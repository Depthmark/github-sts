"""
Prometheus metrics for github-sts.
"""

from prometheus_client import Counter, Gauge, Histogram, Info

# ── HTTP metrics ──────────────────────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "pygithubsts_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "pygithubsts_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

IN_FLIGHT = Gauge(
    "pygithubsts_requests_in_flight",
    "Number of requests currently being processed",
)

# ── Token exchange metrics ────────────────────────────────────────────────────
TOKEN_EXCHANGES_TOTAL = Counter(
    "pygithubsts_token_exchanges_total",
    "Total token exchange attempts",
    ["app", "scope", "identity", "caller", "result"],
    # result: success | denied | error | oidc_invalid | policy_not_found
)

TOKEN_EXCHANGE_LATENCY = Histogram(
    "pygithubsts_token_exchange_duration_seconds",
    "Token exchange duration in seconds",
    ["app", "scope", "identity", "caller"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

OIDC_VALIDATION_ERRORS = Counter(
    "pygithubsts_oidc_validation_errors_total",
    "OIDC token validation failures",
    ["issuer", "reason"],  # reason: expired | signature | claims | unknown
)

# ── JTI replay prevention metrics ─────────────────────────────────────────────
JTI_REPLAY_ATTEMPTS = Counter(
    "pygithubsts_jti_replay_attempts_total",
    "Total JTI replay attack attempts detected",
)

JTI_CACHE_ERRORS = Counter(
    "pygithubsts_jti_cache_errors_total",
    "JTI cache operation errors",
    ["error_type"],  # error_type: redis_connection | cache_check | other
)

# ── Audit logging metrics ─────────────────────────────────────────────────────
AUDIT_EVENTS_LOGGED = Counter(
    "pygithubsts_audit_events_logged_total",
    "Total audit events logged",
    ["result"],  # result: success | policy_denied | oidc_invalid | etc
)

AUDIT_LOG_ERRORS = Counter(
    "pygithubsts_audit_log_errors_total",
    "Audit log write errors",
    ["backend"],  # backend: file
)

# ── Policy metrics ────────────────────────────────────────────────────────────
POLICY_LOADS_TOTAL = Counter(
    "pygithubsts_policy_loads_total",
    "Total policy file load attempts",
    ["app", "backend", "result"],  # backend: github
)

POLICY_CACHE_HITS = Counter(
    "pygithubsts_policy_cache_hits_total",
    "Policy cache hits",
    ["app"],
)

POLICY_CACHE_MISSES = Counter(
    "pygithubsts_policy_cache_misses_total",
    "Policy cache misses",
    ["app"],
)

# ── GitHub App metrics ────────────────────────────────────────────────────────
GITHUB_API_CALLS = Counter(
    "pygithubsts_github_api_calls_total",
    "Total GitHub API calls",
    ["app", "endpoint", "result"],
)

GITHUB_TOKEN_ISSUED = Counter(
    "pygithubsts_github_tokens_issued_total",
    "GitHub installation tokens issued",
    ["app", "scope", "permissions"],
)

# ── GitHub API rate limit metrics ─────────────────────────────────────────────
GITHUB_RATE_LIMIT_LIMIT = Gauge(
    "pygithubsts_github_rate_limit_limit",
    "Maximum number of requests allowed in the current rate limit window",
    ["app", "resource"],
)

GITHUB_RATE_LIMIT_REMAINING = Gauge(
    "pygithubsts_github_rate_limit_remaining",
    "Remaining requests before rate limit is reached",
    ["app", "resource"],
)

GITHUB_RATE_LIMIT_USED = Gauge(
    "pygithubsts_github_rate_limit_used",
    "Requests used in the current rate limit window",
    ["app", "resource"],
)

GITHUB_RATE_LIMIT_RESET_TIMESTAMP = Gauge(
    "pygithubsts_github_rate_limit_reset_timestamp",
    "Unix epoch timestamp when the rate limit window resets",
    ["app", "resource"],
)

GITHUB_RATE_LIMIT_REMAINING_PERCENT = Gauge(
    "pygithubsts_github_rate_limit_remaining_percent",
    "Percentage of rate limit remaining (remaining / limit * 100)",
    ["app", "resource"],
)

GITHUB_RATE_LIMIT_EXCEEDED_TOTAL = Counter(
    "pygithubsts_github_rate_limit_exceeded_total",
    "Total primary rate limit exceeded events (HTTP 403 from GitHub)",
    ["app", "resource", "caller"],
)

GITHUB_SECONDARY_RATE_LIMIT_TOTAL = Counter(
    "pygithubsts_github_secondary_rate_limit_total",
    "Total secondary (abuse) rate limit events from GitHub",
    ["app", "caller"],
)

GITHUB_SECONDARY_RATE_LIMIT_RETRY_AFTER = Gauge(
    "pygithubsts_github_secondary_rate_limit_retry_after_seconds",
    "Current retry-after value in seconds when secondary rate limit is active",
    ["app"],
)

# ── GitHub reachability metrics ───────────────────────────────────────────────
GITHUB_REACHABLE = Gauge(
    "pygithubsts_github_reachable",
    "Whether GitHub API is reachable (1 = reachable, 0 = unreachable)",
    ["app"],
)

GITHUB_REACHABILITY_CHECK_DURATION = Histogram(
    "pygithubsts_github_reachability_check_duration_seconds",
    "Latency of reachability probe to GitHub API",
    ["app"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

GITHUB_REACHABILITY_FAILURES_TOTAL = Counter(
    "pygithubsts_github_reachability_failures_total",
    "Total GitHub reachability probe failures",
    ["app", "reason"],  # reason: timeout | connection_error | http_error | auth_error
)

# ── Instance readiness ─────────────────────────────────────────────────────────
READY = Gauge(
    "pygithubsts_ready",
    "Whether the instance is ready to serve traffic (1 = ready, 0 = not ready)",
)

# ── Event loop health ─────────────────────────────────────────────────────────
EVENT_LOOP_LAG = Gauge(
    "pygithubsts_event_loop_lag_seconds",
    "Event loop scheduling delay",
)

# ── App info ──────────────────────────────────────────────────────────────────
APP_INFO = Info(
    "pygithubsts_app",
    "github-sts application info",
)
APP_INFO.info({"version": "1.0.0", "description": "Python OIDC STS for GitHub"})
