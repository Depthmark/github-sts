// Package metrics defines all Prometheus metrics for github-sts.
//
// Metric naming follows Go-idiomatic conventions (clean break from Python names).
// All metrics use the "githubsts_" prefix.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// HTTP metrics.
var (
	RequestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_http_requests_total",
		Help: "Total HTTP requests.",
	}, []string{"method", "path", "status"})

	RequestLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "githubsts_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5},
	}, []string{"method", "path"})

	InFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "githubsts_http_requests_in_flight",
		Help: "Number of requests currently being processed.",
	})
)

// Token exchange metrics.
var (
	// TokenExchangesTotal's instance label is the pool member that actually
	// minted the token (empty when no instance succeeded — see
	// audit.Event.Instance), populated from InstallationTokenProvider's
	// instance return value.
	TokenExchangesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_token_exchanges_total",
		Help: "Total token exchange attempts.",
	}, []string{"app", "instance", "scope", "identity", "issuer", "result"})

	TokenExchangeLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "githubsts_token_exchange_duration_seconds",
		Help:    "Token exchange duration in seconds.",
		Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"app", "instance", "scope", "identity", "issuer"})

	OIDCValidationErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_oidc_validation_errors_total",
		Help: "OIDC token validation failures.",
	}, []string{"issuer", "reason"})
)

// JTI replay prevention metrics.
var (
	JTIReplayAttempts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "githubsts_jti_replay_attempts_total",
		Help: "Total JTI replay attack attempts detected.",
	})

	JTICacheErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_jti_cache_errors_total",
		Help: "JTI cache operation errors.",
	}, []string{"error_type"})
)

// Audit logging metrics.
var (
	AuditEventsLogged = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_audit_events_logged_total",
		Help: "Total audit events logged.",
	}, []string{"result"})

	AuditLogErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_audit_log_errors_total",
		Help: "Audit log write errors.",
	}, []string{"backend"})

	AuditEventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "githubsts_audit_events_dropped_total",
		Help: "Total audit events dropped due to full channel buffer.",
	})
)

// Policy metrics.
var (
	PolicyLoadsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_policy_loads_total",
		Help: "Total policy file load attempts.",
	}, []string{"app", "backend", "result"})

	PolicyCacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_policy_cache_hits_total",
		Help: "Policy cache hits.",
	}, []string{"app"})

	PolicyCacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_policy_cache_misses_total",
		Help: "Policy cache misses.",
	}, []string{"app"})
)

// GitHub App metrics. Labeled by both app (the logical name callers pass as
// ?app=) and instance (which physical pool member handled the call — for a
// non-pooled app this is that app's single normalized instance, so existing
// single-instance deployments still get one series per app, just qualified
// by a second label).
var (
	GitHubAPICalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_api_calls_total",
		Help: "Total GitHub API calls.",
	}, []string{"app", "instance", "endpoint", "result"})

	GitHubTokenIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_tokens_issued_total",
		Help: "GitHub installation tokens issued.",
	}, []string{"app", "instance", "scope", "permissions"})
)

// GitHub API rate limit metrics.
var (
	GitHubRateLimitLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_limit",
		Help: "Maximum number of requests allowed in the current rate limit window.",
	}, []string{"app", "instance", "resource"})

	GitHubRateLimitRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_remaining",
		Help: "Remaining requests before rate limit is reached.",
	}, []string{"app", "instance", "resource"})

	GitHubRateLimitUsed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_used",
		Help: "Requests used in the current rate limit window.",
	}, []string{"app", "instance", "resource"})

	GitHubRateLimitResetTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_reset_timestamp",
		Help: "Unix epoch timestamp when the rate limit window resets.",
	}, []string{"app", "instance", "resource"})

	GitHubRateLimitRemainingPercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_remaining_percent",
		Help: "Percentage of rate limit remaining.",
	}, []string{"app", "instance", "resource"})

	// GitHubRateLimitExceededTotal and GitHubSecondaryRateLimitTotal below
	// still carry the pre-existing "caller" label, which has its own,
	// unrelated unbounded-cardinality problem (it's the per-request trace
	// ID on the exchange path) — see .agent-tasks/multi-instance-app-rate-limit-rotation.md
	// §11. Out of scope here: this change only adds "instance" mechanically.
	GitHubRateLimitExceededTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_rate_limit_exceeded_total",
		Help: "Total primary rate limit exceeded events.",
	}, []string{"app", "instance", "resource", "caller"})

	GitHubSecondaryRateLimitTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_secondary_rate_limit_total",
		Help: "Total secondary (abuse) rate limit events from GitHub.",
	}, []string{"app", "instance", "caller"})

	GitHubSecondaryRateLimitRetryAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_secondary_rate_limit_retry_after_seconds",
		Help: "Current retry-after value in seconds when secondary rate limit is active.",
	}, []string{"app", "instance"})
)

// GitHub reachability metrics.
var (
	GitHubReachable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_reachable",
		Help: "Whether GitHub API is reachable (1 = reachable, 0 = unreachable).",
	}, []string{"app", "instance"})

	GitHubReachabilityCheckDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "githubsts_github_reachability_check_duration_seconds",
		Help:    "Latency of reachability probe to GitHub API.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"app", "instance"})

	GitHubReachabilityFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_reachability_failures_total",
		Help: "Total GitHub reachability probe failures.",
	}, []string{"app", "instance", "reason"})
)

// App pool metrics — visibility into instance rotation for a pooled app
// (config: apps.<name>.instances). A non-pooled app is a pool of one and
// still emits these (instances=1, every selection outcome "selected").
var (
	AppPoolInstances = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_app_pool_instances",
		Help: "Configured pool size for a logical app.",
	}, []string{"app"})

	// AppPoolSelectionTotal's outcome label is one of: selected,
	// skipped_unreachable, skipped_rate_limited, failover.
	AppPoolSelectionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_app_pool_selection_total",
		Help: "Pool instance selection outcomes.",
	}, []string{"app", "instance", "outcome"})

	// AppPoolExhaustedTotal is the alert-worthy signal: every instance in
	// the pool failed for one request. Alert on this, not on any single
	// instance's rate-limit gauge.
	AppPoolExhaustedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_app_pool_exhausted_total",
		Help: "Total requests where every pool instance failed.",
	}, []string{"app"})
)

// Request rate limiting.
var RateLimitRejections = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "githubsts_rate_limit_rejections_total",
	Help: "Total requests rejected by per-IP rate limiting.",
})

// Instance readiness.
var Ready = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "githubsts_ready",
	Help: "Whether the instance is ready to serve traffic (1 = ready, 0 = not ready).",
})

// Register registers all metrics with the default Prometheus registerer.
func Register() {
	// HTTP
	prometheus.MustRegister(RequestCount, RequestLatency, InFlight)
	// Token exchange
	prometheus.MustRegister(TokenExchangesTotal, TokenExchangeLatency, OIDCValidationErrors)
	// JTI
	prometheus.MustRegister(JTIReplayAttempts, JTICacheErrors)
	// Audit
	prometheus.MustRegister(AuditEventsLogged, AuditLogErrors, AuditEventsDropped)
	// Policy
	prometheus.MustRegister(PolicyLoadsTotal, PolicyCacheHits, PolicyCacheMisses)
	// GitHub
	prometheus.MustRegister(GitHubAPICalls, GitHubTokenIssued)
	// Rate limit
	prometheus.MustRegister(GitHubRateLimitLimit, GitHubRateLimitRemaining, GitHubRateLimitUsed,
		GitHubRateLimitResetTimestamp, GitHubRateLimitRemainingPercent,
		GitHubRateLimitExceededTotal, GitHubSecondaryRateLimitTotal, GitHubSecondaryRateLimitRetryAfter)
	// Reachability
	prometheus.MustRegister(GitHubReachable, GitHubReachabilityCheckDuration, GitHubReachabilityFailuresTotal)
	// App pool
	prometheus.MustRegister(AppPoolInstances, AppPoolSelectionTotal, AppPoolExhaustedTotal)
	// Request rate limiting
	prometheus.MustRegister(RateLimitRejections)
	// Readiness
	prometheus.MustRegister(Ready)
}
