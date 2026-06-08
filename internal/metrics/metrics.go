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
	TokenExchangesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_token_exchanges_total",
		Help: "Total token exchange attempts.",
	}, []string{"app", "scope", "identity", "issuer", "result"})

	TokenExchangeLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "githubsts_token_exchange_duration_seconds",
		Help:    "Token exchange duration in seconds.",
		Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"app", "scope", "identity", "issuer"})

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

// GitHub App metrics.
var (
	GitHubAPICalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_api_calls_total",
		Help: "Total GitHub API calls.",
	}, []string{"app", "endpoint", "result"})

	GitHubTokenIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_tokens_issued_total",
		Help: "GitHub installation tokens issued.",
	}, []string{"app", "scope", "permissions"})
)

// GitHub API rate limit metrics.
var (
	GitHubRateLimitLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_limit",
		Help: "Maximum number of requests allowed in the current rate limit window.",
	}, []string{"app", "resource"})

	GitHubRateLimitRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_remaining",
		Help: "Remaining requests before rate limit is reached.",
	}, []string{"app", "resource"})

	GitHubRateLimitUsed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_used",
		Help: "Requests used in the current rate limit window.",
	}, []string{"app", "resource"})

	GitHubRateLimitResetTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_reset_timestamp",
		Help: "Unix epoch timestamp when the rate limit window resets.",
	}, []string{"app", "resource"})

	GitHubRateLimitRemainingPercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_rate_limit_remaining_percent",
		Help: "Percentage of rate limit remaining.",
	}, []string{"app", "resource"})

	GitHubRateLimitExceededTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_rate_limit_exceeded_total",
		Help: "Total primary rate limit exceeded events.",
	}, []string{"app", "resource", "caller"})

	GitHubSecondaryRateLimitTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_secondary_rate_limit_total",
		Help: "Total secondary (abuse) rate limit events from GitHub.",
	}, []string{"app", "caller"})

	GitHubSecondaryRateLimitRetryAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_secondary_rate_limit_retry_after_seconds",
		Help: "Current retry-after value in seconds when secondary rate limit is active.",
	}, []string{"app"})
)

// GitHub reachability metrics.
var (
	GitHubReachable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_github_reachable",
		Help: "Whether GitHub API is reachable (1 = reachable, 0 = unreachable).",
	}, []string{"app"})

	GitHubReachabilityCheckDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "githubsts_github_reachability_check_duration_seconds",
		Help:    "Latency of reachability probe to GitHub API.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"app"})

	GitHubReachabilityFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_github_reachability_failures_total",
		Help: "Total GitHub reachability probe failures.",
	}, []string{"app", "reason"})
)

// OPA bundle metrics. The bundle is the org-rego guardrail layer pulled
// from an OCI registry, cosign-verified, and consulted on every token
// exchange. Phase 1 ships exchange-mode only; the `mode` label on
// OrgDecisionTotal is added in Phase 3 alongside validate-mode.
var (
	OrgDecisionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_org_decision_total",
		Help: "Org-rego bundle decisions. result is allow|deny|error.",
	}, []string{"app", "bundle", "result"})

	BundlePullTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_pull_total",
		Help: "OCI bundle pull attempts. result is success|failure.",
	}, []string{"bundle", "result"})

	BundleVerifyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_verify_total",
		Help: "Cosign bundle verification attempts. result is success|failure.",
	}, []string{"bundle", "result"})

	BundleLoadedDigestInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_loaded_digest_info",
		Help: "1 for the OCI digest of the currently loaded bundle.",
	}, []string{"bundle", "digest"})

	BundleAgeSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_age_seconds",
		Help: "Seconds since the last successful bundle pull.",
	}, []string{"bundle"})

	// BundleReloadTotal counts reload attempts after the initial Init.
	// result is success|failure|unchanged. Init pulls also stamp
	// BundlePullTotal so they don't double-count here.
	BundleReloadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_reload_total",
		Help: "Bundle reload attempts. result is success|failure|unchanged.",
	}, []string{"bundle", "result"})

	// BundleStaleEvalsTotal counts requests where the bundle was stale
	// at eval time. mode=closed means the request was rejected with
	// bundle_stale; mode=open means it proceeded with a warning. Both
	// are counted separately from a healthy allow/deny.
	BundleStaleEvalsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_stale_evals_total",
		Help: "Bundle eval attempts where the bundle was stale (age > max_staleness). mode is closed|open.",
	}, []string{"bundle", "mode"})

	BundlePolicyRevisionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_policy_revision_info",
		Help: "1 for the active Rego policy digest by bundle.",
	}, []string{"bundle", "digest"})

	BundlePolicyRevisionChangesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_policy_revision_changes_total",
		Help: "Policy revision reload outcomes. result is changed|unchanged|failure.",
	}, []string{"bundle", "result"})

	BundlePolicyDecisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_policy_decisions_total",
		Help: "Policy decisions by app, bundle, digest, and result.",
	}, []string{"app", "bundle", "digest", "result"})

	BundlePolicyRuleDecisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_policy_rule_decisions_total",
		Help: "Policy decisions by bounded enterprise rule ID.",
	}, []string{"bundle", "rule_id", "result"})

	BundlePolicyExceptionsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_policy_exceptions_total",
		Help: "Discovered policy exceptions by status. status is active|expiring|expired|invalid.",
	}, []string{"bundle", "digest", "status"})

	BundlePolicyExceptionExpirationTimestampSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_policy_exception_expiration_timestamp_seconds",
		Help: "Unix timestamp when a discovered policy exception expires.",
	}, []string{"bundle", "digest", "exception_id", "rule_id", "owner"})

	BundlePolicyExceptionSecondsUntilExpiration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "githubsts_bundle_policy_exception_seconds_until_expiration",
		Help: "Seconds until a discovered policy exception expires; negative means expired.",
	}, []string{"bundle", "digest", "exception_id", "rule_id", "owner"})

	BundlePolicyExceptionHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_policy_exception_hits_total",
		Help: "Exchange attempts where a policy decision reported an exception hit.",
	}, []string{"bundle", "digest", "exception_id", "rule_id", "owner", "app"})
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
	// Bundle
	prometheus.MustRegister(OrgDecisionTotal, BundlePullTotal, BundleVerifyTotal, BundleLoadedDigestInfo, BundleAgeSeconds, BundleReloadTotal, BundleStaleEvalsTotal, BundlePolicyRevisionInfo, BundlePolicyRevisionChangesTotal, BundlePolicyDecisionsTotal, BundlePolicyRuleDecisionsTotal, BundlePolicyExceptionsTotal, BundlePolicyExceptionExpirationTimestampSeconds, BundlePolicyExceptionSecondsUntilExpiration, BundlePolicyExceptionHitsTotal)
	// Request rate limiting
	prometheus.MustRegister(RateLimitRejections)
	// Readiness
	prometheus.MustRegister(Ready)
}
