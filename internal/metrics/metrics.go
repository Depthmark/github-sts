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

	ImmutableSubjectClaimsRequired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "githubsts_oidc_immutable_subject_claims_required",
		Help: "Whether immutable GitHub.com subject claims are required (1 = required, 0 = legacy subject format allowed).",
	})
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

// OPA bundle metrics. The bundle is the org-rego guardrail layer pulled
// from an OCI registry, cosign-verified, and consulted on every token
// exchange. Phase 1 ships exchange-mode only; the `mode` label on
// OrgDecisionTotal is added in Phase 3 alongside validate-mode.
var (
	OrgDecisionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_org_decision_total",
		Help: "Org-rego bundle outcomes. result is allow|deny|error|not_evaluated.",
	}, []string{"app", "bundle", "result"})

	BundlePullTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_pull_total",
		Help: "OCI bundle pull attempts. result is success|failure.",
	}, []string{"bundle", "result"})

	BundleVerifyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "githubsts_bundle_verify_total",
		Help: "Cosign bundle verification attempts. result is success|failure|skipped.",
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
		Help: "1 for the active signed Rego policy digest and revision by bundle.",
	}, []string{"bundle", "digest", "policy_revision"})

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

	BundleEnforcementRequired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "githubsts_bundle_enforcement_required",
		Help: "Configured bundle enforcement posture (1 = required, 0 = explicitly optional).",
	})
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
	prometheus.MustRegister(TokenExchangesTotal, TokenExchangeLatency, OIDCValidationErrors, ImmutableSubjectClaimsRequired)
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
	// Bundle
	prometheus.MustRegister(OrgDecisionTotal, BundlePullTotal, BundleVerifyTotal, BundleLoadedDigestInfo, BundleAgeSeconds, BundleReloadTotal, BundleStaleEvalsTotal, BundlePolicyRevisionInfo, BundlePolicyRevisionChangesTotal, BundlePolicyDecisionsTotal, BundlePolicyRuleDecisionsTotal, BundlePolicyExceptionsTotal, BundlePolicyExceptionExpirationTimestampSeconds, BundlePolicyExceptionSecondsUntilExpiration, BundlePolicyExceptionHitsTotal, BundleEnforcementRequired)
	// Request rate limiting
	prometheus.MustRegister(RateLimitRejections)
	// Readiness
	prometheus.MustRegister(Ready)
}
