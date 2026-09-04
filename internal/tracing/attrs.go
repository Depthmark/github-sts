// Package tracing provides OpenTelemetry trace export for github-sts.
//
// Every span attribute this service emits is constructed here and nowhere
// else. Two properties depend on that:
//
//   - Audit fields and span attributes cannot drift. ExchangeAttributes maps
//     an audit.Event, the same record written to the audit log, so a span and
//     its audit line always describe the same exchange in the same terms.
//   - The secret deny-list is testable in one place. A bearer token, a minted
//     installation token, an App private key or JWT, a raw claims map, or a
//     registry credential must never reach a span under any key. AllowedKeys
//     below is the complete set, and TestAttributeKeysAreAllowListed fails the
//     build if anything else appears.
package tracing

import (
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/depthmark/github-sts/internal/audit"
)

// Attribute keys.
//
// LABEL NAMING RULE (mirrors internal/metrics/metrics.go): a span attribute is
// not confined to traces. The OpenTelemetry Collector's spanmetrics connector
// promotes span attributes to Prometheus metric dimensions, and at that moment
// they meet exactly the Kubernetes scrape-injection hazard that renamed
// app -> github_app and instance -> github_app_instance in d6a89f4. Never use a
// bare `app`, `instance`, `endpoint`, `job`, `namespace`, `pod`, `container`,
// `service` or `node`.
//
// The GitHub App keys are deliberately not in the sts.* namespace. The
// OTel-to-Prometheus mapping replaces "." with "_", so github.app becomes
// github_app and github.app.instance becomes github_app_instance -- the exact
// label names the metrics already use. Span-derived metrics then join with the
// native ones in PromQL instead of sitting in a parallel namespace no dashboard
// can correlate.
const (
	AttrGitHubApp         = attribute.Key("github.app")
	AttrGitHubAppInstance = attribute.Key("github.app.instance")

	AttrScope     = attribute.Key("sts.scope")
	AttrIdentity  = attribute.Key("sts.identity")
	AttrResult    = attribute.Key("sts.result")
	AttrErrorCode = attribute.Key("sts.error.code")

	AttrOIDCIssuer  = attribute.Key("sts.oidc.issuer")
	AttrOIDCSubject = attribute.Key("sts.oidc.subject")

	AttrSourceRepository        = attribute.Key("sts.source.repository")
	AttrSourceRepositoryID      = attribute.Key("sts.source.repository_id")
	AttrSourceRepositoryOwner   = attribute.Key("sts.source.repository_owner")
	AttrSourceRepositoryOwnerID = attribute.Key("sts.source.repository_owner_id")

	AttrTargetRepository        = attribute.Key("sts.target.repository")
	AttrTargetRepositoryID      = attribute.Key("sts.target.repository_id")
	AttrTargetRepositoryOwner   = attribute.Key("sts.target.repository_owner")
	AttrTargetRepositoryOwnerID = attribute.Key("sts.target.repository_owner_id")

	AttrIdentityImmutable         = attribute.Key("sts.identity.immutable")
	AttrIdentityImmutableRequired = attribute.Key("sts.identity.immutable_required")

	AttrJTI = attribute.Key("sts.jti")

	AttrPolicyRepository = attribute.Key("sts.policy.repository")
	AttrPolicyPath       = attribute.Key("sts.policy.path")
	AttrPolicyBlobSHA    = attribute.Key("sts.policy.blob_sha")
	AttrPolicySource     = attribute.Key("sts.policy.source")

	// Permission sets are emitted as sorted "name=level" lists, never as the
	// raw maps: an attribute value must be a scalar or a slice of scalars, and
	// a stable ordering keeps two spans for the same grant byte-identical.
	AttrPermissionsInstallation = attribute.Key("sts.permissions.installation")
	AttrPermissionsPolicy       = attribute.Key("sts.permissions.policy")
	AttrPermissionsRequested    = attribute.Key("sts.permissions.requested")
	AttrPermissionsGranted      = attribute.Key("sts.permissions.granted")
	AttrPermissionsNarrowed     = attribute.Key("sts.permissions.narrowed")

	AttrBundleEnforcement = attribute.Key("sts.bundle.enforcement")
	AttrBundleDigest      = attribute.Key("sts.bundle.digest")
	AttrBundleApplicable  = attribute.Key("sts.bundle.applicable")
	AttrBundleEvaluated   = attribute.Key("sts.bundle.evaluated")
	AttrBundleAllow       = attribute.Key("sts.bundle.allow")

	// Semantic conventions, used with their standard meanings only.
	AttrClientAddress     = attribute.Key("client.address")
	AttrUserAgentOriginal = attribute.Key("user_agent.original")
)

// AllowedKeys is the complete set of attribute keys this service may emit on
// an exchange span. It is the allow-list the guard test enforces; adding a key
// here is a deliberate act that should be weighed against the deny-list in the
// package doc.
var AllowedKeys = map[attribute.Key]struct{}{
	AttrGitHubApp: {}, AttrGitHubAppInstance: {},
	AttrScope: {}, AttrIdentity: {}, AttrResult: {}, AttrErrorCode: {},
	AttrOIDCIssuer: {}, AttrOIDCSubject: {},
	AttrSourceRepository: {}, AttrSourceRepositoryID: {},
	AttrSourceRepositoryOwner: {}, AttrSourceRepositoryOwnerID: {},
	AttrTargetRepository: {}, AttrTargetRepositoryID: {},
	AttrTargetRepositoryOwner: {}, AttrTargetRepositoryOwnerID: {},
	AttrIdentityImmutable: {}, AttrIdentityImmutableRequired: {},
	AttrJTI:              {},
	AttrPolicyRepository: {}, AttrPolicyPath: {}, AttrPolicyBlobSHA: {}, AttrPolicySource: {},
	AttrPermissionsInstallation: {}, AttrPermissionsPolicy: {},
	AttrPermissionsRequested: {}, AttrPermissionsGranted: {}, AttrPermissionsNarrowed: {},
	AttrBundleEnforcement: {}, AttrBundleDigest: {},
	AttrBundleApplicable: {}, AttrBundleEvaluated: {}, AttrBundleAllow: {},
	AttrClientAddress: {}, AttrUserAgentOriginal: {},
}

// ReservedLabelNames are injected by Kubernetes service discovery and by
// Prometheus Operator's ServiceMonitor. This mirrors internal/metrics's list
// verbatim, and applies here because a span attribute promoted to a metric
// dimension by the spanmetrics connector becomes a Prometheus label with the
// normalized form of this key ("." replaced by "_").
var ReservedLabelNames = map[string]struct{}{
	"app": {}, "instance": {}, "job": {}, "endpoint": {}, "service": {},
	"namespace": {}, "pod": {}, "container": {}, "node": {},
}

// ExchangeAttributes maps a completed audit event onto the root exchange
// span's attributes. Empty fields are omitted rather than emitted blank, so a
// span carries only what actually applied to the request.
//
// JTI and user agent arrive already truncated by the audit layer
// (audit.TruncateJTI, audit.TruncateUserAgent); this function does not
// re-truncate, so the span and the audit line always agree.
func ExchangeAttributes(e audit.Event) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 32)

	add := func(k attribute.Key, v string) {
		if v != "" {
			attrs = append(attrs, k.String(v))
		}
	}

	add(AttrGitHubApp, e.AppName)
	add(AttrGitHubAppInstance, e.Instance)
	add(AttrScope, e.Scope)
	add(AttrIdentity, e.Identity)
	add(AttrResult, string(e.Result))

	add(AttrOIDCIssuer, e.Issuer)
	add(AttrOIDCSubject, e.Subject)

	add(AttrSourceRepository, e.SourceRepository)
	add(AttrSourceRepositoryID, e.SourceRepositoryID)
	add(AttrSourceRepositoryOwner, e.SourceRepositoryOwner)
	add(AttrSourceRepositoryOwnerID, e.SourceRepositoryOwnerID)

	add(AttrTargetRepository, e.TargetRepository)
	add(AttrTargetRepositoryID, e.TargetRepositoryID)
	add(AttrTargetRepositoryOwner, e.TargetRepositoryOwner)
	add(AttrTargetRepositoryOwnerID, e.TargetRepositoryOwnerID)

	if e.ImmutableSubject != nil {
		attrs = append(attrs, AttrIdentityImmutable.Bool(*e.ImmutableSubject))
	}
	if e.ImmutableSubjectRequired != nil {
		attrs = append(attrs, AttrIdentityImmutableRequired.Bool(*e.ImmutableSubjectRequired))
	}

	add(AttrJTI, e.JTI)

	add(AttrPolicyRepository, e.PolicyRepository)
	add(AttrPolicyPath, e.PolicyPath)
	add(AttrPolicyBlobSHA, e.PolicyBlobSHA)
	add(AttrPolicySource, e.PolicySource)

	// The four-set permission chain (installation >= policy >= requested >=
	// granted). Carrying all four lets a reviewer see in one span which stage
	// narrowed what, and how much authority the broker holds that this
	// exchange did not need.
	add(AttrPermissionsInstallation, formatPermissions(e.InstallationPermissions))
	add(AttrPermissionsPolicy, formatPermissions(e.PolicyPermissions))
	add(AttrPermissionsRequested, formatPermissions(e.RequestedPermissions))
	add(AttrPermissionsGranted, formatPermissions(e.GrantedPermissions))
	if e.RequestedPermissions != nil {
		attrs = append(attrs, AttrPermissionsNarrowed.Bool(true))
	}

	add(AttrBundleEnforcement, e.BundleEnforcement)
	add(AttrBundleDigest, e.BundleDigest)
	if e.OrgDecision != nil {
		attrs = append(attrs,
			AttrBundleApplicable.Bool(e.OrgDecision.Applicable),
			AttrBundleEvaluated.Bool(e.OrgDecision.Evaluated),
			AttrBundleAllow.Bool(e.OrgDecision.Allow),
		)
	}

	add(AttrClientAddress, e.RemoteIP)
	add(AttrUserAgentOriginal, e.UserAgent)

	return attrs
}

// ErrorCode builds the public error-code attribute. It is a separate
// constructor because the code is an ErrorResponse field, not an audit.Event
// field, so the handler supplies it alongside the event.
//
// Deliberately the stable Code* enum and not audit.Event.ErrorReason: the
// reason is free text wrapping an upstream error, which is exactly the kind of
// value that can pick up material this package must never emit. The code is a
// closed set, safe by construction, and already public API.
func ErrorCode(code string) attribute.KeyValue {
	return AttrErrorCode.String(code)
}

// formatPermissions renders a permission map as a sorted, comma-separated
// "name=level" list. Sorted because Go map iteration is randomized, and two
// spans describing the same grant must produce the same string -- otherwise
// the value is useless for grouping and diffing. Returns "" for an empty or
// nil map so the caller omits the attribute entirely.
func formatPermissions(perms map[string]string) string {
	if len(perms) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(perms))
	for name, level := range perms {
		pairs = append(pairs, name+"="+level)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}
