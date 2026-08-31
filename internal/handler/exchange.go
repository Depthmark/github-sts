// Package handler implements HTTP handlers for the github-sts service.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/jti"
	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
)

// maxRequestBodyBytes limits POST request body size to 1 MB.
const maxRequestBodyBytes = 1 << 20

// safeFieldPattern restricts scope/identity/app to safe characters to
// prevent Prometheus label cardinality abuse.
var safeFieldPattern = regexp.MustCompile(`^[a-zA-Z0-9._/\-]+$`)

// ExchangeRequest represents parsed exchange parameters.
type ExchangeRequest struct {
	Scope    string `json:"scope"`
	Identity string `json:"identity"`
	AppName  string `json:"app"`
}

// ExchangeResponse is returned on successful token exchange.
//
// ExpiresIn is the token's remaining lifetime in seconds, named and shaped
// after RFC 8693 / RFC 6749 so a caller can schedule its own refresh instead
// of hardcoding GitHub's current one-hour default. It is measured from the
// expiry GitHub returned, at the moment the broker writes the response, and
// rounded down so it never over-promises. The field is omitted — never sent
// as a guess — when GitHub gave no usable expiry (see github.IssuedToken);
// callers must handle its absence by falling back to their own heuristic.
type ExchangeResponse struct {
	Token       string            `json:"token"`
	ExpiresIn   int64             `json:"expires_in,omitempty"`
	Scope       string            `json:"scope"`
	App         string            `json:"app"`
	Identity    string            `json:"identity"`
	Permissions map[string]string `json:"permissions"`
}

// expiresIn converts an absolute token expiry into the RFC 6749 expires_in
// lifetime: whole seconds remaining, rounded down, and 0 (which
// ExchangeResponse omits) for an unknown or already-elapsed expiry.
func expiresIn(expiresAt, now time.Time) int64 {
	if expiresAt.IsZero() {
		return 0
	}
	remaining := int64(expiresAt.Sub(now) / time.Second)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ErrorResponse is returned on exchange errors.
//
// Error stays deliberately generic ("forbidden", "upstream error") so
// attackers cannot probe the validator. Code is a stable, coarse category
// safe to surface to callers — operators use it to tell apart "fix the
// workflow" from "fix the policy" failures without log access. TraceID is
// the per-request identifier also emitted in audit/server logs; give it to
// ops to find the matching log line, which carries the full reason.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// Error codes returned in ErrorResponse.Code. These are a stable public API —
// do not rename without a major version bump.
const (
	// 400 — request shape rejected before any auth happened.
	CodeBadRequest = "bad_request"

	// 403 — token rejected. Coarse on purpose; the matching trace_id log line
	// carries the precise reason.
	CodeOIDCInvalid           = "oidc_invalid"            // missing/expired/bad-signature/unknown-issuer/missing-kid/malformed
	CodeGitHubIdentityInvalid = "github_identity_invalid" // GitHub identity claims are missing, malformed, or contradictory
	CodeAudienceMismatch      = "audience_mismatch"       // token aud did not match policy.audience
	CodeAppUnknown            = "app_unknown"             // requested ?app= is not configured on the server
	CodePolicyNotFound        = "policy_not_found"        // no .sts.yaml for this scope/app/identity
	CodeTrustPolicyInvalid    = "trust_policy_invalid"    // policy definition is malformed or structurally unsafe
	CodePolicyDenied          = "policy_denied"           // policy exists but evaluation failed (subject/claim_pattern)
	CodeOrgPolicyDenied       = "org_policy_denied"       // org-rego bundle blocked this request at exchange time

	// 503 — server is up but a dependency is degraded.
	CodeBundleStale            = "bundle_stale"             // bundle hasn't refreshed in time and fail_mode=closed
	CodeBundleUnavailable      = "bundle_unavailable"       // mandatory baseline did not participate
	CodeBundleEvaluationFailed = "bundle_evaluation_failed" // timeout, strict built-in error, or other evaluation fault

	// Other status codes.
	CodeMethodNotAllowed = "method_not_allowed" // 405
	CodeReplay           = "replay_detected"    // 409
	CodeInternal         = "internal_error"     // 500
	CodeUpstream         = "upstream_error"     // 502
)

// contextKey is an unexported type for context keys.
type contextKey string

// TraceIDKey is the context key for the trace ID.
const TraceIDKey contextKey = "trace_id"

// ExchangeHandler orchestrates the token exchange flow.
type ExchangeHandler struct {
	jtiCache                      jti.Cache
	policyLoader                  policy.Loader
	appProviders                  map[string]github.ExchangeApp
	allowedIssuers                []string
	requiredAudience              string
	requireImmutableSubjectClaims bool
	auditLogger                   audit.Logger
	slogger                       *slog.Logger
	trustForwardedHeaders         bool
	bundleManager                 bundle.Manager

	// validator is the OIDC token validator. Production wires
	// oidc.Validate; tests override to inject synthetic claims so the
	// handler can be driven past OIDC validation without a JWKS server.
	validator func(ctx context.Context, token string, allowedIssuers []string) (oidc.Claims, error)
}

// NewExchangeHandler creates a new ExchangeHandler with all dependencies injected.
// requiredAudience, when non-empty, is enforced on every token before policy
// lookup as a server-wide defense against permissive policy files.
//
// bundleManager is the org-rego guardrail. When Enabled() is true, the
// handler consults it after the YAML policy match and before the GitHub
// API mint; a deny returns 403 org_policy_denied. Pass bundle.Disabled{}
// when bundle integration is off (default).
func NewExchangeHandler(
	jtiCache jti.Cache,
	policyLoader policy.Loader,
	appProviders map[string]github.ExchangeApp,
	allowedIssuers []string,
	requiredAudience string,
	requireImmutableSubjectClaims bool,
	auditLogger audit.Logger,
	slogger *slog.Logger,
	trustForwardedHeaders bool,
	bundleManager bundle.Manager,
) *ExchangeHandler {
	if bundleManager == nil {
		bundleManager = bundle.Disabled{}
	}
	return &ExchangeHandler{
		jtiCache:                      jtiCache,
		policyLoader:                  policyLoader,
		appProviders:                  appProviders,
		allowedIssuers:                allowedIssuers,
		requiredAudience:              requiredAudience,
		requireImmutableSubjectClaims: requireImmutableSubjectClaims,
		auditLogger:                   auditLogger,
		slogger:                       slogger,
		trustForwardedHeaders:         trustForwardedHeaders,
		bundleManager:                 bundleManager,
		validator:                     oidc.Validate,
	}
}

// ServeHTTP handles the token exchange request.
func (h *ExchangeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	traceID := traceIDFromContext(r)

	// Only GET and POST are allowed.
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed", Code: CodeMethodNotAllowed, TraceID: traceID})
		return
	}

	// Parse request parameters.
	req, err := parseExchangeRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest, TraceID: traceID})
		return
	}

	// Validate required fields.
	if req.Scope == "" || req.Identity == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "scope and identity are required", Code: CodeBadRequest, TraceID: traceID})
		return
	}

	// Validate field characters and length to prevent metrics cardinality abuse.
	if err := validateField("scope", req.Scope, 200); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest, TraceID: traceID})
		return
	}
	if err := validateField("identity", req.Identity, 100); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest, TraceID: traceID})
		return
	}
	if req.AppName != "" {
		if err := validateField("app", req.AppName, 100); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest, TraceID: traceID})
			return
		}
	}
	targetScope, err := github.ParseRepositoryScope(req.Scope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest, TraceID: traceID})
		return
	}

	// Build base audit event.
	bundleEnforcement := bundle.EnforcementOptional
	if h.bundleManager != nil {
		bundleEnforcement = h.bundleManager.Enforcement()
	}
	event := audit.Event{
		TraceID:           traceID,
		Scope:             req.Scope,
		Identity:          req.Identity,
		UserAgent:         audit.TruncateUserAgent(r.UserAgent(), 100),
		RemoteIP:          remoteIP(r, h.trustForwardedHeaders),
		BundleEnforcement: bundleEnforcement,
	}

	// Step 1: Extract and validate OIDC token.
	bearer := extractBearer(r)
	if bearer == "" {
		event.Result = audit.ResultOIDCInvalid
		event.ErrorReason = "missing or invalid authorization header"
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeOIDCInvalid, TraceID: traceID})
		return
	}

	validate := h.validator
	if validate == nil {
		validate = oidc.Validate
	}
	claims, err := validate(r.Context(), bearer, h.allowedIssuers)
	if err != nil {
		event.Issuer = claimString(claims, "iss")
		event.Subject = claimString(claims, "sub")
		event.Result = audit.ResultOIDCInvalid
		event.ErrorReason = fmt.Sprintf("oidc validation failed: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("oidc validation failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"identity", req.Identity,
				"issuer", claimString(claims, "iss"),
				"error", err,
			)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeOIDCInvalid, TraceID: traceID})
		return
	}

	event.Issuer = claimString(claims, "iss")
	event.Subject = claimString(claims, "sub")
	if event.Issuer == oidc.GitHubActionsIssuer {
		required := h.requireImmutableSubjectClaims
		event.ImmutableSubjectRequired = &required
	}

	// GitHub.com repository identity is a broker-level security contract. It is
	// validated before audience, JTI, app, or target policy work so malformed
	// identity cannot consume state or probe target configuration.
	sourceIdentity, err := oidc.ParseGitHubIdentity(claims, h.requireImmutableSubjectClaims)
	if err != nil {
		reason := "github_identity_invalid"
		var identityErr *oidc.GitHubIdentityError
		if errors.As(err, &identityErr) {
			reason = string(identityErr.Reason)
		}
		metrics.OIDCValidationErrors.WithLabelValues(event.Issuer, reason).Inc()
		event.Result = audit.ResultOIDCInvalid
		event.ErrorReason = err.Error()
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("GitHub identity validation failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"identity", req.Identity,
				"issuer", event.Issuer,
				"reason", reason,
			)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeGitHubIdentityInvalid, TraceID: traceID})
		return
	}
	if sourceIdentity != nil {
		immutable := sourceIdentity.ImmutableSubject
		event.SourceRepositoryOwner = sourceIdentity.RepositoryOwner
		event.SourceRepositoryOwnerID = sourceIdentity.RepositoryOwnerID
		event.SourceRepository = sourceIdentity.Repository
		event.SourceRepositoryID = sourceIdentity.RepositoryID
		event.ImmutableSubject = &immutable
	}

	// Server-wide required audience: enforced before JTI reservation so a
	// token minted for the wrong relying party cannot burn a replay slot or
	// reach policy lookup. Acts as defense-in-depth on top of the per-policy
	// audience check below.
	if h.requiredAudience != "" && !audienceMatches(claims, h.requiredAudience) {
		event.Result = audit.ResultPolicyDenied
		event.ErrorReason = "audience mismatch (server required_audience)"
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("audience mismatch (server required_audience)",
				"trace_id", traceID,
				"scope", req.Scope,
				"identity", req.Identity,
				"expected_audience", h.requiredAudience,
			)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeAudienceMismatch, TraceID: traceID})
		return
	}

	// Step 2: JTI replay prevention (atomic reserve).
	jtiValue := claimString(claims, "jti")
	if jtiValue == "" {
		jtiValue = fmt.Sprintf("%x", sha256.Sum256([]byte(bearer)))
	}
	event.JTI = audit.TruncateJTI(jtiValue, 50)

	expTime := claimExpiry(claims)
	isNew, err := h.jtiCache.Reserve(r.Context(), jtiValue, expTime)
	if err != nil {
		event.Result = audit.ResultCacheError
		event.ErrorReason = fmt.Sprintf("jti cache error: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Error("jti cache reserve failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"identity", req.Identity,
				"error", err,
			)
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal error", Code: CodeInternal, TraceID: traceID})
		return
	}
	if !isNew {
		event.Result = audit.ResultJTIReplay
		event.ErrorReason = "token already used"
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "token replay detected", Code: CodeReplay, TraceID: traceID})
		return
	}

	// JTI is now reserved. Release it on any failure so the client can
	// retry with the same OIDC token after transient errors.
	jtiReserved := true
	defer func() {
		if jtiReserved {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.jtiCache.Release(releaseCtx, jtiValue); err != nil {
				if h.slogger != nil {
					h.slogger.Error("jti release failed",
						"trace_id", traceID,
						"jti", event.JTI,
						"error", err,
					)
				}
			}
		}
	}()

	// Step 3: Resolve app.
	appName, provider, err := h.resolveApp(req.AppName)
	if err != nil {
		event.AppName = req.AppName
		event.Result = audit.ResultUnknownError
		event.ErrorReason = fmt.Sprintf("app resolution failed: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Error("app resolution failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"requested_app", req.AppName,
				"identity", req.Identity,
				"error", err,
			)
		}
		status := http.StatusForbidden
		code := CodeAppUnknown
		msg := "forbidden"
		if strings.Contains(err.Error(), "misconfiguration") {
			status = http.StatusInternalServerError
			code = CodeInternal
			msg = "internal error"
		}
		writeJSON(w, status, ErrorResponse{Error: msg, Code: code, TraceID: traceID})
		return
	}
	event.AppName = appName

	// Resolve the caller-supplied target through the selected App before policy
	// lookup. Names select the GitHub resource; immutable IDs authorize it.
	targetIdentity, err := provider.ResolveTarget(r.Context(), targetScope)
	if err != nil {
		event.Result = audit.ResultGitHubError
		event.ErrorReason = fmt.Sprintf("target resolution failed: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("target resolution failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"app", appName,
				"identity", req.Identity,
				"error", err,
			)
		}
		if errors.Is(err, github.ErrTargetScopeNotCanonical) {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "target scope is not canonical", Code: CodeBadRequest, TraceID: traceID})
			return
		}
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: "upstream error", Code: CodeUpstream, TraceID: traceID})
		return
	}
	event.TargetRepositoryOwner = targetIdentity.Owner
	event.TargetRepositoryOwnerID = targetIdentity.OwnerID
	event.TargetRepository = targetIdentity.Scope
	event.TargetRepositoryID = targetIdentity.RepositoryID

	// Step 4: Load and evaluate policy.
	pol, err := h.policyLoader.Load(r.Context(), policy.LoadRequest{
		Scope:              targetIdentity.Scope,
		TargetOwnerID:      targetIdentity.OwnerID,
		TargetRepositoryID: targetIdentity.RepositoryID,
		AppName:            appName,
		Identity:           req.Identity,
	})
	if err != nil {
		var validationErr *policy.ValidationError
		if errors.As(err, &validationErr) {
			event.Result = audit.ResultPolicyInvalid
			event.ErrorReason = err.Error()
			event.DurationMS = msSince(start)
			h.emitResult(event, req, start)
			if h.slogger != nil {
				h.slogger.Warn("trust policy invalid", "trace_id", traceID, "scope", req.Scope, "app", appName, "identity", req.Identity, "error", err)
			}
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeTrustPolicyInvalid, TraceID: traceID})
			return
		}
		event.Result = audit.ResultGitHubError
		event.ErrorReason = fmt.Sprintf("policy load error: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Error("policy load failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"app", appName,
				"identity", req.Identity,
				"error", err,
				"hint", classifyUpstreamError(err),
			)
		}
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: "upstream error", Code: CodeUpstream, TraceID: traceID})
		return
	}
	if pol == nil {
		event.Result = audit.ResultNotFound
		event.ErrorReason = "policy not found"
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("policy not found",
				"trace_id", traceID,
				"scope", req.Scope,
				"app", appName,
				"identity", req.Identity,
			)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodePolicyNotFound, TraceID: traceID})
		return
	}
	if err := pol.Validate(); err != nil {
		event.Result = audit.ResultPolicyInvalid
		event.ErrorReason = err.Error()
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("trust policy invalid", "trace_id", traceID, "scope", req.Scope, "app", appName, "identity", req.Identity, "error", err)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeTrustPolicyInvalid, TraceID: traceID})
		return
	}

	// Per-policy audience validation. Audience is mandatory in the policy
	// schema (see policy.Validate), so an empty value here means a policy
	// loaded through a non-validating path — fail closed.
	if pol.Audience == "" || !audienceMatches(claims, pol.Audience) {
		event.Result = audit.ResultPolicyDenied
		if pol.Audience == "" {
			event.ErrorReason = "policy missing audience"
		} else {
			event.ErrorReason = "audience mismatch"
		}
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		if h.slogger != nil {
			h.slogger.Warn("audience check failed",
				"trace_id", traceID,
				"scope", req.Scope,
				"identity", req.Identity,
				"expected_audience", pol.Audience,
				"reason", event.ErrorReason,
			)
		}
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeAudienceMismatch, TraceID: traceID})
		return
	}

	// Policy evaluation.
	evalResult := pol.Evaluate(claims)
	if !evalResult.Allowed {
		event.Result = audit.ResultPolicyDenied
		event.ErrorReason = evalResult.Reason
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		h.slogger.Warn("policy denied",
			"trace_id", traceID,
			"scope", req.Scope,
			"identity", req.Identity,
			"issuer", event.Issuer,
			"subject", event.Subject,
			"reason", evalResult.Reason,
		)
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodePolicyDenied, TraceID: traceID})
		return
	}
	if sourceIdentity != nil {
		relationship := pol.EvaluateGitHubRelationship(
			policy.GitHubRepository{
				OwnerID:      policy.GitHubID(sourceIdentity.RepositoryOwnerID),
				RepositoryID: policy.GitHubID(sourceIdentity.RepositoryID),
			},
			policy.GitHubRepository{
				OwnerID:      policy.GitHubID(targetIdentity.OwnerID),
				RepositoryID: policy.GitHubID(targetIdentity.RepositoryID),
			},
		)
		if !relationship.Allowed {
			event.Result = audit.ResultPolicyDenied
			event.ErrorReason = relationship.Reason
			event.DurationMS = msSince(start)
			h.emitResult(event, req, start)
			if h.slogger != nil {
				h.slogger.Warn("source-to-target relationship denied", "trace_id", traceID, "scope", req.Scope, "identity", req.Identity, "reason", relationship.Reason)
			}
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodePolicyDenied, TraceID: traceID})
			return
		}
	}

	// Repository scopes always mint for the one resolved immutable target.
	repositories := []string{targetIdentity.Repository}
	repositoryIDs := []string{targetIdentity.RepositoryID}

	// Step 4.5: Org-rego bundle guardrail. Composes with the YAML policy
	// (deny wins, both must allow). The bundle digest is recorded in
	// the audit event whether the call allowed or denied — it's the
	// fingerprint that proves which bundle gated which decision. A
	// deny here returns 403 org_policy_denied and never reaches the
	// mint call. An engine error fails closed (also 403, not 500) so
	// a Rego compile bug or context cancellation can't accidentally
	// produce an allow.
	if h.bundleManager.Enabled() {
		input := bundle.Input{
			Mode: bundle.ModeExchange,
			Request: bundle.InputRequest{
				Scope: req.Scope, App: appName, Identity: req.Identity,
			},
			YAMLPolicy:     bundle.FromPolicy(pol),
			Claims:         claims,
			SourceIdentity: bundleSourceIdentity(sourceIdentity, h.requireImmutableSubjectClaims),
			TargetIdentity: bundleTargetIdentity(targetIdentity),
			Requested: &bundle.InputRequested{
				Permissions:      pol.Permissions,
				Repositories:     repositories,
				RepositoryIDs:    repositoryIDs,
				OrganizationWide: false,
			},
		}
		decision, evalErr := h.bundleManager.Eval(r.Context(), input)
		if evalErr != nil {
			if decision.SnapshotDigest != "" {
				event.BundleDigest = decision.SnapshotDigest
			} else if decision.EvaluatedDigest != "" {
				event.BundleDigest = decision.EvaluatedDigest
			}
			event.BundleDecisions = audit.FromBundleDecision(decision)
			// Bundle staleness (fail_mode=closed + age > max_staleness)
			// surfaces as 503 bundle_stale, not 403 — this is a server-
			// side dependency degradation, not a policy decision. Clients
			// (and especially github-sts-action) should back off + retry,
			// not surface the request as a hard authorization failure to
			// end users.
			metrics.OrgDecisionTotal.WithLabelValues(appName, "all", "error").Inc()
			code := CodeBundleEvaluationFailed
			result := audit.ResultBundleEvaluationFailed
			reason := "bundle evaluation failed"
			logMessage := "bundle evaluation failed (failing closed)"
			retryAfter := "1"
			switch {
			case errors.Is(evalErr, bundle.ErrBundleStale):
				code = CodeBundleStale
				result = audit.ResultBundleStale
				reason = "bundle stale (no successful refresh within max_staleness)"
				logMessage = "bundle stale: refusing exchange (fail_mode=closed)"
				retryAfter = "60"
			case errors.Is(evalErr, bundle.ErrBundleUnavailable), errors.Is(evalErr, bundle.ErrDisabled):
				code = CodeBundleUnavailable
				result = audit.ResultBundleUnavailable
				reason = "mandatory bundle unavailable"
				logMessage = "mandatory bundle unavailable (failing closed)"
				retryAfter = "60"
			}
			event.Result = result
			event.ErrorReason = fmt.Sprintf("%s: %v", reason, evalErr)
			event.OrgDecision = &audit.OrgDecision{
				Applicable: decision.Applicable,
				Evaluated:  decision.Evaluated,
				Allow:      false,
				Reasons:    []string{reason},
			}
			event.DurationMS = msSince(start)
			h.emitResult(event, req, start)
			h.slogger.Error(logMessage,
				"trace_id", traceID,
				"scope", req.Scope,
				"app", appName,
				"identity", req.Identity,
				"bundle_digest", event.BundleDigest,
				"error", evalErr,
			)
			w.Header().Set("Retry-After", retryAfter)
			writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "service unavailable", Code: code, TraceID: traceID})
			return
		}
		if decision.EvaluatedDigest != "" {
			event.BundleDigest = decision.EvaluatedDigest
		}
		event.OrgDecision = &audit.OrgDecision{
			Applicable: decision.Applicable,
			Evaluated:  decision.Evaluated,
			Allow:      decision.Allow,
			Reasons:    decision.Reasons,
		}
		event.BundleDecisions = audit.FromBundleDecision(decision)
		if !decision.Allow {
			metrics.OrgDecisionTotal.WithLabelValues(appName, "all", "deny").Inc()
			event.Result = audit.ResultOrgPolicyDenied
			event.ErrorReason = fmt.Sprintf("org policy denied: %v", decision.Reasons)
			event.DurationMS = msSince(start)
			h.emitResult(event, req, start)
			h.slogger.Warn("org policy denied",
				"trace_id", traceID,
				"scope", req.Scope,
				"app", appName,
				"identity", req.Identity,
				"bundle_digest", event.BundleDigest,
				"reasons", decision.Reasons,
			)
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden", Code: CodeOrgPolicyDenied, TraceID: traceID})
			return
		}
		if decision.Evaluated {
			metrics.OrgDecisionTotal.WithLabelValues(appName, "all", "allow").Inc()
		} else {
			metrics.OrgDecisionTotal.WithLabelValues(appName, "all", "not_evaluated").Inc()
		}
	}

	issued, instance, err := provider.GetInstallationTokenForTarget(r.Context(), targetIdentity, pol.Permissions, traceID)
	if err != nil {
		event.Result = audit.ResultGitHubError
		event.ErrorReason = fmt.Sprintf("github token issuance failed: %v", err)
		event.DurationMS = msSince(start)
		h.emitResult(event, req, start)
		h.slogger.Error("github token issuance failed",
			"trace_id", traceID,
			"scope", req.Scope,
			"app", appName,
			"identity", req.Identity,
			"error", err,
			"hint", classifyUpstreamError(err),
		)
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: "upstream error", Code: CodeUpstream, TraceID: traceID})
		return
	}

	// Token issued — keep the JTI reserved to prevent replay.
	jtiReserved = false

	// Success.
	event.Instance = instance
	event.Result = audit.ResultSuccess
	event.DurationMS = msSince(start)
	h.emitResult(event, req, start)

	writeJSON(w, http.StatusOK, ExchangeResponse{
		Token:       issued.Token,
		ExpiresIn:   expiresIn(issued.ExpiresAt, time.Now()),
		Scope:       req.Scope,
		App:         appName,
		Identity:    req.Identity,
		Permissions: pol.Permissions,
	})
}

// resolveApp determines which app provider to use.
func (h *ExchangeHandler) resolveApp(requestedApp string) (string, github.ExchangeApp, error) {
	if requestedApp != "" {
		provider, ok := h.appProviders[requestedApp]
		if !ok {
			return "", nil, fmt.Errorf("unknown app %q", requestedApp)
		}
		return requestedApp, provider, nil
	}

	switch len(h.appProviders) {
	case 0:
		return "", nil, fmt.Errorf("no apps configured (misconfiguration)")
	case 1:
		for name, provider := range h.appProviders {
			return name, provider, nil
		}
	}

	return "", nil, fmt.Errorf("app parameter required when multiple apps configured")
}

// emitResult records metrics and audit events.
func (h *ExchangeHandler) emitResult(event audit.Event, req ExchangeRequest, start time.Time) {
	h.auditLogger.Log(event)

	result := string(event.Result)
	metrics.TokenExchangesTotal.WithLabelValues(
		event.AppName, event.Instance, req.Scope, req.Identity, event.Issuer, result,
	).Inc()

	if event.Result == audit.ResultSuccess {
		metrics.TokenExchangeLatency.WithLabelValues(
			event.AppName, event.Instance, req.Scope, req.Identity, event.Issuer,
		).Observe(time.Since(start).Seconds())
	}
}

// parseExchangeRequest extracts parameters from GET query or POST JSON body.
func parseExchangeRequest(r *http.Request) (ExchangeRequest, error) {
	if r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(ct, "application/json") {
			return ExchangeRequest{}, fmt.Errorf("unsupported content type: expected application/json")
		}
		r.Body = http.MaxBytesReader(nil, r.Body, maxRequestBodyBytes)
		var req ExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return ExchangeRequest{}, fmt.Errorf("invalid JSON body: %w", err)
		}
		return req, nil
	}

	// GET — read from query string.
	return ExchangeRequest{
		Scope:    r.URL.Query().Get("scope"),
		Identity: r.URL.Query().Get("identity"),
		AppName:  r.URL.Query().Get("app"),
	}, nil
}

// extractBearer extracts the bearer token from the Authorization header.
func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// traceIDFromContext extracts the trace ID from the request context.
func traceIDFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(TraceIDKey).(string); ok {
		return v
	}
	return "no-trace"
}

// claimString extracts a string claim from the claims map.
func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// claimExpiry extracts the exp claim as a time.Time.
func claimExpiry(claims map[string]any) time.Time {
	if claims == nil {
		return time.Now().Add(1 * time.Hour)
	}
	v, ok := claims["exp"]
	if !ok {
		return time.Now().Add(1 * time.Hour)
	}
	switch exp := v.(type) {
	case float64:
		return time.Unix(int64(exp), 0)
	case json.Number:
		if n, err := exp.Int64(); err == nil {
			return time.Unix(n, 0)
		}
	}
	return time.Now().Add(1 * time.Hour)
}

// audienceMatches checks if the token's aud claim matches the expected audience.
func audienceMatches(claims map[string]any, expected string) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}

	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func bundleSourceIdentity(identity *oidc.GitHubIdentity, required bool) *bundle.InputSourceIdentity {
	if identity == nil {
		return nil
	}
	return &bundle.InputSourceIdentity{
		Version:                  bundle.SourceIdentityVersionV1,
		Issuer:                   identity.Issuer,
		Subject:                  identity.Subject,
		RepositoryOwner:          identity.RepositoryOwner,
		RepositoryOwnerID:        identity.RepositoryOwnerID,
		Repository:               identity.Repository,
		RepositoryID:             identity.RepositoryID,
		ImmutableSubject:         identity.ImmutableSubject,
		ImmutableSubjectRequired: required,
	}
}

func bundleTargetIdentity(identity github.TargetIdentity) *bundle.InputTargetIdentity {
	return &bundle.InputTargetIdentity{
		Version:           bundle.TargetIdentityVersionV1,
		Scope:             identity.Scope,
		RepositoryOwner:   identity.Owner,
		RepositoryOwnerID: identity.OwnerID,
		Repository:        identity.Scope,
		RepositoryID:      identity.RepositoryID,
	}
}

// remoteIP extracts the client IP from the request. X-Forwarded-For is
// only trusted when explicitly enabled via configuration.
func remoteIP(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.SplitN(fwd, ",", 2)
			return strings.TrimSpace(parts[0])
		}
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// classifyUpstreamError extracts an actionable hint from a GitHub API
// error for structured logging. Operators can search for these hints.
func classifyUpstreamError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "is not installed on organization"):
		return "GitHub App is not installed on the target organization. Install it via the GitHub organization settings."
	case strings.Contains(msg, "authentication failed"):
		return "GitHub App credentials are invalid. Verify app_id and private_key in the configuration."
	case strings.Contains(msg, "HTTP 422"):
		return "GitHub refused the token request. The policy may request permissions or repositories the App is not authorized for."
	case strings.Contains(msg, "org_policy_repo required"):
		return "Org-level scope requires org_policy_repo to be set in the app configuration."
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "context canceled"):
		return "Request to GitHub API timed out. Check network connectivity and GitHub API status."
	default:
		return "Unexpected GitHub API error. Check the error field for details."
	}
}

// validateField checks that a user-supplied field contains only safe
// characters and does not exceed the maximum length. This prevents
// Prometheus label cardinality abuse from malicious input.
func validateField(name, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d", name, maxLen)
	}
	if !safeFieldPattern.MatchString(value) {
		return fmt.Errorf("%s contains invalid characters", name)
	}
	return nil
}

// msSince returns milliseconds elapsed since start.
func msSince(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
