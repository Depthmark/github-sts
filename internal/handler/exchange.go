// Package handler implements HTTP handlers for the github-sts service.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
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
type ExchangeResponse struct {
	Token       string            `json:"token"`
	Scope       string            `json:"scope"`
	App         string            `json:"app"`
	Identity    string            `json:"identity"`
	Permissions map[string]string `json:"permissions"`
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
	CodeOIDCInvalid      = "oidc_invalid"       // missing/expired/bad-signature/unknown-issuer/missing-kid/malformed
	CodeAudienceMismatch = "audience_mismatch"  // token aud did not match policy.audience
	CodeAppUnknown       = "app_unknown"        // requested ?app= is not configured on the server
	CodePolicyNotFound   = "policy_not_found"   // no .sts.yaml for this scope/app/identity
	CodePolicyDenied     = "policy_denied"      // policy exists but evaluation failed (subject/claim_pattern)

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
	jtiCache              jti.Cache
	policyLoader          policy.Loader
	appProviders          map[string]*github.AppTokenProvider
	allowedIssuers        []string
	requiredAudience      string
	auditLogger           audit.Logger
	slogger               *slog.Logger
	trustForwardedHeaders bool
}

// NewExchangeHandler creates a new ExchangeHandler with all dependencies injected.
// requiredAudience, when non-empty, is enforced on every token before policy
// lookup as a server-wide defense against permissive policy files.
func NewExchangeHandler(
	jtiCache jti.Cache,
	policyLoader policy.Loader,
	appProviders map[string]*github.AppTokenProvider,
	allowedIssuers []string,
	requiredAudience string,
	auditLogger audit.Logger,
	slogger *slog.Logger,
	trustForwardedHeaders bool,
) *ExchangeHandler {
	return &ExchangeHandler{
		jtiCache:              jtiCache,
		policyLoader:          policyLoader,
		appProviders:          appProviders,
		allowedIssuers:        allowedIssuers,
		requiredAudience:      requiredAudience,
		auditLogger:           auditLogger,
		slogger:               slogger,
		trustForwardedHeaders: trustForwardedHeaders,
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

	// Build base audit event.
	event := audit.Event{
		TraceID:   traceID,
		Scope:     req.Scope,
		Identity:  req.Identity,
		UserAgent: audit.TruncateUserAgent(r.UserAgent(), 100),
		RemoteIP:  remoteIP(r, h.trustForwardedHeaders),
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

	claims, err := oidc.Validate(r.Context(), bearer, h.allowedIssuers)
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

	// Step 4: Load and evaluate policy.
	pol, err := h.policyLoader.Load(r.Context(), req.Scope, appName, req.Identity)
	if err != nil {
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

	// Step 5: Issue GitHub token.
	subject, _ := claims["sub"].(string)
	repositories := buildRepositories(req.Scope, pol, subject)
	token, err := provider.GetInstallationToken(r.Context(), req.Scope, pol.Permissions, repositories, traceID)
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
	event.Result = audit.ResultSuccess
	event.DurationMS = msSince(start)
	h.emitResult(event, req, start)

	writeJSON(w, http.StatusOK, ExchangeResponse{
		Token:       token,
		Scope:       req.Scope,
		App:         appName,
		Identity:    req.Identity,
		Permissions: pol.Permissions,
	})
}

// resolveApp determines which app provider to use.
func (h *ExchangeHandler) resolveApp(requestedApp string) (string, *github.AppTokenProvider, error) {
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
		event.AppName, req.Scope, req.Identity, event.Issuer, result,
	).Inc()

	if event.Result == audit.ResultSuccess {
		metrics.TokenExchangeLatency.WithLabelValues(
			event.AppName, req.Scope, req.Identity, event.Issuer,
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

// subjectRepoPattern matches the leading "repo:<org>/<repo>:" segment of a
// GitHub Actions OIDC subject and captures the repo name.
var subjectRepoPattern = regexp.MustCompile(`^repo:[^/]+/([^:]+):`)

// buildRepositories constructs the repository list for token issuance.
//
// Security invariants:
//   - Repo-level scope ("org/repo") always issues a token restricted to that
//     repo, regardless of what the policy declares.
//   - Centralized policies (loaded from the org policy repo) NEVER issue
//     org-wide tokens. For org-level scope, the requesting repo is derived
//     from the OIDC subject and the token is restricted to that single repo.
//     This prevents a centralized identity from minting cross-repo tokens.
//   - Non-centralized org-level scope falls back to the policy's repositories
//     field (may be nil for full org access — only honored for repo-local
//     identities that explicitly opt in).
func buildRepositories(scope string, pol *policy.TrustPolicy, subject string) []string {
	if strings.Contains(scope, "/") {
		parts := strings.SplitN(scope, "/", 2)
		if len(parts) == 2 {
			return []string{parts[1]}
		}
	}
	if pol.Centralized() {
		if m := subjectRepoPattern.FindStringSubmatch(subject); len(m) == 2 {
			return []string{m[1]}
		}
		// Centralized policy but subject doesn't identify a repo — refuse to
		// issue an org-wide token. Returning an empty (non-nil) slice causes
		// GitHub to reject the token request rather than grant org-wide access.
		return []string{}
	}
	return pol.Repositories
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
