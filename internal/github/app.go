// Package github provides server-side GitHub App authentication, rate limit
// monitoring, and reachability probing.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// installationCacheTTL controls how long resolved installation IDs are
// cached. If a GitHub App is removed and reinstalled, the old ID becomes
// stale; this TTL ensures the service self-heals without a restart.
const installationCacheTTL = 15 * time.Minute

// appJWTCacheTTL controls how long the signed App JWT is reused. The JWT
// itself is valid for 10 minutes; we cache for 9 minutes to leave a
// 1-minute safety margin. This eliminates redundant RSA signings on the
// hot path (~1-2ms each) without any security impact — the JWT is an
// internal server credential that never leaves the service.
const appJWTCacheTTL = 9 * time.Minute

type cachedInstallation struct {
	id          int64
	permissions map[string]string // granted permissions on the installation
	fetchedAt   time.Time
}

type cachedJWT struct {
	token     string
	expiresAt time.Time
}

// AppTokenProvider creates permission-scoped GitHub installation tokens
// for the server-side exchange flow.
type AppTokenProvider struct {
	appName           string // logical app name (e.g. "checkout") — stable across a pool
	instance          string // this credential's identity within its pool (e.g. "checkout-2" or app_id); equals appName's app_id for a non-pooled app
	appID             int64
	privateKey        *rsa.PrivateKey
	apiURL            string
	httpClient        *http.Client
	installationCache map[string]*cachedInstallation // org → entry
	targetCache       map[string]*cachedTarget       // canonical owner/repository → entry
	mu                sync.RWMutex
	jwtCache          cachedJWT
	jwtMu             sync.Mutex
	installSF         singleflight.Group
	targetSF          singleflight.Group
}

// NewAppTokenProvider creates a server-side AppTokenProvider. instance
// labels this specific credential (e.g. "checkout-2") for metrics/logs when
// it's one member of an AppPool; appName stays the logical app name shared
// by every member of the same pool.
func NewAppTokenProvider(appName, instance string, appID int64, privateKey *rsa.PrivateKey, apiURL string, httpClient *http.Client) *AppTokenProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &AppTokenProvider{
		appName:           appName,
		instance:          instance,
		appID:             appID,
		privateKey:        privateKey,
		apiURL:            apiURL,
		httpClient:        httpClient,
		installationCache: make(map[string]*cachedInstallation),
		targetCache:       make(map[string]*cachedTarget),
	}
}

// TokenMintError classifies a GetInstallationID/GetInstallationToken failure
// for callers (AppPool) deciding whether retrying the same request against a
// different pool credential is worth attempting. StatusCode is 0 when no
// HTTP response was received (network/timeout error).
type TokenMintError struct {
	StatusCode int
	Retryable  bool
	Err        error
}

func (e *TokenMintError) Error() string { return e.Err.Error() }
func (e *TokenMintError) Unwrap() error { return e.Err }

// GenerateAppJWT returns a short-lived JWT for authenticating as the GitHub
// App. The signed token is cached for 9 minutes (valid for 10) to avoid
// redundant RSA signing operations under load.
func (p *AppTokenProvider) GenerateAppJWT() (string, error) {
	p.jwtMu.Lock()
	defer p.jwtMu.Unlock()

	if p.jwtCache.token != "" && time.Now().Before(p.jwtCache.expiresAt) {
		return p.jwtCache.token, nil
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": fmt.Sprintf("%d", p.appID),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(p.privateKey)
	if err != nil {
		return "", err
	}

	p.jwtCache = cachedJWT{
		token:     signed,
		expiresAt: now.Add(appJWTCacheTTL),
	}
	return signed, nil
}

// GetInstallationID resolves the GitHub App installation ID for the given scope.
// Only org-level resolution is supported (no repo-level fallback).
// Concurrent requests for the same org are deduplicated via singleflight.
func (p *AppTokenProvider) GetInstallationID(ctx context.Context, scope string) (int64, error) {
	org := extractOrg(scope)

	// Check cache (with TTL).
	p.mu.RLock()
	if entry, ok := p.installationCache[org]; ok && time.Since(entry.fetchedAt) < installationCacheTTL {
		p.mu.RUnlock()
		return entry.id, nil
	}
	p.mu.RUnlock()

	// Singleflight: deduplicate concurrent fetches for the same org.
	v, err, _ := p.installSF.Do(org, func() (any, error) {
		// Double-check cache after winning the singleflight race.
		p.mu.RLock()
		if entry, ok := p.installationCache[org]; ok && time.Since(entry.fetchedAt) < installationCacheTTL {
			p.mu.RUnlock()
			return entry.id, nil
		}
		p.mu.RUnlock()

		return p.fetchInstallationID(ctx, org)
	})
	if err != nil {
		return 0, err
	}
	return v.(int64), nil
}

// fetchInstallationID resolves the installation ID for org via this
// specific credential. Every failure path is wrapped in a *TokenMintError
// with Retryable: true — a failure here (not installed, bad credentials,
// upstream error) is inherently a property of *this* instance, and another
// pool member's independent credentials/installation may well succeed where
// this one didn't (see design doc §5.6 on graceful degradation via
// failover). This is unlike GetInstallationToken's 422, which reflects a
// requested-permissions problem no amount of retrying can fix.
func (p *AppTokenProvider) fetchInstallationID(ctx context.Context, org string) (int64, error) {
	appJWT, err := p.GenerateAppJWT()
	if err != nil {
		return 0, &TokenMintError{Retryable: true, Err: fmt.Errorf("generating app JWT: %w", err)}
	}

	url := fmt.Sprintf("%s/orgs/%s/installation", p.apiURL, org)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, &TokenMintError{Retryable: true, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "get_installation", "error").Inc()
		return 0, &TokenMintError{Retryable: true, Err: fmt.Errorf("resolving installation for org %q: %w", org, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	ExtractRateLimitHeaders(resp, p.appName, p.instance, "get_installation")

	if resp.StatusCode == http.StatusNotFound {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "get_installation", "not_found").Inc()
		return 0, &TokenMintError{StatusCode: resp.StatusCode, Retryable: true, Err: fmt.Errorf(
			"github app %q instance %q (app_id: %d) is not installed on organization %q — "+
				"install it at https://github.com/organizations/%s/settings/installations",
			p.appName, p.instance, p.appID, org, org)}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "get_installation", "auth_error").Inc()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, &TokenMintError{StatusCode: resp.StatusCode, Retryable: true, Err: fmt.Errorf(
			"github app %q instance %q (app_id: %d) authentication failed for org %q (HTTP %d) — "+
				"verify the app_id and private_key are correct: %s",
			p.appName, p.instance, p.appID, org, resp.StatusCode, string(body))}
	}
	if resp.StatusCode != http.StatusOK {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "get_installation", "error").Inc()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, &TokenMintError{StatusCode: resp.StatusCode, Retryable: true, Err: fmt.Errorf(
			"resolving installation for org %q via app %q instance %q: GitHub API returned HTTP %d: %s",
			org, p.appName, p.instance, resp.StatusCode, string(body))}
	}

	var install struct {
		ID          int64             `json:"id"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&install); err != nil {
		return 0, &TokenMintError{StatusCode: resp.StatusCode, Retryable: true, Err: err}
	}

	metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "get_installation", "ok").Inc()

	// Cache the result with timestamp. We capture the installation's granted
	// permissions so we can diff them against requested permissions on a 422.
	p.mu.Lock()
	p.installationCache[org] = &cachedInstallation{
		id:          install.ID,
		permissions: install.Permissions,
		fetchedAt:   time.Now(),
	}
	p.mu.Unlock()

	return install.ID, nil
}

// GetGrantedPermissions returns the cached set of permissions actually
// granted to this app's installation on the given org, or nil if no
// installation has been resolved yet (or the entry has expired). It does NOT
// trigger a fetch — call GetInstallationID first if needed.
func (p *AppTokenProvider) GetGrantedPermissions(scope string) map[string]string {
	org := extractOrg(scope)
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.installationCache[org]
	if !ok || time.Since(entry.fetchedAt) >= installationCacheTTL {
		return nil
	}
	if entry.permissions == nil {
		return nil
	}
	out := make(map[string]string, len(entry.permissions))
	for k, v := range entry.permissions {
		out[k] = v
	}
	return out
}

// MintedToken is one installation token plus the grant GitHub actually
// attached to it. Permissions comes from the 201 response body, not from
// what we requested: the two are expected to agree, but only the response
// is authoritative, and callers that report a token's scope to a client
// must report this rather than the ask. Never log Token (BR-2A-17).
type MintedToken struct {
	Token       string
	Permissions map[string]string

	// ExpiresAt is the absolute expiry GitHub reported, which is what lets
	// the broker tell callers how long the token is good for (RFC 8693
	// expires_in) instead of making them assume GitHub's one-hour default.
	//
	// It is the zero time when GitHub omitted expires_at or sent a value we
	// could not parse. The token is still usable, so that is not an error —
	// callers must treat a zero ExpiresAt as "lifetime unknown" and fall
	// back to their own refresh heuristic rather than reporting an expiry
	// they invented.
	ExpiresAt time.Time

	// InstallationPermissions is what the GitHub App installation itself
	// holds on the target org: the absolute ceiling above the trust policy,
	// and the blast radius of this credential if it were compromised. It
	// comes from the instance that actually minted the token, so in a pool
	// there is no ambiguity about whose installation it describes.
	//
	// This is the *installation's* grant, not the App's registered
	// permissions. They differ whenever the App declares a permission the
	// org admin has not yet accepted; the accepted set is the one that
	// governs, and the unaccepted delta is a common cause of 422s (see
	// permissionDiffHint).
	//
	// nil when the installation cache entry expired between the mint and
	// this read, which is rare and non-fatal: callers log it as unknown
	// rather than treating it as "no permissions".
	InstallationPermissions map[string]string
}

// implicitPermissions are permissions GitHub attaches to an installation
// token regardless of what was requested, so seeing them in a grant that
// did not ask for them is normal and must not be reported as divergence.
//
// PROVISIONAL: confirm against real API output before trusting this list —
// run tools/probe-token-permissions.sh and reconcile. metadata:read is
// GitHub's documented always-on repository permission; if the probe shows
// others, add them here rather than loosening the comparison.
var implicitPermissions = map[string]bool{
	"metadata": true,
}

// checkPermissionDivergence compares the grant GitHub returned against what
// was requested and reports any mismatch.
//
// The two directions are not equally serious. An over-grant means the token
// can do more than the caller asked for, which is a privilege-boundary
// failure and the thing that makes narrowing meaningful at all: if GitHub
// silently upgraded a requested read back to the installation's write, every
// narrowed request would be a lie. An under-grant is surprising and worth
// knowing about, but it fails safe. Both are counted; both warn.
//
// A nil requested set means "inherit everything the installation has", so
// there is no ask to compare against and the check is skipped.
func (p *AppTokenProvider) checkPermissionDivergence(granted, requested map[string]string, scope, caller string) {
	if requested == nil || granted == nil {
		return
	}

	var above, below []string
	for _, perm := range sortedPermissionNames(granted) {
		grantedLevel := granted[perm]
		requestedLevel, asked := requested[perm]
		if !asked {
			if implicitPermissions[perm] {
				continue
			}
			above = append(above, fmt.Sprintf("%s (granted %s, not requested)", perm, grantedLevel))
			continue
		}
		if policy.PermissionRank(grantedLevel) > policy.PermissionRank(requestedLevel) {
			above = append(above, fmt.Sprintf("%s (requested %s, granted %s)", perm, requestedLevel, grantedLevel))
		}
	}
	for _, perm := range sortedPermissionNames(requested) {
		requestedLevel := requested[perm]
		grantedLevel, ok := granted[perm]
		if !ok {
			below = append(below, fmt.Sprintf("%s (requested %s, not granted)", perm, requestedLevel))
			continue
		}
		if policy.PermissionRank(grantedLevel) < policy.PermissionRank(requestedLevel) {
			below = append(below, fmt.Sprintf("%s (requested %s, granted %s)", perm, requestedLevel, grantedLevel))
		}
	}

	for _, entry := range above {
		metrics.GitHubTokenPermissionDivergence.WithLabelValues(p.appName, p.instance, permissionNameOf(entry), "above_requested").Inc()
	}
	for _, entry := range below {
		metrics.GitHubTokenPermissionDivergence.WithLabelValues(p.appName, p.instance, permissionNameOf(entry), "below_requested").Inc()
	}

	if len(above) > 0 {
		slog.Warn("github granted more permission than requested",
			"app", p.appName, "instance", p.instance, "scope", scope, "caller", caller,
			"requested_permissions", policy.FormatPermissions(requested),
			"granted_permissions", policy.FormatPermissions(granted),
			"divergence", strings.Join(above, "; "),
			"hint", "the token exceeds what the caller asked for; narrowing is not being honored upstream",
		)
	}
	if len(below) > 0 {
		slog.Warn("github granted less permission than requested",
			"app", p.appName, "instance", p.instance, "scope", scope, "caller", caller,
			"requested_permissions", policy.FormatPermissions(requested),
			"granted_permissions", policy.FormatPermissions(granted),
			"divergence", strings.Join(below, "; "),
			"hint", "fails safe, but callers may see unexpected 403s from the GitHub API",
		)
	}
}

// permissionNameOf recovers the bare permission name from a divergence
// entry so it can be used as a metric label. The name is always the first
// space-separated field, and it comes from GitHub's fixed permission set,
// which keeps the label bounded.
func permissionNameOf(entry string) string {
	if idx := strings.IndexByte(entry, ' '); idx > 0 {
		return entry[:idx]
	}
	return entry
}

func sortedPermissionNames(perms map[string]string) []string {
	names := make([]string, 0, len(perms))
	for name := range perms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func equalPermissions(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// GetInstallationToken creates a permission-scoped GitHub installation token.
// GetInstallationToken creates a permission-scoped GitHub installation
// token. Failures are wrapped in *TokenMintError (see the type doc):
// network/timeout and 5xx/rate-limit responses are Retryable so AppPool can
// fail over to another instance; a 422 (permission/repo mismatch) and any
// other unclassified response are not — retrying elsewhere can't fix a
// requested-permissions problem, and an unrecognized failure mode fails
// closed rather than being silently masked by blind cross-credential retries.
func (p *AppTokenProvider) GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, error) {
	if repositories != nil && len(repositories) == 0 {
		return "", fmt.Errorf("refusing to create an unrestricted installation token from an empty repository list")
	}
	if repositories == nil && strings.Contains(scope, "/") {
		parts := strings.SplitN(scope, "/", 2)
		repositories = []string{parts[1]}
	}
	// No ceiling: this path (policy-file reads, target resolution) has no
	// caller-supplied narrowing, so the requested set is its own ceiling.
	minted, err := p.getInstallationToken(ctx, scope, permissions, repositories, nil, nil, caller)
	if err != nil {
		return "", err
	}
	return minted.Token, nil
}

func (p *AppTokenProvider) getInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, repositoryIDs []int64, ceiling map[string]string, caller string) (MintedToken, error) {
	if repositories != nil && repositoryIDs != nil {
		return MintedToken{}, fmt.Errorf("repository names and IDs are mutually exclusive")
	}
	if repositoryIDs != nil && len(repositoryIDs) == 0 {
		return MintedToken{}, fmt.Errorf("refusing to create an unrestricted installation token from an empty repository ID list")
	}
	installationID, err := p.GetInstallationID(ctx, scope)
	if err != nil {
		return MintedToken{}, err
	}

	appJWT, err := p.GenerateAppJWT()
	if err != nil {
		return MintedToken{}, &TokenMintError{Retryable: true, Err: fmt.Errorf("generating app JWT: %w", err)}
	}

	// Build request body with permissions and optional repository restriction.
	body := make(map[string]any)
	if permissions != nil {
		body["permissions"] = permissions
	}
	if repositories != nil {
		body["repositories"] = repositories
	}
	if repositoryIDs != nil {
		body["repository_ids"] = repositoryIDs
	}

	var reqBody bytes.Buffer
	if err := json.NewEncoder(&reqBody).Encode(body); err != nil {
		return MintedToken{}, &TokenMintError{Retryable: true, Err: err}
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &reqBody)
	if err != nil {
		return MintedToken{}, &TokenMintError{Retryable: true, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "create_token", "error").Inc()
		return MintedToken{}, &TokenMintError{Retryable: true, Err: fmt.Errorf("creating installation token: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	ExtractRateLimitHeaders(resp, p.appName, p.instance, caller)

	if resp.StatusCode == http.StatusUnprocessableEntity {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "create_token", "error").Inc()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		// Diff the requested permissions against what the installation
		// actually has, so the operator sees exactly which permission is
		// missing or insufficient (GitHub's 422 body doesn't say).
		granted := p.GetGrantedPermissions(scope)
		diff := DiffPermissions(permissions, granted)
		slog.Error("github token issuance refused (HTTP 422)",
			"app", p.appName,
			"instance", p.instance,
			"app_id", p.appID,
			"scope", scope,
			"installation_id", installationID,
			"requested_permissions", permissions,
			"requested_repositories", repositories,
			"requested_repository_ids", repositoryIDs,
			"granted_permissions", granted,
			"permissions_diff", diff,
			"github_response", string(respBody),
			"caller", caller,
			"hint", permissionDiffHint(diff, granted),
		)
		return MintedToken{}, &TokenMintError{StatusCode: resp.StatusCode, Retryable: false, Err: fmt.Errorf(
			"github refused to create token for app %q instance %q scope %q — "+
				"the requested permissions or repositories may exceed what the app is allowed (HTTP 422): %s",
			p.appName, p.instance, scope, string(respBody))}
	}
	if resp.StatusCode != http.StatusCreated {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "create_token", "error").Inc()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return MintedToken{}, &TokenMintError{
			StatusCode: resp.StatusCode,
			Retryable:  isRetryableTokenMintStatus(resp),
			Err: fmt.Errorf("creating installation token for app %q instance %q scope %q: GitHub API returned HTTP %d: %s",
				p.appName, p.instance, scope, resp.StatusCode, string(respBody)),
		}
	}

	// GitHub echoes the token's *actual* grant back in the 201. That is the
	// only authoritative statement of what this credential can do — what we
	// asked for in `permissions` is just a request — so decode it and carry
	// it up rather than assuming the ask was honored verbatim.
	var result struct {
		Token       string            `json:"token"`
		ExpiresAt   string            `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return MintedToken{}, &TokenMintError{StatusCode: resp.StatusCode, Retryable: false, Err: err}
	}

	// GitHub documents expires_at as RFC 3339 (currently one hour out), but a
	// token we already hold is worth more than a lifetime hint: an absent or
	// unparseable value degrades to "lifetime unknown" instead of discarding
	// a valid credential. See MintedToken.
	var expiresAt time.Time
	if result.ExpiresAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339, result.ExpiresAt)
		if parseErr != nil {
			slog.Warn("github returned an unparseable token expiry",
				"app", p.appName, "instance", p.instance, "scope", scope,
				"expires_at", result.ExpiresAt, "error", parseErr, "caller", caller)
		} else {
			expiresAt = parsed
		}
	}

	p.checkPermissionDivergence(result.Permissions, permissions, scope, caller)

	// Label the issuance metric from the policy ceiling, never from the
	// effective set. The ceiling is policy-derived and therefore bounded;
	// the effective set is caller-controlled and would otherwise add one
	// series per requestable subset (see internal/metrics/metrics.go).
	labelPermissions := ceiling
	if labelPermissions == nil {
		labelPermissions = permissions
	}

	// Emit metrics — NEVER log the token value (BR-2A-17).
	permStr := policy.FormatPermissions(labelPermissions)
	narrowed := strconv.FormatBool(!equalPermissions(permissions, labelPermissions))
	metrics.GitHubTokenIssued.WithLabelValues(p.appName, p.instance, scope, permStr, narrowed).Inc()
	metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "create_token", "ok").Inc()
	slog.Info("installation token issued",
		"app", p.appName,
		"instance", p.instance,
		"scope", scope,
		"permissions", permStr,
		"requested_permissions", policy.FormatPermissions(permissions),
		"granted_permissions", policy.FormatPermissions(result.Permissions),
		"narrowed", narrowed,
		"caller", caller,
	)

	return MintedToken{
		Token:       result.Token,
		Permissions: result.Permissions,
		ExpiresAt:   expiresAt,
		// Already resolved and cached by GetInstallationID above, so this
		// is a map copy rather than another API call.
		InstallationPermissions: p.GetGrantedPermissions(scope),
	}, nil
}

// isRetryableTokenMintStatus reports whether a non-201, non-422
// GetInstallationToken response is worth retrying against a different pool
// instance: primary rate limit (403 or 429 + remaining=0), secondary/abuse
// rate limit (403 or 429 + Retry-After), or a 5xx. GitHub documents both 403
// and 429 for primary and secondary rate-limit responses — see
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit.
// Everything else (other 4xx, or a bare 403/429 with neither signal) fails
// closed — not retried.
func isRetryableTokenMintStatus(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return true
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("Retry-After") != "" {
			return true
		}
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return true
		}
	}
	return false
}

// ExtractRateLimitHeaders reads GitHub rate limit headers from an HTTP
// response and updates Prometheus gauges. Also detects rate limit exceeded
// conditions on 403 or 429 responses. instance labels which pool member (or,
// for a non-pooled app, which normalized single instance) made the call.
func ExtractRateLimitHeaders(resp *http.Response, appName, instance, caller string) {
	resource := resp.Header.Get("X-RateLimit-Resource")
	if resource == "" {
		resource = "core"
	}

	if v := resp.Header.Get("X-RateLimit-Limit"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitLimit.WithLabelValues(appName, instance, resource).Set(n)
		}
	}

	var remaining, limit float64
	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			remaining = n
			metrics.GitHubRateLimitRemaining.WithLabelValues(appName, instance, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Used"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitUsed.WithLabelValues(appName, instance, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitResetTimestamp.WithLabelValues(appName, instance, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Limit"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			limit = n
		}
	}

	if limit > 0 {
		pct := (remaining / limit) * 100
		metrics.GitHubRateLimitRemainingPercent.WithLabelValues(appName, instance, resource).Set(pct)
	}

	// Detect rate limit exceeded on 403 or 429 — GitHub documents both status
	// codes for primary and secondary rate limits (see
	// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit).
	// Signal detection matches isRetryableTokenMintStatus exactly (an
	// explicit Retry-After or X-RateLimit-Remaining: 0 header), so failover
	// and observability share one contract: a header absent is not the same
	// as a header present with value 0, and the parsed remaining float above
	// (0 when the header is absent) is deliberately not reused here.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			// Secondary/abuse rate limit.
			metrics.GitHubSecondaryRateLimitTotal.WithLabelValues(appName, instance, caller).Inc()
			if n, err := strconv.ParseFloat(retryAfter, 64); err == nil {
				metrics.GitHubSecondaryRateLimitRetryAfter.WithLabelValues(appName, instance).Set(n)
			}
			slog.Warn("secondary rate limit hit", "app", appName, "instance", instance, "status", resp.StatusCode, "retry_after", retryAfter, "caller", caller)
		} else if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			// Primary rate limit exceeded.
			metrics.GitHubRateLimitExceededTotal.WithLabelValues(appName, instance, resource, caller).Inc()
			slog.Warn("primary rate limit exceeded", "app", appName, "instance", instance, "status", resp.StatusCode, "resource", resource, "caller", caller)
		}
	}
}

// extractOrg returns the org portion of a scope.
// "myorg/myrepo" → "myorg", "myorg" → "myorg".
func extractOrg(scope string) string {
	if idx := strings.Index(scope, "/"); idx >= 0 {
		return scope[:idx]
	}
	return scope
}

// PermissionDiffEntry describes how a single requested permission compares to
// what the installation actually has.
type PermissionDiffEntry struct {
	Permission string `json:"permission"`
	Requested  string `json:"requested"`
	Granted    string `json:"granted,omitempty"` // empty if not granted at all
	Status     string `json:"status"`            // ok | insufficient | missing | unknown
}

// DiffPermissions compares requested permissions against what was granted on
// the installation. It returns one entry per requested permission, ordered by
// permission name. Status is:
//   - "ok": granted level meets or exceeds requested
//   - "insufficient": granted but at a lower level (e.g. read < write)
//   - "missing": permission not granted at all on the installation
//   - "unknown": granted permissions are not known (e.g. installation cache miss)
//
// If granted is nil (cache miss / never resolved), every entry is "unknown"
// rather than "missing", so the operator isn't misled.
func DiffPermissions(requested, granted map[string]string) []PermissionDiffEntry {
	if len(requested) == 0 {
		return nil
	}
	keys := make([]string, 0, len(requested))
	for k := range requested {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]PermissionDiffEntry, 0, len(keys))
	for _, k := range keys {
		req := requested[k]
		entry := PermissionDiffEntry{Permission: k, Requested: req}
		if granted == nil {
			entry.Status = "unknown"
			out = append(out, entry)
			continue
		}
		got, ok := granted[k]
		entry.Granted = got
		switch {
		case !ok:
			entry.Status = "missing"
		case policy.PermissionRank(got) >= policy.PermissionRank(req):
			entry.Status = "ok"
		default:
			entry.Status = "insufficient"
		}
		out = append(out, entry)
	}
	return out
}

// permissionDiffHint produces a one-line operator hint summarizing the diff.
func permissionDiffHint(diff []PermissionDiffEntry, granted map[string]string) string {
	if granted == nil {
		return "installation permissions not yet cached — retry after the next /orgs/{org}/installation lookup, or check the GitHub App's installation page directly"
	}
	var missing, insufficient []string
	for _, e := range diff {
		switch e.Status {
		case "missing":
			missing = append(missing, e.Permission)
		case "insufficient":
			insufficient = append(insufficient, fmt.Sprintf("%s (have %s, need %s)", e.Permission, e.Granted, e.Requested))
		}
	}
	if len(missing) == 0 && len(insufficient) == 0 {
		return "no permission mismatch detected — the 422 may be due to repositories restriction or a recently-added permission the org admin has not yet accepted"
	}
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(missing, ","))
	}
	if len(insufficient) > 0 {
		parts = append(parts, "insufficient: "+strings.Join(insufficient, "; "))
	}
	return "policy asks for permissions the installation lacks — " + strings.Join(parts, " | ") +
		". Update the GitHub App permissions and have the org admin accept the new grants, or reduce what the policy requests"
}
