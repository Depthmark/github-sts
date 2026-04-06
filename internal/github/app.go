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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
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
	id        int64
	fetchedAt time.Time
}

type cachedJWT struct {
	token     string
	expiresAt time.Time
}

// AppTokenProvider creates permission-scoped GitHub installation tokens
// for the server-side exchange flow.
type AppTokenProvider struct {
	appName           string
	appID             int64
	privateKey        *rsa.PrivateKey
	apiURL            string
	httpClient        *http.Client
	installationCache map[string]*cachedInstallation // org → entry
	mu                sync.RWMutex
	jwtCache          cachedJWT
	jwtMu             sync.Mutex
	installSF         singleflight.Group
}

// NewAppTokenProvider creates a server-side AppTokenProvider.
func NewAppTokenProvider(appName string, appID int64, privateKey *rsa.PrivateKey, apiURL string, httpClient *http.Client) *AppTokenProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &AppTokenProvider{
		appName:           appName,
		appID:             appID,
		privateKey:        privateKey,
		apiURL:            apiURL,
		httpClient:        httpClient,
		installationCache: make(map[string]*cachedInstallation),
	}
}

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

// fetchInstallationID performs the actual GitHub API call to resolve the
// installation ID for the given org, and caches the result.
func (p *AppTokenProvider) fetchInstallationID(ctx context.Context, org string) (int64, error) {
	appJWT, err := p.GenerateAppJWT()
	if err != nil {
		return 0, fmt.Errorf("generating app JWT: %w", err)
	}

	url := fmt.Sprintf("%s/orgs/%s/installation", p.apiURL, org)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "get_installation", "error").Inc()
		return 0, fmt.Errorf("resolving installation for org %q: %w", org, err)
	}
	defer func() { _ = resp.Body.Close() }()

	ExtractRateLimitHeaders(resp, p.appName, "get_installation")

	if resp.StatusCode == http.StatusNotFound {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "get_installation", "not_found").Inc()
		return 0, fmt.Errorf("github app %q (app_id: %d) is not installed on organization %q — "+
			"install it at https://github.com/organizations/%s/settings/installations",
			p.appName, p.appID, org, org)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "get_installation", "auth_error").Inc()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("github app %q (app_id: %d) authentication failed for org %q (HTTP %d) — "+
			"verify the app_id and private_key are correct: %s",
			p.appName, p.appID, org, resp.StatusCode, string(body))
	}
	if resp.StatusCode != http.StatusOK {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "get_installation", "error").Inc()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("resolving installation for org %q via app %q: GitHub API returned HTTP %d: %s",
			org, p.appName, resp.StatusCode, string(body))
	}

	var install struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&install); err != nil {
		return 0, err
	}

	metrics.GitHubAPICalls.WithLabelValues(p.appName, "get_installation", "ok").Inc()

	// Cache the result with timestamp.
	p.mu.Lock()
	p.installationCache[org] = &cachedInstallation{
		id:        install.ID,
		fetchedAt: time.Now(),
	}
	p.mu.Unlock()

	return install.ID, nil
}

// GetInstallationToken creates a permission-scoped GitHub installation token.
func (p *AppTokenProvider) GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, error) {
	installationID, err := p.GetInstallationID(ctx, scope)
	if err != nil {
		return "", err
	}

	appJWT, err := p.GenerateAppJWT()
	if err != nil {
		return "", fmt.Errorf("generating app JWT: %w", err)
	}

	// Build request body with permissions and optional repository restriction.
	body := make(map[string]any)
	if permissions != nil {
		body["permissions"] = permissions
	}
	if repositories != nil {
		body["repositories"] = repositories
	} else if strings.Contains(scope, "/") {
		// Repo-level scope: restrict to the target repository.
		parts := strings.SplitN(scope, "/", 2)
		body["repositories"] = []string{parts[1]}
	}

	var reqBody bytes.Buffer
	if err := json.NewEncoder(&reqBody).Encode(body); err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &reqBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "create_token", "error").Inc()
		return "", fmt.Errorf("creating installation token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	ExtractRateLimitHeaders(resp, p.appName, caller)

	if resp.StatusCode == http.StatusUnprocessableEntity {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "create_token", "error").Inc()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("github refused to create token for app %q scope %q — "+
			"the requested permissions or repositories may exceed what the app is allowed (HTTP 422): %s",
			p.appName, scope, string(respBody))
	}
	if resp.StatusCode != http.StatusCreated {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, "create_token", "error").Inc()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("creating installation token for app %q scope %q: GitHub API returned HTTP %d: %s",
			p.appName, scope, resp.StatusCode, string(respBody))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Emit metrics — NEVER log the token value (BR-2A-17).
	permStr := formatPermissions(permissions)
	metrics.GitHubTokenIssued.WithLabelValues(p.appName, scope, permStr).Inc()
	metrics.GitHubAPICalls.WithLabelValues(p.appName, "create_token", "ok").Inc()
	slog.Info("installation token issued", "app", p.appName, "scope", scope, "permissions", permStr, "caller", caller)

	return result.Token, nil
}

// ExtractRateLimitHeaders reads GitHub rate limit headers from an HTTP
// response and updates Prometheus gauges. Also detects rate limit exceeded
// conditions on 403 responses.
func ExtractRateLimitHeaders(resp *http.Response, appName, caller string) {
	resource := resp.Header.Get("X-RateLimit-Resource")
	if resource == "" {
		resource = "core"
	}

	if v := resp.Header.Get("X-RateLimit-Limit"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitLimit.WithLabelValues(appName, resource).Set(n)
		}
	}

	var remaining, limit float64
	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			remaining = n
			metrics.GitHubRateLimitRemaining.WithLabelValues(appName, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Used"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitUsed.WithLabelValues(appName, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			metrics.GitHubRateLimitResetTimestamp.WithLabelValues(appName, resource).Set(n)
		}
	}

	if v := resp.Header.Get("X-RateLimit-Limit"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			limit = n
		}
	}

	if limit > 0 {
		pct := (remaining / limit) * 100
		metrics.GitHubRateLimitRemainingPercent.WithLabelValues(appName, resource).Set(pct)
	}

	// Detect rate limit exceeded on 403.
	if resp.StatusCode == http.StatusForbidden {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			// Secondary/abuse rate limit.
			metrics.GitHubSecondaryRateLimitTotal.WithLabelValues(appName, caller).Inc()
			if n, err := strconv.ParseFloat(retryAfter, 64); err == nil {
				metrics.GitHubSecondaryRateLimitRetryAfter.WithLabelValues(appName).Set(n)
			}
			slog.Warn("secondary rate limit hit", "app", appName, "retry_after", retryAfter, "caller", caller)
		} else if remaining == 0 {
			// Primary rate limit exceeded.
			metrics.GitHubRateLimitExceededTotal.WithLabelValues(appName, resource, caller).Inc()
			slog.Warn("primary rate limit exceeded", "app", appName, "resource", resource, "caller", caller)
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

func formatPermissions(perms map[string]string) string {
	if len(perms) == 0 {
		return "all"
	}
	parts := make([]string, 0, len(perms))
	for k, v := range perms {
		parts = append(parts, k+":"+v)
	}
	return strings.Join(parts, ",")
}
