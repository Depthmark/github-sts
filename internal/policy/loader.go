package policy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"golang.org/x/sync/singleflight"
)

// Loader loads trust policies for a given scope/app/identity combination.
type Loader interface {
	Load(ctx context.Context, scope, appName, identity string) (*TrustPolicy, error)
}

// TokenProvider provides GitHub installation tokens for accessing policy files.
type TokenProvider interface {
	GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, error)
}

type cacheEntry struct {
	policy    *TrustPolicy
	expiresAt time.Time
}

// maxPolicyResponseBytes limits the policy file response size (1 MB).
const maxPolicyResponseBytes = 1 << 20

// GitHubPolicyLoader loads trust policies from GitHub repositories.
// Each configured app has its own token provider and optional org policy repo,
// so policy fetches use the correct app's credentials. Concurrent loads for
// the same cache key are deduplicated via singleflight.
type GitHubPolicyLoader struct {
	tokenProviders map[string]TokenProvider // app name → provider
	orgPolicyRepos map[string]string        // app name → org_policy_repo
	apiURL         string
	basePath       string
	cacheTTL       time.Duration
	cache          map[string]*cacheEntry
	mu             sync.RWMutex
	httpClient     *http.Client
	slogger        *slog.Logger
	sf             singleflight.Group
}

// NewGitHubLoader creates a GitHubPolicyLoader.
// tokenProviders maps app names to their token providers.
// orgPolicyRepos maps app names to their org_policy_repo setting.
// If httpClient is nil, a default client with 15s timeout is used.
func NewGitHubLoader(
	tokenProviders map[string]TokenProvider,
	orgPolicyRepos map[string]string,
	apiURL, basePath string,
	cacheTTL time.Duration,
	slogger *slog.Logger,
	httpClient *http.Client,
) *GitHubPolicyLoader {
	if basePath == "" {
		basePath = ".github/sts"
	}
	if slogger == nil {
		slogger = slog.Default()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &GitHubPolicyLoader{
		tokenProviders: tokenProviders,
		orgPolicyRepos: orgPolicyRepos,
		apiURL:         apiURL,
		basePath:       basePath,
		cacheTTL:       cacheTTL,
		cache:          make(map[string]*cacheEntry),
		httpClient:     httpClient,
		slogger:        slogger,
	}
}

// Load fetches a trust policy for the given scope/app/identity. Results are
// cached for cacheTTL duration. Returns nil if the policy file is not found.
// Concurrent loads for the same key are deduplicated via singleflight.
func (l *GitHubPolicyLoader) Load(ctx context.Context, scope, appName, identity string) (*TrustPolicy, error) {
	cacheKey := fmt.Sprintf("github:%s:%s:%s", scope, appName, identity)

	// Check cache.
	l.mu.RLock()
	if entry, ok := l.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		l.mu.RUnlock()
		metrics.PolicyCacheHits.WithLabelValues(appName).Inc()
		return entry.policy, nil
	}
	l.mu.RUnlock()

	metrics.PolicyCacheMisses.WithLabelValues(appName).Inc()

	// Singleflight: deduplicate concurrent cache-miss fetches for the same key.
	v, err, _ := l.sf.Do(cacheKey, func() (any, error) {
		// Double-check cache after winning the singleflight race.
		l.mu.RLock()
		if entry, ok := l.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
			l.mu.RUnlock()
			return entry.policy, nil
		}
		l.mu.RUnlock()

		return l.fetchAndCache(ctx, cacheKey, scope, appName, identity)
	})
	if err != nil {
		return nil, err
	}
	// singleflight returns nil interface when the policy is nil (not found).
	if v == nil {
		return nil, nil
	}
	return v.(*TrustPolicy), nil
}

// fetchAndCache performs the actual policy fetch from GitHub and caches the result.
func (l *GitHubPolicyLoader) fetchAndCache(ctx context.Context, cacheKey, scope, appName, identity string) (*TrustPolicy, error) {
	// Resolve the token provider for this app.
	tp, ok := l.tokenProviders[appName]
	if !ok {
		return nil, fmt.Errorf("no token provider configured for app %q", appName)
	}

	// Determine repo and file path.
	filePath := fmt.Sprintf("%s/%s/%s.sts.yaml", l.basePath, appName, identity)

	var repo string
	var tokenScope string
	if strings.Contains(scope, "/") {
		// Repo-level: load from target repo.
		repo = scope
		tokenScope = scope
	} else {
		// Org-level: load from centralized org policy repo.
		orgPolicyRepo := l.orgPolicyRepos[appName]
		if orgPolicyRepo == "" {
			return nil, fmt.Errorf("org_policy_repo required for app %q with org-level scope %q", appName, scope)
		}
		repo = scope + "/" + orgPolicyRepo
		tokenScope = repo
	}

	// Get installation token with contents:read to fetch the policy file.
	token, err := tp.GetInstallationToken(ctx, tokenScope,
		map[string]string{"contents": "read"}, nil, "policy_loader")
	if err != nil {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "token_error").Inc()
		l.slogger.Error("policy loader: failed to get installation token",
			"scope", scope,
			"app", appName,
			"identity", identity,
			"token_scope", tokenScope,
			"repo", repo,
			"policy_file", filePath,
			"error", err,
		)
		return nil, fmt.Errorf("getting token for policy fetch from %s (policy: %s): %w", repo, filePath, err)
	}

	// Fetch policy file from GitHub.
	policy, err := l.fetchPolicyFile(ctx, token, repo, filePath, appName)
	if err != nil {
		return nil, err
	}

	// Cache result (including nil for not-found).
	l.mu.Lock()
	l.cache[cacheKey] = &cacheEntry{
		policy:    policy,
		expiresAt: time.Now().Add(l.cacheTTL),
	}
	l.mu.Unlock()

	return policy, nil
}

func (l *GitHubPolicyLoader) fetchPolicyFile(ctx context.Context, token, repo, filePath, appName string) (*TrustPolicy, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s", l.apiURL, repo, filePath)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building policy request for %s/%s: %w", repo, filePath, err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.raw+json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "http_error").Inc()
		l.slogger.Error("policy fetch failed",
			"repo", repo, "path", filePath, "error", err,
		)
		return nil, fmt.Errorf("fetching policy from %s/%s: %w", repo, filePath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "not_found").Inc()
		l.slogger.Warn("policy file not found",
			"repo", repo, "path", filePath, "url", url, "http_status", resp.StatusCode,
		)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "http_error").Inc()
		l.slogger.Error("policy fetch unexpected status",
			"repo", repo, "path", filePath, "url", url,
			"http_status", resp.StatusCode, "response_body", string(body),
		)
		return nil, fmt.Errorf("fetching policy from %s/%s: HTTP %d: %s", repo, filePath, resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponseBytes))
	if err != nil {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "read_error").Inc()
		l.slogger.Error("policy body read failed",
			"repo", repo, "path", filePath, "error", err,
		)
		return nil, fmt.Errorf("reading policy body from %s/%s: %w", repo, filePath, err)
	}

	policy, err := ParsePolicy(body)
	if err != nil {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "parse_error").Inc()
		l.slogger.Error("policy parse failed",
			"repo", repo, "path", filePath, "error", err, "body_preview", truncate(string(body), 200),
		)
		return nil, fmt.Errorf("parsing policy from %s/%s: %w", repo, filePath, err)
	}

	metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "ok").Inc()
	return policy, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
