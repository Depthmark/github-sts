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
	Load(ctx context.Context, request LoadRequest) (*TrustPolicy, error)
}

// LoadRequest carries the canonical target name used for GitHub fetches and
// immutable target IDs used for cache isolation.
type LoadRequest struct {
	Scope              string
	TargetOwnerID      string
	TargetRepositoryID string
	AppName            string
	Identity           string
}

// TokenProvider provides GitHub installation tokens for accessing policy
// files. The instance return value (which pool member served the call) is
// not needed for policy fetches today — the one caller, fetchFrom, discards
// it — but the signature has to match InstallationTokenProvider
// (internal/handler) so *github.AppPool satisfies both interfaces with one
// method.
type TokenProvider interface {
	GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, string, error)
}

type cacheEntry struct {
	policy    *TrustPolicy
	expiresAt time.Time
}

// maxPolicyResponseBytes limits the policy file response size (1 MB).
const maxPolicyResponseBytes = 1 << 20

// GitHubPolicyLoader loads trust policies from GitHub repositories.
// Each configured app has its own token provider, optional org policy repo,
// and optional resolution mode, so policy fetches use the correct app's
// credentials and resolution semantics. Concurrent loads for the same cache
// key are deduplicated via singleflight.
type GitHubPolicyLoader struct {
	tokenProviders map[string]TokenProvider // app name → provider
	orgPolicyRepos map[string]string        // app name → org_policy_repo
	policyModes    map[string]Resolution    // app name → resolution mode
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
// policyModes maps app names to their resolution mode (org_first, repo_first,
// org_only). Apps without an entry default to ResolutionOrgFirst when their
// org policy repo is set, or to repo-only behavior when it isn't.
// If httpClient is nil, a default client with 15s timeout is used.
func NewGitHubLoader(
	tokenProviders map[string]TokenProvider,
	orgPolicyRepos map[string]string,
	policyModes map[string]Resolution,
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
	if policyModes == nil {
		policyModes = make(map[string]Resolution)
	}
	// Emit a deprecation warning once per app for repo_first.
	for app, mode := range policyModes {
		if mode == ResolutionRepoFirst {
			slogger.Warn("policy_resolution=repo_first is deprecated and allows repo-local policies to override the centralized org policy",
				"app", app,
			)
		}
	}
	return &GitHubPolicyLoader{
		tokenProviders: tokenProviders,
		orgPolicyRepos: orgPolicyRepos,
		policyModes:    policyModes,
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
func (l *GitHubPolicyLoader) Load(ctx context.Context, request LoadRequest) (*TrustPolicy, error) {
	parts := strings.Split(request.Scope, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("policy load requires a repository scope")
	}
	if !validGitHubID(GitHubID(request.TargetOwnerID)) || !validGitHubID(GitHubID(request.TargetRepositoryID)) {
		return nil, fmt.Errorf("policy load requires immutable target owner and repository IDs")
	}
	cacheKey := request.cacheKey()

	// Check cache.
	l.mu.RLock()
	if entry, ok := l.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		l.mu.RUnlock()
		metrics.PolicyCacheHits.WithLabelValues(request.AppName).Inc()
		return entry.policy, nil
	}
	l.mu.RUnlock()

	metrics.PolicyCacheMisses.WithLabelValues(request.AppName).Inc()

	// Singleflight: deduplicate concurrent cache-miss fetches for the same key.
	v, err, _ := l.sf.Do(cacheKey, func() (any, error) {
		// Double-check cache after winning the singleflight race.
		l.mu.RLock()
		if entry, ok := l.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
			l.mu.RUnlock()
			return entry.policy, nil
		}
		l.mu.RUnlock()

		return l.fetchAndCache(ctx, cacheKey, request.Scope, request.AppName, request.Identity)
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

func (r LoadRequest) cacheKey() string {
	return fmt.Sprintf("github:repository:%s:%s:%s:%s", r.TargetOwnerID, r.TargetRepositoryID, r.AppName, r.Identity)
}

// fetchAndCache performs the actual policy fetch from GitHub and caches the result.
//
// Resolution order is controlled by the per-app policy_resolution mode:
//
//   - org_first (default): try the org policy repo first; on 404, fall back
//     to the requesting repo. On collision, the org policy wins.
//   - repo_first (legacy): try the requesting repo first; on 404, fall back
//     to the org policy repo. On collision, the repo policy wins. This allows
//     repo owners to override centralized policy and is retained only for
//     backwards compatibility.
//   - org_only: load only from the org policy repo. The requesting repo is
//     never consulted.
//
// When org_policy_repo is unset for the app, only the requesting repo is
// consulted regardless of mode.
//
// Policies resolved from the org repo are marked centralized so the
// response-token issuer can force per-request repo scoping.
func (l *GitHubPolicyLoader) fetchAndCache(ctx context.Context, cacheKey, scope, appName, identity string) (*TrustPolicy, error) {
	// Resolve the token provider for this app.
	tp, ok := l.tokenProviders[appName]
	if !ok {
		return nil, fmt.Errorf("no token provider configured for app %q", appName)
	}

	filePath := fmt.Sprintf("%s/%s/%s.sts.yaml", l.basePath, appName, identity)
	orgPolicyRepo := l.orgPolicyRepos[appName]

	var pol *TrustPolicy
	var err error
	centralized := false

	pol, centralized, err = l.fetchRepoLevel(ctx, tp, scope, orgPolicyRepo, filePath, appName, identity)
	if err != nil {
		return nil, err
	}

	if pol != nil {
		pol.SetCentralized(centralized)
	}

	// Cache result (including nil for not-found).
	l.mu.Lock()
	l.cache[cacheKey] = &cacheEntry{
		policy:    pol,
		expiresAt: time.Now().Add(l.cacheTTL),
	}
	l.mu.Unlock()

	return pol, nil
}

// fetchRepoLevel resolves a policy for repo-level scope ("org/repo") using
// the configured resolution mode for the app. Returns (policy, centralized,
// error). centralized is true when the policy was sourced from the org repo.
func (l *GitHubPolicyLoader) fetchRepoLevel(ctx context.Context, tp TokenProvider, scope, orgPolicyRepo, filePath, appName, identity string) (*TrustPolicy, bool, error) {
	mode := l.policyModes[appName]
	// When no org policy repo is configured the mode is moot — only the
	// requesting repo can be consulted.
	if orgPolicyRepo == "" {
		pol, err := l.fetchFrom(ctx, tp, scope, scope, filePath, appName, identity)
		return pol, false, err
	}

	// Default mode when org_policy_repo is set is org_first; config
	// validation should have populated it, but defend in depth here.
	if mode == "" {
		mode = ResolutionOrgFirst
	}

	org := strings.SplitN(scope, "/", 2)[0]
	orgRepo := org + "/" + orgPolicyRepo

	switch mode {
	case ResolutionOrgOnly:
		pol, err := l.fetchFrom(ctx, tp, scope, orgRepo, filePath, appName, identity)
		return pol, pol != nil, err

	case ResolutionRepoFirst:
		pol, err := l.fetchFrom(ctx, tp, scope, scope, filePath, appName, identity)
		if err != nil {
			return nil, false, err
		}
		if pol != nil {
			return pol, false, nil
		}
		pol, err = l.fetchFrom(ctx, tp, scope, orgRepo, filePath, appName, identity)
		if err != nil {
			return nil, false, err
		}
		return pol, pol != nil, nil

	case ResolutionOrgFirst:
		fallthrough
	default:
		pol, err := l.fetchFrom(ctx, tp, scope, orgRepo, filePath, appName, identity)
		if err != nil {
			return nil, false, err
		}
		if pol != nil {
			return pol, true, nil
		}
		pol, err = l.fetchFrom(ctx, tp, scope, scope, filePath, appName, identity)
		if err != nil {
			return nil, false, err
		}
		return pol, false, nil
	}
}

// fetchFrom obtains an installation token scoped to repo and fetches the
// policy file at filePath from that repo. Returns (nil, nil) if the policy
// file does not exist (404).
func (l *GitHubPolicyLoader) fetchFrom(ctx context.Context, tp TokenProvider, scope, repo, filePath, appName, identity string) (*TrustPolicy, error) {
	token, _, err := tp.GetInstallationToken(ctx, repo,
		map[string]string{"contents": "read"}, nil, "policy_loader")
	if err != nil {
		metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "token_error").Inc()
		l.slogger.Error("policy loader: failed to get installation token",
			"scope", scope,
			"app", appName,
			"identity", identity,
			"token_scope", repo,
			"repo", repo,
			"policy_file", filePath,
			"error", err,
		)
		return nil, fmt.Errorf("getting token for policy fetch from %s (policy: %s): %w", repo, filePath, err)
	}
	return l.fetchPolicyFile(ctx, token, repo, filePath, appName)
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

	// Record which repo actually served these bytes, and their git object
	// hash. Both are already in hand here, so provenance costs no extra
	// API call. Under org_first/repo_first resolution the serving repo is
	// not knowable from the request alone, which is precisely why it has
	// to be captured at the point of the fetch.
	policy.SetSource(repo, filePath, GitBlobSHA(body))

	metrics.PolicyLoadsTotal.WithLabelValues(appName, "github", "ok").Inc()
	l.slogger.Debug("policy loaded",
		"repo", repo, "path", filePath, "blob_sha", policy.Provenance().BlobSHA,
	)
	return policy, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
