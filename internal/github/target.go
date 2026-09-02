package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
)

const targetCacheTTL = 5 * time.Minute

var (
	ownerNamePattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repositoryNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

	// ErrOrganizationScopeUnsupported marks a syntactically valid organization
	// scope that is intentionally denied until immutable repository sets and
	// explicit organization-wide grants are implemented.
	ErrOrganizationScopeUnsupported = errors.New("organization-level scopes are not supported")
	ErrTargetScopeNotCanonical      = errors.New("target scope is not canonical")
)

// RepositoryScope is a syntactically validated repository target supplied by
// a caller. GitHub remains authoritative for its current canonical spelling.
type RepositoryScope struct {
	Owner      string
	Repository string
}

func (s RepositoryScope) String() string { return s.Owner + "/" + s.Repository }

// TargetIdentity is the canonical immutable identity of one target repository.
type TargetIdentity struct {
	Scope        string
	Owner        string
	OwnerID      string
	Repository   string
	RepositoryID string
}

// ExchangeApp is the subset of a GitHub App provider used by token exchange.
// The policy loader uses its separate TokenProvider interface.
//
// GetInstallationTokenForTarget returns the minted token with the expiry
// GitHub reported for it (see IssuedToken), plus which physical pool instance
// minted it (for audit/metrics attribution — see design doc §5.4.1), the same
// way TokenProvider.GetInstallationToken does. *AppTokenProvider (a pool of
// one) returns its own fixed instance; *AppPool applies the same
// round-robin/failover selection used for GetInstallationToken.
type ExchangeApp interface {
	ResolveTarget(context.Context, RepositoryScope) (TargetIdentity, error)
	GetInstallationTokenForTarget(ctx context.Context, target TargetIdentity, permissions PermissionRequest, caller string) (token MintedToken, instance string, err error)
}

// PermissionRequest carries both halves of a possibly-narrowed permission
// ask so a call site cannot confuse them. Keeping them together matters:
// Effective is what the token is actually minted with and is caller-
// controlled, while Ceiling is policy-derived and is the only one of the
// two safe to use as a metric label.
type PermissionRequest struct {
	// Ceiling is the trust policy's full permission set: the most this
	// identity may ever obtain.
	Ceiling map[string]string
	// Effective is the set sent to GitHub. Equal to Ceiling when the caller
	// did not narrow.
	Effective map[string]string
}

// UnnarrowedPermissions builds a PermissionRequest for a caller that did not
// ask for anything less than the policy allows.
func UnnarrowedPermissions(ceiling map[string]string) PermissionRequest {
	return PermissionRequest{Ceiling: ceiling, Effective: ceiling}
}

type cachedTarget struct {
	identity  TargetIdentity
	fetchedAt time.Time
}

// ParseRepositoryScope accepts exactly owner/repository. Organization scopes
// are recognized separately so callers can fail closed with a useful error.
func ParseRepositoryScope(raw string) (RepositoryScope, error) {
	parts := strings.Split(raw, "/")
	if len(parts) == 1 && validOwnerName(parts[0]) {
		return RepositoryScope{}, ErrOrganizationScopeUnsupported
	}
	if len(parts) != 2 || !validOwnerName(parts[0]) || !validRepositoryName(parts[1]) {
		return RepositoryScope{}, fmt.Errorf("scope must be a valid owner/repository")
	}
	return RepositoryScope{Owner: parts[0], Repository: parts[1]}, nil
}

func validOwnerName(name string) bool {
	return ownerNamePattern.MatchString(name) && !strings.Contains(name, "--")
}

func validRepositoryName(name string) bool {
	return repositoryNamePattern.MatchString(name) && name != "." && name != ".."
}

// ResolveTarget resolves a repository through this App and requires the caller
// to use GitHub's current canonical owner/repository spelling.
func (p *AppTokenProvider) ResolveTarget(ctx context.Context, scope RepositoryScope) (TargetIdentity, error) {
	key := strings.ToLower(scope.String())
	p.mu.RLock()
	if entry, ok := p.targetCache[key]; ok && time.Since(entry.fetchedAt) < targetCacheTTL {
		p.mu.RUnlock()
		if scope.String() != entry.identity.Scope {
			return TargetIdentity{}, fmt.Errorf("%w: %q", ErrTargetScopeNotCanonical, scope.String())
		}
		return entry.identity, nil
	}
	p.mu.RUnlock()

	v, err, _ := p.targetSF.Do(key, func() (any, error) {
		p.mu.RLock()
		if entry, ok := p.targetCache[key]; ok && time.Since(entry.fetchedAt) < targetCacheTTL {
			p.mu.RUnlock()
			return entry.identity, nil
		}
		p.mu.RUnlock()
		return p.fetchTarget(ctx, scope)
	})
	if err != nil {
		return TargetIdentity{}, err
	}
	identity := v.(TargetIdentity)
	if scope.String() != identity.Scope {
		return TargetIdentity{}, fmt.Errorf("%w: %q", ErrTargetScopeNotCanonical, scope.String())
	}
	return identity, nil
}

func (p *AppTokenProvider) fetchTarget(ctx context.Context, scope RepositoryScope) (TargetIdentity, error) {
	token, err := p.GetInstallationToken(ctx, scope.String(), map[string]string{"metadata": "read"}, []string{scope.Repository}, "target_resolver")
	if err != nil {
		return TargetIdentity{}, fmt.Errorf("creating target-resolution token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s", p.apiURL, url.PathEscape(scope.Owner), url.PathEscape(scope.Repository))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return TargetIdentity{}, fmt.Errorf("building target-resolution request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "resolve_target", "error").Inc()
		return TargetIdentity{}, &TokenMintError{Retryable: true, Err: fmt.Errorf("resolving target %q: %w", scope.String(), err)}
	}
	defer func() { _ = resp.Body.Close() }()
	ExtractRateLimitHeaders(resp, p.appName, p.instance, "target_resolver")

	if resp.StatusCode != http.StatusOK {
		metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "resolve_target", "error").Inc()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return TargetIdentity{}, &TokenMintError{
			StatusCode: resp.StatusCode,
			Retryable:  isRetryableTokenMintStatus(resp),
			Err: fmt.Errorf("resolving target %q: GitHub API returned HTTP %d: %s",
				scope.String(), resp.StatusCode, string(body)),
		}
	}

	var repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Owner    struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		} `json:"owner"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repository); err != nil {
		return TargetIdentity{}, fmt.Errorf("decoding target %q: %w", scope.String(), err)
	}
	if repository.ID <= 0 || repository.Owner.ID <= 0 || !validOwnerName(repository.Owner.Login) || !validRepositoryName(repository.Name) {
		return TargetIdentity{}, fmt.Errorf("target %q returned an invalid immutable identity", scope.String())
	}
	canonicalScope := repository.Owner.Login + "/" + repository.Name
	if repository.FullName != "" && !strings.EqualFold(repository.FullName, canonicalScope) {
		return TargetIdentity{}, fmt.Errorf("target %q returned inconsistent canonical names", scope.String())
	}
	identity := TargetIdentity{
		Scope:        canonicalScope,
		Owner:        repository.Owner.Login,
		OwnerID:      strconv.FormatInt(repository.Owner.ID, 10),
		Repository:   repository.Name,
		RepositoryID: strconv.FormatInt(repository.ID, 10),
	}
	if scope.String() != identity.Scope {
		return TargetIdentity{}, fmt.Errorf("%w: %q", ErrTargetScopeNotCanonical, scope.String())
	}

	metrics.GitHubAPICalls.WithLabelValues(p.appName, p.instance, "resolve_target", "ok").Inc()
	p.mu.Lock()
	p.targetCache[strings.ToLower(identity.Scope)] = &cachedTarget{identity: identity, fetchedAt: time.Now()}
	p.mu.Unlock()
	return identity, nil
}

// GetInstallationTokenForTarget mints a token restricted to the immutable
// repository ID that was authorized by both the trust policy and Rego.
// Returns this credential's own instance label (see ExchangeApp) — a pool
// of one, same as GetInstallationToken.
func (p *AppTokenProvider) GetInstallationTokenForTarget(ctx context.Context, target TargetIdentity, permissions PermissionRequest, caller string) (MintedToken, string, error) {
	repositoryID, err := strconv.ParseInt(target.RepositoryID, 10, 64)
	if err != nil || repositoryID <= 0 || target.Scope == "" {
		return MintedToken{}, "", fmt.Errorf("invalid target repository identity")
	}
	minted, err := p.getInstallationToken(ctx, target.Scope, permissions.Effective, nil, []int64{repositoryID}, permissions.Ceiling, caller)
	if err != nil {
		return MintedToken{}, "", err
	}
	return minted, p.instance, nil
}
