// Package policy provides trust policy models and evaluation logic for
// github-sts token exchange. Policies define which OIDC identities can
// obtain GitHub tokens with which permissions.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/depthmark/github-sts/internal/yamlstrict"
	"gopkg.in/yaml.v3"
)

const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// ValidationError identifies a trust-policy definition that is syntactically
// or structurally invalid. Callers should distinguish it from upstream fetch
// failures and from a valid policy that denies a request.
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func validationErrorf(format string, args ...any) error {
	return &ValidationError{Err: fmt.Errorf(format, args...)}
}

// GitHubID is an immutable GitHub numeric identifier encoded as a YAML/JSON
// string. Quoted strings prevent precision loss in tooling that handles IDs as
// JSON numbers.
type GitHubID string

// UnmarshalYAML rejects numeric YAML scalars so IDs must remain strings across
// policy tooling and Rego input.
func (id *GitHubID) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("GitHub ID must be a quoted string")
	}
	*id = GitHubID(node.Value)
	return nil
}

// GitHubRepository identifies one repository by immutable IDs.
type GitHubRepository struct {
	OwnerID      GitHubID `yaml:"owner_id" json:"owner_id"`
	RepositoryID GitHubID `yaml:"repository_id" json:"repository_id"`
}

// GitHubPolicy binds approved source repositories to one exact target
// repository. Organization-level targets remain unsupported and fail closed.
type GitHubPolicy struct {
	Sources []GitHubRepository `yaml:"sources" json:"sources"`
	Target  GitHubRepository   `yaml:"target" json:"target"`
}

// TrustPolicy defines the conditions under which a GitHub installation
// token may be issued to an OIDC identity.
type TrustPolicy struct {
	Issuer         string            `yaml:"issuer"`
	Subject        string            `yaml:"subject,omitempty"`
	SubjectPattern string            `yaml:"subject_pattern,omitempty"`
	ClaimPattern   map[string]string `yaml:"claim_pattern,omitempty"`
	Audience       string            `yaml:"audience,omitempty"`
	Repositories   []string          `yaml:"repositories,omitempty"`
	Permissions    map[string]string `yaml:"permissions"`
	GitHub         *GitHubPolicy     `yaml:"github,omitempty"`

	// centralized is true when the policy was loaded from the org policy repo
	// rather than the requesting repo. Set by the loader, never serialized.
	centralized bool
}

// Centralized reports whether this policy was resolved from the centralized
// org policy repo. The token issuer must force per-request repo scoping in
// that case so a centralized identity cannot mint a cross-repo token.
func (p *TrustPolicy) Centralized() bool { return p.centralized }

// SetCentralized marks the policy as having been loaded from the org policy
// repo. Intended for use by the loader.
func (p *TrustPolicy) SetCentralized(v bool) { p.centralized = v }

// Resolution selects how the loader resolves an identity policy when both a
// requesting repo and an org policy repo could host it.
type Resolution string

const (
	// ResolutionOrgFirst tries the org policy repo first; falls back to the
	// requesting repo if the org has no file for that identity. On collision,
	// the org wins. This is the default and the secure choice for any
	// deployment that uses a central policy repo as a source of truth.
	ResolutionOrgFirst Resolution = "org_first"

	// ResolutionRepoFirst tries the requesting repo first; falls back to the
	// org policy repo. On collision, the repo wins. This is the legacy
	// behavior; it allows a repo owner to override the centralized policy and
	// is retained for backwards compatibility only.
	ResolutionRepoFirst Resolution = "repo_first"

	// ResolutionOrgOnly loads only from the org policy repo. The requesting
	// repo is never consulted. Use this when self-service policies must be
	// forbidden entirely.
	ResolutionOrgOnly Resolution = "org_only"
)

// ValidResolution reports whether m is a known resolution mode.
func ValidResolution(m Resolution) bool {
	switch m {
	case ResolutionOrgFirst, ResolutionRepoFirst, ResolutionOrgOnly:
		return true
	}
	return false
}

// ParsePolicy parses a YAML trust policy from raw bytes.
func ParsePolicy(data []byte) (*TrustPolicy, error) {
	var p TrustPolicy
	if err := yamlstrict.Decode(data, &p); err != nil {
		return nil, validationErrorf("parsing trust policy YAML: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// EvalResult contains the outcome of a policy evaluation.
type EvalResult struct {
	Allowed bool
	// Reason describes why the policy denied the request (empty on success).
	Reason string
}

// Evaluate checks whether the given OIDC claims satisfy this policy.
// Evaluation order: issuer → subject → subject_pattern → claim_pattern.
func (p *TrustPolicy) Evaluate(claims map[string]any) EvalResult {
	// 1. Issuer — exact match (always required).
	iss, _ := claims["iss"].(string)
	if iss != p.Issuer {
		return EvalResult{Reason: fmt.Sprintf("issuer mismatch: got %q, policy requires %q", iss, p.Issuer)}
	}
	if p.Subject == "" && p.SubjectPattern == "" && len(p.ClaimPattern) == 0 {
		return EvalResult{Reason: "trust policy has no workload identity selector"}
	}
	if p.Subject != "" && p.SubjectPattern != "" {
		return EvalResult{Reason: "trust policy has conflicting subject selectors"}
	}

	// 2. Subject — exact match (if set).
	sub, subOK := claims["sub"].(string)
	if p.Subject != "" {
		if !subOK {
			return EvalResult{Reason: "subject claim is missing or is not a string"}
		}
		if sub != p.Subject {
			return EvalResult{Reason: fmt.Sprintf("subject mismatch: got %q, policy requires %q", sub, p.Subject)}
		}
	} else if p.SubjectPattern != "" {
		if !subOK {
			return EvalResult{Reason: "subject claim is missing or is not a string"}
		}
		// 3. Subject pattern — regex full match.
		re, err := compileFullMatch(p.SubjectPattern)
		if err != nil {
			return EvalResult{Reason: fmt.Sprintf("subject_pattern compile error: pattern %q, error: %v", p.SubjectPattern, err)}
		}
		if !re.MatchString(sub) {
			return EvalResult{Reason: fmt.Sprintf("subject_pattern mismatch: got %q, policy requires pattern %q", sub, p.SubjectPattern)}
		}
	}

	// 4. Claim pattern — all patterns must full match.
	for claimName, pattern := range p.ClaimPattern {
		value, ok := claims[claimName].(string)
		if !ok {
			return EvalResult{Reason: fmt.Sprintf("claim_pattern mismatch: claim %q is missing or is not a string", claimName)}
		}
		re, err := compileFullMatch(pattern)
		if err != nil {
			return EvalResult{Reason: fmt.Sprintf("claim_pattern compile error: claim %q, pattern %q, error: %v", claimName, pattern, err)}
		}
		if !re.MatchString(value) {
			return EvalResult{Reason: fmt.Sprintf("claim_pattern mismatch: claim %q got %q, policy requires pattern %q", claimName, value, pattern)}
		}
	}

	return EvalResult{Allowed: true}
}

// EvaluateGitHubRelationship checks the exact immutable source-to-target
// relationship in a validated GitHub.com trust policy.
func (p *TrustPolicy) EvaluateGitHubRelationship(source, target GitHubRepository) EvalResult {
	if p.Issuer != githubActionsIssuer || p.GitHub == nil {
		return EvalResult{Reason: "trust policy does not define a GitHub relationship"}
	}

	sourceAllowed := false
	for _, allowed := range p.GitHub.Sources {
		if allowed == source {
			sourceAllowed = true
			break
		}
	}
	if !sourceAllowed {
		return EvalResult{Reason: "source repository IDs are not authorized by the trust policy"}
	}
	if p.GitHub.Target != target {
		return EvalResult{Reason: "target repository IDs do not match the trust policy"}
	}

	return EvalResult{Allowed: true}
}

// Validate checks that the policy's fields are well-formed.
func (p *TrustPolicy) Validate() error {
	if p.Issuer == "" {
		return validationErrorf("trust policy: issuer is required")
	}
	// Audience is mandatory: a policy without it would accept tokens minted
	// for any other relying party that shares the issuer (cross-RP token
	// reuse — see security.md B-2).
	if p.Audience == "" {
		return validationErrorf("trust policy: audience is required (a policy without audience accepts tokens minted for any other relying party sharing the issuer)")
	}
	if p.Subject == "" && p.SubjectPattern == "" && len(p.ClaimPattern) == 0 {
		return validationErrorf("trust policy: at least one workload identity selector is required")
	}
	if p.Subject != "" && p.SubjectPattern != "" {
		return validationErrorf("trust policy: subject and subject_pattern are mutually exclusive")
	}
	if len(p.Permissions) == 0 {
		return validationErrorf("trust policy: at least one permission is required")
	}
	if len(p.Repositories) > 0 {
		return validationErrorf("trust policy: repositories is unsupported while organization-level scopes are disabled")
	}

	for perm, level := range p.Permissions {
		if !ValidPermissions[perm] {
			return validationErrorf("trust policy: invalid permission %q", perm)
		}
		if !ValidPermissionValues[level] {
			return validationErrorf("trust policy: invalid permission level %q for %q", level, perm)
		}
	}

	if p.Issuer == githubActionsIssuer {
		if err := p.validateGitHub(); err != nil {
			return err
		}
	} else if p.GitHub != nil {
		return validationErrorf("trust policy: github is only valid for issuer %q", githubActionsIssuer)
	}

	if p.SubjectPattern != "" {
		if _, err := compileFullMatch(p.SubjectPattern); err != nil {
			return validationErrorf("trust policy: invalid subject_pattern: %w", err)
		}
	}

	for name, pattern := range p.ClaimPattern {
		if strings.TrimSpace(name) == "" {
			return validationErrorf("trust policy: claim_pattern contains an empty claim name")
		}
		if pattern == "" {
			return validationErrorf("trust policy: claim_pattern for %q is empty", name)
		}
		if _, err := compileFullMatch(pattern); err != nil {
			return validationErrorf("trust policy: invalid claim_pattern for %q: %w", name, err)
		}
	}

	return nil
}

func (p *TrustPolicy) validateGitHub() error {
	if p.GitHub == nil {
		return validationErrorf("trust policy: github is required for issuer %q", githubActionsIssuer)
	}
	if len(p.GitHub.Sources) == 0 {
		return validationErrorf("trust policy: github.sources must contain at least one source")
	}

	seen := make(map[GitHubRepository]struct{}, len(p.GitHub.Sources))
	for i, source := range p.GitHub.Sources {
		if err := validateGitHubRepository(source); err != nil {
			return validationErrorf("trust policy: github.sources[%d]: %v", i, err)
		}
		if _, ok := seen[source]; ok {
			return validationErrorf("trust policy: github.sources[%d] duplicates an earlier source", i)
		}
		seen[source] = struct{}{}
	}
	if err := validateGitHubRepository(p.GitHub.Target); err != nil {
		return validationErrorf("trust policy: github.target: %v", err)
	}
	return nil
}

func validateGitHubRepository(repository GitHubRepository) error {
	if !validGitHubID(repository.OwnerID) {
		return fmt.Errorf("owner_id must be a non-zero decimal string")
	}
	if !validGitHubID(repository.RepositoryID) {
		return fmt.Errorf("repository_id must be a non-zero decimal string")
	}
	return nil
}

func validGitHubID(id GitHubID) bool {
	nonZero := false
	for _, c := range string(id) {
		if c < '0' || c > '9' {
			return false
		}
		if c != '0' {
			nonZero = true
		}
	}
	return id != "" && nonZero
}

func compileFullMatch(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("^(?:" + pattern + ")$")
}

// ValidPermissions is the set of valid GitHub App installation token
// permission names, matching the GitHub REST API documentation for
// creating installation access tokens.
// See: https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
var ValidPermissions = map[string]bool{
	// Repository permissions
	"actions":                      true,
	"administration":               true,
	"artifact_metadata":            true,
	"attestations":                 true,
	"checks":                       true,
	"codespaces":                   true,
	"contents":                     true,
	"dependabot_secrets":           true,
	"deployments":                  true,
	"discussions":                  true,
	"environments":                 true,
	"issues":                       true,
	"merge_queues":                 true,
	"metadata":                     true,
	"packages":                     true,
	"pages":                        true,
	"pull_requests":                true,
	"repository_custom_properties": true,
	"repository_hooks":             true,
	"repository_projects":          true,
	"secret_scanning_alerts":       true,
	"secrets":                      true,
	"security_events":              true,
	"single_file":                  true,
	"statuses":                     true,
	"vulnerability_alerts":         true,
	"workflows":                    true,

	// Organization permissions
	"custom_properties_for_organizations":         true,
	"members":                                     true,
	"organization_administration":                 true,
	"organization_announcement_banners":           true,
	"organization_copilot_agent_settings":         true,
	"organization_copilot_seat_management":        true,
	"organization_custom_org_roles":               true,
	"organization_custom_properties":              true,
	"organization_custom_roles":                   true,
	"organization_events":                         true,
	"organization_hooks":                          true,
	"organization_packages":                       true,
	"organization_personal_access_token_requests": true,
	"organization_personal_access_tokens":         true,
	"organization_plan":                           true,
	"organization_projects":                       true,
	"organization_secrets":                        true,
	"organization_self_hosted_runners":            true,
	"organization_user_blocking":                  true,

	// User permissions
	"email_addresses":    true,
	"followers":          true,
	"git_ssh_keys":       true,
	"gpg_keys":           true,
	"interaction_limits": true,
	"profile":            true,
	"starring":           true,

	// Enterprise permissions
	"enterprise_custom_properties_for_organizations": true,
}

// ValidPermissionValues is the set of valid permission levels.
var ValidPermissionValues = map[string]bool{
	"read":  true,
	"write": true,
	"admin": true,
}
