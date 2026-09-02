// Package policy provides trust policy models and evaluation logic for
// github-sts token exchange. Policies define which OIDC identities can
// obtain GitHub tokens with which permissions.
package policy

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

	// provenance records where this policy came from and which exact bytes
	// were parsed. Set by the loader, never serialized into the policy
	// file itself.
	provenance Provenance
}

// Provenance identifies the exact trust policy that governed one exchange.
//
// The org Rego bundle has carried a digest in the audit trail since it was
// introduced, on the reasoning that a decision record is only as good as its
// ability to name what produced it. The YAML policy is the other half of the
// same decision, and the half that names the permissions, so it needs the
// same treatment.
//
// BlobSHA is git's own object hash of the bytes that were parsed, which
// makes the record verifiable offline by anyone with a clone:
//
//	git hash-object .github/sts/default/ci.sts.yaml   # matches BlobSHA
//	git log --find-object=<BlobSHA>                   # the commits behind it
//
// It is content-addressed rather than history-addressed on purpose: it
// survives force-pushes and rebases, and two commits carrying identical
// policy bytes are genuinely the same policy for audit purposes.
type Provenance struct {
	// Repository is the owner/repo that actually served the file, which
	// under org_first or repo_first resolution is not knowable from the
	// request alone.
	Repository string
	// Path is the file path within Repository.
	Path string
	// BlobSHA is the git blob SHA-1 of the parsed bytes. Empty when the
	// policy did not come from a fetch (tests, in-memory loaders).
	BlobSHA string
	// Centralized reports resolution from the org policy repo rather than
	// the requesting repo. The distinction has authorization consequences
	// under ResolutionRepoFirst, where a repo owner can override the
	// centralized policy.
	Centralized bool
}

// Source returns "centralized" or "repository": which side won resolution.
// A bounded value, safe to filter and group on in a log aggregator.
func (p Provenance) Source() string {
	if p.Centralized {
		return "centralized"
	}
	return "repository"
}

// Provenance returns where this policy was loaded from.
func (p *TrustPolicy) Provenance() Provenance { return p.provenance }

// SetSource records the repository, path, and content hash a policy was
// fetched from. Intended for use by the loader.
func (p *TrustPolicy) SetSource(repository, path, blobSHA string) {
	p.provenance.Repository = repository
	p.provenance.Path = path
	p.provenance.BlobSHA = blobSHA
}

// Centralized reports whether this policy was resolved from the centralized
// org policy repo. The token issuer must force per-request repo scoping in
// that case so a centralized identity cannot mint a cross-repo token.
func (p *TrustPolicy) Centralized() bool { return p.provenance.Centralized }

// SetCentralized marks the policy as having been loaded from the org policy
// repo. Intended for use by the loader.
func (p *TrustPolicy) SetCentralized(v bool) { p.provenance.Centralized = v }

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
		if !ValidPermission(perm) {
			return validationErrorf("trust policy: invalid permission %q", perm)
		}
		if !PermissionLevelAllowed(perm, level) {
			return validationErrorf("trust policy: invalid permission level %q for %q (GitHub accepts %s)",
				level, perm, strings.Join(ValidPermissionLevels[perm], ", "))
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

// Permission levels GitHub accepts, grouped by which permissions accept them.
// These are shared slices, so callers must not mutate what they receive.
var (
	levelsReadWrite      = []string{"read", "write"}
	levelsReadWriteAdmin = []string{"read", "write", "admin"}
	levelsRead           = []string{"read"}
	levelsWrite          = []string{"write"}
)

// ValidPermissionLevels maps each GitHub App installation token permission to
// the levels GitHub accepts for it. The levels are not uniform: of the 55
// permissions, 47 take read or write, four also take admin, two are read-only,
// and two are write-only.
//
// Source of truth is GitHub's own OpenAPI description, at
// components.schemas.app-permissions in
// github/rest-api-description. That is the same schema the mint endpoint
// declares for its request body, so a level rejected here is a level GitHub
// would reject with a 422:
//
//	paths["/app/installations/{installation_id}/access_tokens"].post
//	  .requestBody.content["application/json"].schema.permissions
//	  -> $ref: "#/components/schemas/app-permissions"
//
// Validating the pair here rather than the name and level independently is
// what moves "contents: admin" from a mint-time 422 to a policy-load error.
// Run `make check-github-permissions` to diff this table against upstream.
var ValidPermissionLevels = map[string][]string{
	// read or write
	"actions":                              levelsReadWrite,
	"administration":                       levelsReadWrite,
	"artifact_metadata":                    levelsReadWrite,
	"attestations":                         levelsReadWrite,
	"checks":                               levelsReadWrite,
	"code_quality":                         levelsReadWrite,
	"codespaces":                           levelsReadWrite,
	"contents":                             levelsReadWrite,
	"custom_properties_for_organizations":  levelsReadWrite,
	"dependabot_secrets":                   levelsReadWrite,
	"deployments":                          levelsReadWrite,
	"discussions":                          levelsReadWrite,
	"email_addresses":                      levelsReadWrite,
	"environments":                         levelsReadWrite,
	"followers":                            levelsReadWrite,
	"git_ssh_keys":                         levelsReadWrite,
	"gpg_keys":                             levelsReadWrite,
	"interaction_limits":                   levelsReadWrite,
	"issues":                               levelsReadWrite,
	"members":                              levelsReadWrite,
	"merge_queues":                         levelsReadWrite,
	"metadata":                             levelsReadWrite,
	"organization_administration":          levelsReadWrite,
	"organization_announcement_banners":    levelsReadWrite,
	"organization_copilot_agent_settings":  levelsReadWrite,
	"organization_copilot_seat_management": levelsReadWrite,
	"organization_custom_org_roles":        levelsReadWrite,
	"organization_custom_roles":            levelsReadWrite,
	"organization_hooks":                   levelsReadWrite,
	"organization_packages":                levelsReadWrite,
	"organization_personal_access_token_requests": levelsReadWrite,
	"organization_personal_access_tokens":         levelsReadWrite,
	"organization_secrets":                        levelsReadWrite,
	"organization_self_hosted_runners":            levelsReadWrite,
	"organization_user_blocking":                  levelsReadWrite,
	"packages":                                    levelsReadWrite,
	"pages":                                       levelsReadWrite,
	"pull_requests":                               levelsReadWrite,
	"repository_custom_properties":                levelsReadWrite,
	"repository_hooks":                            levelsReadWrite,
	"secret_scanning_alerts":                      levelsReadWrite,
	"secrets":                                     levelsReadWrite,
	"security_events":                             levelsReadWrite,
	"single_file":                                 levelsReadWrite,
	"starring":                                    levelsReadWrite,
	"statuses":                                    levelsReadWrite,
	"vulnerability_alerts":                        levelsReadWrite,

	// read, write, or admin
	"enterprise_custom_properties_for_organizations": levelsReadWriteAdmin,
	"organization_custom_properties":                 levelsReadWriteAdmin,
	"organization_projects":                          levelsReadWriteAdmin,
	"repository_projects":                            levelsReadWriteAdmin,

	// read only
	"organization_events": levelsRead,
	"organization_plan":   levelsRead,

	// write only
	"profile":   levelsWrite,
	"workflows": levelsWrite}

// PermissionLevelAllowed reports whether level is a level GitHub accepts for
// permission. An unknown permission name is never allowed.
func PermissionLevelAllowed(permission, level string) bool {
	for _, allowed := range ValidPermissionLevels[permission] {
		if allowed == level {
			return true
		}
	}
	return false
}

// ValidPermission reports whether permission is a GitHub App installation
// token permission name.
func ValidPermission(permission string) bool {
	_, ok := ValidPermissionLevels[permission]
	return ok
}

// permissionRank orders GitHub App permission levels from least to most
// privileged. "none" is not a level a trust policy may declare; it is the
// rank of an absent permission, which makes ceiling comparisons total.
var permissionRank = map[string]int{
	"none":  0,
	"read":  1,
	"write": 2,
	"admin": 3,
}

// PermissionRank returns the privilege ordering of a GitHub App permission
// level. An unrecognized level ranks 0 ("none") so a malformed value can
// never compare as more privileged than a known one.
func PermissionRank(level string) int { return permissionRank[level] }

// NarrowPermissions resolves the effective permission set for one exchange.
//
// ceiling is the trust policy's permission map: the most this identity may
// ever obtain. requested is the caller's optional narrowing ask. A nil
// requested means "everything the policy allows" and returns a copy of the
// ceiling, which is the behavior every caller had before narrowing existed.
//
// Narrowing may only ever reduce privilege. Asking for a permission the
// policy does not grant, or for a level above what it grants, is an
// escalation attempt and returns a *ValidationError. An explicitly empty
// (non-nil) request is also rejected rather than silently treated as "all":
// a caller that builds the map programmatically and ends up with zero
// entries must fail loudly, not receive a full-privilege token.
func NarrowPermissions(ceiling, requested map[string]string) (map[string]string, error) {
	if requested == nil {
		out := make(map[string]string, len(ceiling))
		for perm, level := range ceiling {
			out[perm] = level
		}
		return out, nil
	}
	if len(requested) == 0 {
		return nil, validationErrorf("requested permissions is empty: omit the field to request everything the trust policy allows")
	}

	// Iterate in sorted order so a request with several problems always
	// reports the same one, keeping errors reproducible for callers and
	// tests.
	names := make([]string, 0, len(requested))
	for perm := range requested {
		names = append(names, perm)
	}
	sort.Strings(names)

	out := make(map[string]string, len(requested))
	for _, perm := range names {
		level := requested[perm]
		if !ValidPermission(perm) {
			return nil, validationErrorf("requested permission %q is not a recognized GitHub App permission", perm)
		}
		// Check the pair, not the level alone: the levels GitHub accepts
		// differ per permission, so a narrowing request for "contents: admin"
		// is invalid even though "admin" is a level some permissions take.
		if !PermissionLevelAllowed(perm, level) {
			return nil, validationErrorf("requested level %q for permission %q is not one GitHub accepts (%s)",
				level, perm, strings.Join(ValidPermissionLevels[perm], ", "))
		}
		allowed, ok := ceiling[perm]
		if !ok {
			return nil, validationErrorf("requested permission %q is not granted by the trust policy", perm)
		}
		if PermissionRank(level) > PermissionRank(allowed) {
			return nil, validationErrorf("requested level %q for permission %q exceeds the trust policy ceiling %q", level, perm, allowed)
		}
		out[perm] = level
	}
	return out, nil
}

// FormatPermissions renders a permission set as a compact, deterministic
// "name:level,name:level" string, sorted by permission name.
//
// The sort is not cosmetic. This string is used as a Prometheus label value
// and as a log field, and Go randomizes map iteration order: an unsorted
// join produces a different string on different calls for the *same* set,
// which splits one logical time series into as many as n! of them and makes
// log lines for identical grants fail to group.
//
// An empty set renders as "all", matching the GitHub API's semantics: a
// create-token request that omits `permissions` inherits everything the
// installation was granted.
func FormatPermissions(perms map[string]string) string {
	if len(perms) == 0 {
		return "all"
	}
	names := make([]string, 0, len(perms))
	for name := range perms {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+":"+perms[name])
	}
	return strings.Join(parts, ",")
}

// GitBlobSHA returns git's object hash for the given file content: the same
// value as `git hash-object <file>` and as GitHub's `sha` field for a blob.
//
// It is computed locally from bytes already in hand, so recording policy
// provenance costs no additional GitHub API call -- which matters in a
// broker whose whole app-pool design exists to conserve rate-limit budget.
//
// This is SHA-1 because git is SHA-1; the point is to match git's identity,
// not to provide a collision-resistant primitive. The value is an audit
// record describing what was evaluated, never an input to an authorization
// decision, so SHA-1's collision weakness does not apply here.
func GitBlobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // git object identity, not a security primitive
	// hash.Hash.Write is documented never to return an error.
	h.Write([]byte("blob " + strconv.Itoa(len(content)) + "\x00"))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}
