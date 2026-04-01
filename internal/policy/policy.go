// Package policy provides trust policy models and evaluation logic for
// github-sts token exchange. Policies define which OIDC identities can
// obtain GitHub tokens with which permissions.
package policy

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

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

	// Pre-compiled regexes (populated by Validate, not serialized).
	subjectRegex *regexp.Regexp
	claimRegexes map[string]*regexp.Regexp
}

// ParsePolicy parses a YAML trust policy from raw bytes.
func ParsePolicy(data []byte) (*TrustPolicy, error) {
	var p TrustPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing trust policy YAML: %w", err)
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
// Pre-compiled regexes from Validate() are used when available; otherwise
// regexes are compiled on the fly for backward compatibility.
func (p *TrustPolicy) Evaluate(claims map[string]any) EvalResult {
	// 1. Issuer — exact match (always required).
	iss, _ := claims["iss"].(string)
	if iss != p.Issuer {
		return EvalResult{Reason: fmt.Sprintf("issuer mismatch: got %q, policy requires %q", iss, p.Issuer)}
	}

	// 2. Subject — exact match (if set).
	sub, _ := claims["sub"].(string)
	if p.Subject != "" {
		if sub != p.Subject {
			return EvalResult{Reason: fmt.Sprintf("subject mismatch: got %q, policy requires %q", sub, p.Subject)}
		}
	} else if p.SubjectPattern != "" {
		// 3. Subject pattern — regex full match.
		re := p.subjectRegex
		if re == nil {
			var err error
			re, err = regexp.Compile("^" + p.SubjectPattern + "$")
			if err != nil {
				return EvalResult{Reason: fmt.Sprintf("subject_pattern compile error: pattern %q, error: %v", p.SubjectPattern, err)}
			}
		}
		if !re.MatchString(sub) {
			return EvalResult{Reason: fmt.Sprintf("subject_pattern mismatch: got %q, policy requires pattern %q", sub, p.SubjectPattern)}
		}
	}

	// 4. Claim pattern — all patterns must full match.
	for claimName, pattern := range p.ClaimPattern {
		value := claimToString(claims[claimName])
		re := p.claimRegexes[claimName]
		if re == nil {
			var err error
			re, err = regexp.Compile("^" + pattern + "$")
			if err != nil {
				return EvalResult{Reason: fmt.Sprintf("claim_pattern compile error: claim %q, pattern %q, error: %v", claimName, pattern, err)}
			}
		}
		if !re.MatchString(value) {
			return EvalResult{Reason: fmt.Sprintf("claim_pattern mismatch: claim %q got %q, policy requires pattern %q", claimName, value, pattern)}
		}
	}

	return EvalResult{Allowed: true}
}

// Validate checks that the policy's fields are well-formed.
func (p *TrustPolicy) Validate() error {
	if p.Issuer == "" {
		return fmt.Errorf("trust policy: issuer is required")
	}
	if len(p.Permissions) == 0 {
		return fmt.Errorf("trust policy: at least one permission is required")
	}

	for perm, level := range p.Permissions {
		if !ValidPermissions[perm] {
			return fmt.Errorf("trust policy: invalid permission %q", perm)
		}
		if !ValidPermissionValues[level] {
			return fmt.Errorf("trust policy: invalid permission level %q for %q", level, perm)
		}
	}

	if p.SubjectPattern != "" {
		re, err := regexp.Compile("^" + p.SubjectPattern + "$")
		if err != nil {
			return fmt.Errorf("trust policy: invalid subject_pattern: %w", err)
		}
		p.subjectRegex = re
	}

	p.claimRegexes = make(map[string]*regexp.Regexp, len(p.ClaimPattern))
	for name, pattern := range p.ClaimPattern {
		re, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			return fmt.Errorf("trust policy: invalid claim_pattern for %q: %w", name, err)
		}
		p.claimRegexes[name] = re
	}

	return nil
}

func claimToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
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
	"custom_properties_for_organizations":          true,
	"members":                                      true,
	"organization_administration":                  true,
	"organization_announcement_banners":            true,
	"organization_copilot_agent_settings":          true,
	"organization_copilot_seat_management":         true,
	"organization_custom_org_roles":                true,
	"organization_custom_properties":               true,
	"organization_custom_roles":                    true,
	"organization_events":                          true,
	"organization_hooks":                           true,
	"organization_packages":                        true,
	"organization_personal_access_token_requests":  true,
	"organization_personal_access_tokens":          true,
	"organization_plan":                            true,
	"organization_projects":                        true,
	"organization_secrets":                         true,
	"organization_self_hosted_runners":             true,
	"organization_user_blocking":                   true,

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
