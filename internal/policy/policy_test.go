package policy

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestEvaluate_IssuerMatch(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://iss.example.com",
		Subject:     "workload-1",
		Permissions: map[string]string{"contents": "read"},
	}
	claims := map[string]any{
		"iss": "https://iss.example.com",
		"sub": "workload-1",
	}
	if r := p.Evaluate(claims); !r.Allowed {
		t.Fatal("expected match")
	}
}

func TestEvaluate_IssuerMismatch(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Permissions: map[string]string{"contents": "read"},
	}
	claims := map[string]any{
		"iss": "https://accounts.google.com",
		"sub": "test",
	}
	if r := p.Evaluate(claims); r.Allowed {
		t.Fatal("expected no match for wrong issuer")
	}
}

func TestEvaluate_SubjectExact(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://iss.example.com",
		Subject:     "repo:myorg/myrepo:ref:refs/heads/main",
		Permissions: map[string]string{"contents": "read"},
	}

	// Match.
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "repo:myorg/myrepo:ref:refs/heads/main"}); !r.Allowed {
		t.Fatal("expected match")
	}

	// No match.
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "repo:other/repo:ref:refs/heads/main"}); r.Allowed {
		t.Fatal("expected no match")
	}
}

func TestEvaluate_SubjectPattern(t *testing.T) {
	p := &TrustPolicy{
		Issuer:         "https://iss.example.com",
		SubjectPattern: `repo:myorg/.*:ref:refs/heads/main`,
		Permissions:    map[string]string{"contents": "read"},
	}

	// Match.
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "repo:myorg/myrepo:ref:refs/heads/main"}); !r.Allowed {
		t.Fatal("expected match")
	}

	// No match (different branch).
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "repo:myorg/myrepo:ref:refs/heads/dev"}); r.Allowed {
		t.Fatal("expected no match")
	}

	// No match (partial — full match required).
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "repo:myorg/myrepo:ref:refs/heads/main-extra"}); r.Allowed {
		t.Fatal("expected no match for partial string")
	}
}

func TestEvaluate_ClaimPattern(t *testing.T) {
	p := &TrustPolicy{
		Issuer: "https://iss.example.com",
		ClaimPattern: map[string]string{
			"repository": `myorg/.*`,
			"ref":        `refs/heads/(main|release/.*)`,
		},
		Permissions: map[string]string{"contents": "read"},
	}

	// Match.
	if r := p.Evaluate(map[string]any{
		"iss":        "https://iss.example.com",
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/main",
	}); !r.Allowed {
		t.Fatal("expected match")
	}

	// No match (wrong ref).
	if r := p.Evaluate(map[string]any{
		"iss":        "https://iss.example.com",
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/dev",
	}); r.Allowed {
		t.Fatal("expected no match for wrong ref")
	}
}

func TestEvaluate_MissingClaim(t *testing.T) {
	p := &TrustPolicy{
		Issuer:       "https://iss.example.com",
		ClaimPattern: map[string]string{"repository": `myorg/.*`},
		Permissions:  map[string]string{"contents": "read"},
	}

	// Missing claim → empty string → no match.
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com"}); r.Allowed {
		t.Fatal("expected no match for missing claim")
	}
}

func TestEvaluate_NonStringClaimDenied(t *testing.T) {
	p := &TrustPolicy{
		Issuer:       "https://iss.example.com",
		ClaimPattern: map[string]string{"repository_id": `[0-9]+`},
		Permissions:  map[string]string{"contents": "read"},
	}

	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "repository_id": 123}); r.Allowed {
		t.Fatal("expected no match for non-string claim")
	}
}

func TestEvaluate_SubjectPatternAlternationIsFullyAnchored(t *testing.T) {
	p := &TrustPolicy{
		Issuer:         "https://iss.example.com",
		SubjectPattern: `main|release`,
		Permissions:    map[string]string{"contents": "read"},
	}

	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "main-extra"}); r.Allowed {
		t.Fatal("expected top-level alternation to be fully anchored")
	}
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com", "sub": "release"}); !r.Allowed {
		t.Fatalf("expected exact alternative to match: %s", r.Reason)
	}
}

func TestEvaluate_NoSelectorFailsClosed(t *testing.T) {
	p := &TrustPolicy{Issuer: "https://iss.example.com", Permissions: map[string]string{"contents": "read"}}
	if r := p.Evaluate(map[string]any{"iss": "https://iss.example.com"}); r.Allowed {
		t.Fatal("expected selector-free policy to deny")
	}
}

func TestTrustPolicy_ConcurrentValidateAndEvaluate(t *testing.T) {
	p := validGitHubPolicy()
	p.Subject = ""
	p.SubjectPattern = `workload-(main|release)`
	p.ClaimPattern = map[string]string{"ref": `refs/heads/(main|release)`}
	claims := map[string]any{
		"iss": githubActionsIssuer,
		"sub": "workload-main",
		"ref": "refs/heads/main",
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if err := p.Validate(); err != nil {
					t.Errorf("Validate: %v", err)
					return
				}
				if result := p.Evaluate(claims); !result.Allowed {
					t.Errorf("Evaluate denied: %s", result.Reason)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestValidate_ValidPolicy(t *testing.T) {
	p := validGitHubPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingAudience(t *testing.T) {
	p := validGitHubPolicy()
	p.Audience = ""
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing audience")
	}
}

func TestValidate_MissingIssuer(t *testing.T) {
	p := validGitHubPolicy()
	p.Issuer = ""
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestValidate_MissingPermissions(t *testing.T) {
	p := validGitHubPolicy()
	p.Permissions = nil
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing permissions")
	}
}

func TestValidate_InvalidPermissionName(t *testing.T) {
	p := validGitHubPolicy()
	p.Permissions = map[string]string{"not_a_real_permission": "read"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid permission name")
	}
}

func TestValidate_InvalidPermissionLevel(t *testing.T) {
	p := validGitHubPolicy()
	p.Permissions = map[string]string{"contents": "execute"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid permission level")
	}
}

func TestValidate_InvalidSubjectPattern(t *testing.T) {
	p := &TrustPolicy{
		Issuer:         "https://iss.example.com",
		SubjectPattern: "[invalid",
		Audience:       "https://sts.example.com",
		Permissions:    map[string]string{"contents": "read"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestValidate_RequiresWorkloadSelector(t *testing.T) {
	p := validGitHubPolicy()
	p.Subject = ""
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing workload identity selector")
	}
}

func TestValidate_RejectsSubjectConflict(t *testing.T) {
	p := validGitHubPolicy()
	p.SubjectPattern = `.*`
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for conflicting subject selectors")
	}
}

func TestValidate_RejectsRepositoriesWhileOrganizationScopesDisabled(t *testing.T) {
	p := validGitHubPolicy()
	p.Repositories = []string{"repo-a"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected repositories to be rejected")
	}
}

func TestValidate_RequiresGitHubRelationship(t *testing.T) {
	p := validGitHubPolicy()
	p.GitHub = nil
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing GitHub relationship")
	}
}

func TestValidate_RejectsGitHubRelationshipForOtherIssuer(t *testing.T) {
	p := validGitHubPolicy()
	p.Issuer = "https://iss.example.com"
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for GitHub relationship on another issuer")
	}
}

func TestValidate_GitHubIDs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TrustPolicy)
	}{
		{name: "empty sources", mutate: func(p *TrustPolicy) { p.GitHub.Sources = nil }},
		{name: "source owner zero", mutate: func(p *TrustPolicy) { p.GitHub.Sources[0].OwnerID = "0" }},
		{name: "source repository regex", mutate: func(p *TrustPolicy) { p.GitHub.Sources[0].RepositoryID = ".*" }},
		{name: "target owner empty", mutate: func(p *TrustPolicy) { p.GitHub.Target.OwnerID = "" }},
		{name: "target repository nondecimal", mutate: func(p *TrustPolicy) { p.GitHub.Target.RepositoryID = "123x" }},
		{name: "duplicate source", mutate: func(p *TrustPolicy) { p.GitHub.Sources = append(p.GitHub.Sources, p.GitHub.Sources[0]) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validGitHubPolicy()
			tt.mutate(p)
			if err := p.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEvaluateGitHubRelationship(t *testing.T) {
	p := validGitHubPolicy()
	source := GitHubRepository{OwnerID: "1001", RepositoryID: "2001"}
	target := GitHubRepository{OwnerID: "1001", RepositoryID: "2002"}

	if r := p.EvaluateGitHubRelationship(source, target); !r.Allowed {
		t.Fatalf("expected relationship to match: %s", r.Reason)
	}
	if r := p.EvaluateGitHubRelationship(GitHubRepository{OwnerID: "1001", RepositoryID: "9999"}, target); r.Allowed {
		t.Fatal("expected unknown source to deny")
	}
	if r := p.EvaluateGitHubRelationship(source, GitHubRepository{OwnerID: "1001", RepositoryID: "9999"}); r.Allowed {
		t.Fatal("expected wrong target to deny")
	}
}

func TestParsePolicy_ValidYAML(t *testing.T) {
	yaml := `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*:ref:refs/heads/main"
audience: https://sts.example.com
github:
  sources:
    - owner_id: "1001"
      repository_id: "2001"
  target:
    owner_id: "1001"
    repository_id: "2002"
permissions:
  contents: read
  pull_requests: write
`
	p, err := ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("unexpected issuer: %s", p.Issuer)
	}
	if len(p.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(p.Permissions))
	}
}

func TestParsePolicy_RejectsUnquotedGitHubID(t *testing.T) {
	yaml := `issuer: https://token.actions.githubusercontent.com
subject: workload-1
audience: https://sts.example.com
github:
  sources:
    - owner_id: 1001
      repository_id: "2001"
  target:
    owner_id: "1001"
    repository_id: "2002"
permissions:
  contents: read
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected unquoted GitHub ID to fail")
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *ValidationError", err)
	}
}

func TestParsePolicy_StrictYAML(t *testing.T) {
	base := `issuer: https://token.actions.githubusercontent.com
claim_pattern:
  ref: refs/heads/main
audience: https://sts.example.com
github:
  sources:
    - owner_id: "1001"
      repository_id: "2001"
  target:
    owner_id: "1001"
    repository_id: "2002"
permissions:
  contents: read
`
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "unknown top level", content: base + "subjet: workload\n", want: "field subjet not found"},
		{name: "unknown nested", content: strings.Replace(base, "    repository_id: \"2002\"\npermissions:", "    repository_id: \"2002\"\n    typo: true\npermissions:", 1), want: "field typo not found"},
		{name: "duplicate key", content: base + "audience: duplicate\n", want: "already defined"},
		{name: "multiple documents", content: base + "---\n{}\n", want: "multiple YAML documents"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParsePolicy_InvalidYAML(t *testing.T) {
	_, err := ParsePolicy([]byte("not: [valid: yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func validGitHubPolicy() *TrustPolicy {
	return &TrustPolicy{
		Issuer:      githubActionsIssuer,
		Subject:     "workload-1",
		Audience:    "https://sts.example.com",
		Permissions: map[string]string{"contents": "read", "pull_requests": "write"},
		GitHub: &GitHubPolicy{
			Sources: []GitHubRepository{{OwnerID: "1001", RepositoryID: "2001"}},
			Target:  GitHubRepository{OwnerID: "1001", RepositoryID: "2002"},
		},
	}
}
