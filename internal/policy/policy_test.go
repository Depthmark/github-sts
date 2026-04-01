package policy

import (
	"testing"
)

func TestEvaluate_IssuerMatch(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Permissions: map[string]string{"contents": "read"},
	}
	claims := map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:myorg/myrepo:ref:refs/heads/main",
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

func TestValidate_ValidPolicy(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Permissions: map[string]string{"contents": "read", "pull_requests": "write"},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingIssuer(t *testing.T) {
	p := &TrustPolicy{
		Permissions: map[string]string{"contents": "read"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestValidate_MissingPermissions(t *testing.T) {
	p := &TrustPolicy{
		Issuer: "https://iss.example.com",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing permissions")
	}
}

func TestValidate_InvalidPermissionName(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://iss.example.com",
		Permissions: map[string]string{"not_a_real_permission": "read"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid permission name")
	}
}

func TestValidate_InvalidPermissionLevel(t *testing.T) {
	p := &TrustPolicy{
		Issuer:      "https://iss.example.com",
		Permissions: map[string]string{"contents": "execute"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid permission level")
	}
}

func TestValidate_InvalidSubjectPattern(t *testing.T) {
	p := &TrustPolicy{
		Issuer:         "https://iss.example.com",
		SubjectPattern: "[invalid",
		Permissions:    map[string]string{"contents": "read"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestParsePolicy_ValidYAML(t *testing.T) {
	yaml := `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*:ref:refs/heads/main"
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

func TestParsePolicy_InvalidYAML(t *testing.T) {
	_, err := ParsePolicy([]byte("not: [valid: yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}
