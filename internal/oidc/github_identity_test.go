package oidc

import (
	"errors"
	"testing"
)

func validGitHubIdentityClaims() Claims {
	return Claims{
		"iss":                 GitHubActionsIssuer,
		"sub":                 "repo:Depthmark@268749784/github-sts@1198676434:ref:refs/heads/main",
		"repository":          "Depthmark/github-sts",
		"repository_owner":    "Depthmark",
		"repository_id":       "1198676434",
		"repository_owner_id": "268749784",
	}
}

func cloneClaims(in Claims) Claims {
	out := make(Claims, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestParseGitHubIdentity_ImmutableContexts(t *testing.T) {
	subjects := []string{
		"repo:Depthmark@268749784/github-sts@1198676434:ref:refs/heads/main",
		"repo:Depthmark@268749784/github-sts@1198676434:ref:refs/tags/v1.2.3",
		"repo:Depthmark@268749784/github-sts@1198676434:pull_request",
		"repo:Depthmark@268749784/github-sts@1198676434:environment:production",
		"repository_visibility:private:repo:Depthmark@268749784/github-sts@1198676434:job_workflow_ref:Depthmark/automation/.github/workflows/release.yml@refs/heads/main",
		"repository_owner:repo:repo:Depthmark@268749784/github-sts@1198676434:ref:refs/heads/main",
	}

	for _, subject := range subjects {
		t.Run(subject, func(t *testing.T) {
			claims := validGitHubIdentityClaims()
			claims["sub"] = subject
			identity, err := ParseGitHubIdentity(claims, true)
			if err != nil {
				t.Fatalf("ParseGitHubIdentity() error: %v", err)
			}
			if !identity.ImmutableSubject {
				t.Fatal("ImmutableSubject = false, want true")
			}
			if identity.RepositoryName != "github-sts" || identity.RepositoryID != "1198676434" {
				t.Fatalf("unexpected identity: %+v", identity)
			}
		})
	}
}

func TestParseGitHubIdentity_CaseInsensitiveNames(t *testing.T) {
	claims := validGitHubIdentityClaims()
	claims["repository"] = "depthmark/GITHUB-STS"
	claims["repository_owner"] = "DEPTHMARK"

	identity, err := ParseGitHubIdentity(claims, true)
	if err != nil {
		t.Fatalf("ParseGitHubIdentity() error: %v", err)
	}
	if identity.Repository != "depthmark/GITHUB-STS" {
		t.Fatalf("Repository = %q, want signed claim spelling", identity.Repository)
	}
}

func TestParseGitHubIdentity_LegacySubjectOptOut(t *testing.T) {
	claims := validGitHubIdentityClaims()
	claims["sub"] = "repo:Depthmark/github-sts:ref:refs/heads/.*"

	_, err := ParseGitHubIdentity(claims, true)
	assertGitHubIdentityReason(t, err, GitHubIdentityImmutableSubjectRequired)

	identity, err := ParseGitHubIdentity(claims, false)
	if err != nil {
		t.Fatalf("ParseGitHubIdentity(opt-out) error: %v", err)
	}
	if identity.ImmutableSubject {
		t.Fatal("ImmutableSubject = true, want false")
	}
	if identity.RepositoryOwnerID != "268749784" || identity.RepositoryID != "1198676434" {
		t.Fatalf("legacy subject lost immutable claim IDs: %+v", identity)
	}
}

func TestParseGitHubIdentity_RejectsInvalidClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Claims)
		reason GitHubIdentityErrorReason
	}{
		{"missing subject", func(c Claims) { delete(c, "sub") }, GitHubIdentityMissingClaim},
		{"wrong subject type", func(c Claims) { c["sub"] = 1 }, GitHubIdentityInvalidClaimType},
		{"empty repository", func(c Claims) { c["repository"] = "" }, GitHubIdentityInvalidClaim},
		{"malformed repository", func(c Claims) { c["repository"] = "Depthmark" }, GitHubIdentityInvalidClaim},
		{"missing repository ID", func(c Claims) { delete(c, "repository_id") }, GitHubIdentityMissingClaim},
		{"numeric repository ID", func(c Claims) { c["repository_id"] = float64(1198676434) }, GitHubIdentityInvalidClaimType},
		{"zero repository ID", func(c Claims) { c["repository_id"] = "0" }, GitHubIdentityInvalidID},
		{"non-decimal owner ID", func(c Claims) { c["repository_owner_id"] = "owner-1" }, GitHubIdentityInvalidID},
		{"claim owner mismatch", func(c Claims) { c["repository_owner"] = "Other" }, GitHubIdentityClaimMismatch},
		{"subject owner mismatch", func(c Claims) { c["sub"] = "repo:Other@268749784/github-sts@1198676434:ref:refs/heads/main" }, GitHubIdentityClaimMismatch},
		{"subject owner ID mismatch", func(c Claims) { c["sub"] = "repo:Depthmark@1/github-sts@1198676434:ref:refs/heads/main" }, GitHubIdentityClaimMismatch},
		{"subject repository ID mismatch", func(c Claims) { c["sub"] = "repo:Depthmark@268749784/github-sts@1:ref:refs/heads/main" }, GitHubIdentityClaimMismatch},
		{"missing repo segment", func(c Claims) { c["sub"] = "repository_owner:Depthmark" }, GitHubIdentitySubjectRepositoryMissing},
		{"duplicate repo segment", func(c Claims) {
			c["sub"] = "repo:Depthmark@268749784/github-sts@1198676434:repo:Depthmark@268749784/github-sts@1198676434"
		}, GitHubIdentitySubjectRepositoryDuplicate},
		{"partial immutable segment", func(c Claims) { c["sub"] = "repo:Depthmark@268749784/github-sts:ref:refs/heads/main" }, GitHubIdentitySubjectRepositoryInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := cloneClaims(validGitHubIdentityClaims())
			tt.mutate(claims)
			_, err := ParseGitHubIdentity(claims, true)
			assertGitHubIdentityReason(t, err, tt.reason)
		})
	}
}

func TestParseGitHubIdentity_OtherIssuersUnaffected(t *testing.T) {
	for _, issuer := range []string{
		"https://github.example.com/_services/token",
		"https://accounts.google.com",
		"",
	} {
		claims := Claims{"iss": issuer, "sub": "anything"}
		identity, err := ParseGitHubIdentity(claims, true)
		if err != nil {
			t.Fatalf("issuer %q: unexpected error: %v", issuer, err)
		}
		if identity != nil {
			t.Fatalf("issuer %q: identity = %+v, want nil", issuer, identity)
		}
	}
}

func assertGitHubIdentityReason(t *testing.T, err error, want GitHubIdentityErrorReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want reason %q", want)
	}
	var identityErr *GitHubIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("error type = %T, want *GitHubIdentityError", err)
	}
	if identityErr.Reason != want {
		t.Fatalf("reason = %q, want %q (error: %v)", identityErr.Reason, want, err)
	}
}
