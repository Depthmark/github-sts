package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testEnterpriseIssuer = GitHubActionsIssuer + "/octocat-inc"

func testDeclaredIssuer() GitHubIssuer {
	return GitHubIssuer{Issuer: testEnterpriseIssuer, Instance: GitHubDotComInstance, Apps: []string{"deploy"}}
}

func validEnterpriseClaims() Claims {
	claims := validGitHubIdentityClaims()
	claims["iss"] = testEnterpriseIssuer
	return claims
}

func TestGitHubIssuerInstance(t *testing.T) {
	tests := []struct {
		name         string
		issuer       string
		wantInstance string
		wantOK       bool
	}{
		{name: "enterprise slug", issuer: testEnterpriseIssuer, wantInstance: GitHubDotComInstance, wantOK: true},
		{name: "single character slug", issuer: GitHubActionsIssuer + "/a", wantInstance: GitHubDotComInstance, wantOK: true},
		{name: "default issuer needs no declaration", issuer: GitHubActionsIssuer},
		{name: "empty slug", issuer: GitHubActionsIssuer + "/"},
		{name: "trailing slash", issuer: testEnterpriseIssuer + "/"},
		{name: "two path segments", issuer: testEnterpriseIssuer + "/extra"},
		{name: "path traversal", issuer: GitHubActionsIssuer + "/../octocat-inc"},
		{name: "query string", issuer: testEnterpriseIssuer + "?x=1"},
		{name: "fragment", issuer: testEnterpriseIssuer + "#x"},
		{name: "newline after slug", issuer: testEnterpriseIssuer + "\n"},
		{name: "leading hyphen", issuer: GitHubActionsIssuer + "/-octocat"},
		{name: "http scheme", issuer: "http://token.actions.githubusercontent.com/octocat-inc"},
		{name: "explicit port", issuer: "https://token.actions.githubusercontent.com:8443/octocat-inc"},
		{name: "userinfo", issuer: "https://evil@token.actions.githubusercontent.com/octocat-inc"},
		{name: "lookalike host", issuer: "https://token.actions.githubusercontent.com.evil.example/octocat-inc"},
		{name: "unescaped dot in host", issuer: "https://token-actions.githubusercontent.com/octocat-inc"},
		{name: "GHE.com issuer", issuer: "https://token.actions.octocorp.ghe.com/octocorp"},
		{name: "GitHub Enterprise Server issuer", issuer: "https://github.example.com/_services/token"},
		{name: "empty", issuer: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance, ok := GitHubIssuerInstance(tt.issuer)
			if ok != tt.wantOK || instance != tt.wantInstance {
				t.Fatalf("GitHubIssuerInstance(%q) = %q, %v, want %q, %v", tt.issuer, instance, ok, tt.wantInstance, tt.wantOK)
			}
		})
	}
}

func TestGitHubIssuer_EnabledFor(t *testing.T) {
	issuer := testDeclaredIssuer()
	if !issuer.EnabledFor("deploy") {
		t.Fatal("EnabledFor(deploy) = false, want true")
	}
	if issuer.EnabledFor("other") {
		t.Fatal("EnabledFor(other) = true, want false")
	}
}

func TestParseDeclaredGitHubIdentity_Valid(t *testing.T) {
	identity, err := ParseDeclaredGitHubIdentity(validEnterpriseClaims(), testDeclaredIssuer())
	if err != nil {
		t.Fatalf("ParseDeclaredGitHubIdentity() error: %v", err)
	}
	if identity.Issuer != testEnterpriseIssuer {
		t.Fatalf("Issuer = %q, want %q", identity.Issuer, testEnterpriseIssuer)
	}
	if identity.RepositoryOwnerID != "268749784" || identity.RepositoryID != "1198676434" || !identity.ImmutableSubject {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

// The rejections of the default issuer's contract, as in
// TestParseGitHubIdentity_RejectsInvalidClaims, applied to the enterprise issuer.
func TestParseDeclaredGitHubIdentity_Rejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Claims)
		reason GitHubIdentityErrorReason
	}{
		{"missing sub", func(c Claims) { delete(c, "sub") }, GitHubIdentityMissingClaim},
		{"missing repository", func(c Claims) { delete(c, "repository") }, GitHubIdentityMissingClaim},
		{"missing repository owner", func(c Claims) { delete(c, "repository_owner") }, GitHubIdentityMissingClaim},
		{"missing repository ID", func(c Claims) { delete(c, "repository_id") }, GitHubIdentityMissingClaim},
		{"missing owner ID", func(c Claims) { delete(c, "repository_owner_id") }, GitHubIdentityMissingClaim},
		{"numeric repository ID", func(c Claims) { c["repository_id"] = float64(1198676434) }, GitHubIdentityInvalidClaimType},
		{"empty repository", func(c Claims) { c["repository"] = "" }, GitHubIdentityInvalidClaim},
		{"zero repository ID", func(c Claims) { c["repository_id"] = "0" }, GitHubIdentityInvalidID},
		{"non-decimal owner ID", func(c Claims) { c["repository_owner_id"] = "owner-1" }, GitHubIdentityInvalidID},
		{"claim owner mismatch", func(c Claims) { c["repository_owner"] = "Other" }, GitHubIdentityClaimMismatch},
		{"mismatched repository_id", func(c Claims) { c["repository_id"] = "1" }, GitHubIdentityClaimMismatch},
		{"mismatched repository_owner_id", func(c Claims) { c["repository_owner_id"] = "1" }, GitHubIdentityClaimMismatch},
		{"subject repository mismatch", func(c Claims) { c["sub"] = "repo:Depthmark@268749784/other@1198676434:ref:refs/heads/main" }, GitHubIdentityClaimMismatch},
		{"legacy subject", func(c Claims) { c["sub"] = "repo:Depthmark/github-sts:ref:refs/heads/main" }, GitHubIdentityImmutableSubjectRequired},
		{"missing repo segment", func(c Claims) { c["sub"] = "repository_owner:Depthmark" }, GitHubIdentitySubjectRepositoryMissing},
		{"duplicate repo segment", func(c Claims) {
			c["sub"] = "repo:Depthmark@268749784/github-sts@1198676434:repo:Depthmark@268749784/github-sts@1198676434"
		}, GitHubIdentitySubjectRepositoryDuplicate},
		{"partial immutable segment", func(c Claims) { c["sub"] = "repo:Depthmark@268749784/github-sts:ref:refs/heads/main" }, GitHubIdentitySubjectRepositoryInvalid},
		{"issuer differs from the declaration", func(c Claims) { c["iss"] = GitHubActionsIssuer + "/other" }, GitHubIdentityClaimMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := cloneClaims(validEnterpriseClaims())
			tt.mutate(claims)
			_, err := ParseDeclaredGitHubIdentity(claims, testDeclaredIssuer())
			assertGitHubIdentityReason(t, err, tt.reason)
		})
	}
}

// The undeclared enterprise issuer stays a generic issuer: only a declaration
// brings it under the GitHub identity contract.
func TestParseGitHubIdentity_UndeclaredEnterpriseIssuerUnaffected(t *testing.T) {
	identity, err := ParseGitHubIdentity(Claims{"iss": testEnterpriseIssuer, "sub": "anything"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != nil {
		t.Fatalf("identity = %+v, want nil", identity)
	}
}

// GitHub serves an enterprise issuer's discovery document under the slug, with
// a jwks_uri at the root of the same host, shared by every enterprise. This
// mirrors that shape, which same-host pinning must accept without an override.
func TestValidate_EnterpriseIssuerSharesRootJWKS(t *testing.T) {
	ResetCacheForTesting()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/octocat-inc/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   fmt.Sprintf("http://%s/octocat-inc", r.Host),
			"jwks_uri": fmt.Sprintf("http://%s/.well-known/jwks", r.Host),
		})
	})
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-kid-1",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issuer := srv.URL + "/octocat-inc"
	now := time.Now()
	token := signTestToken(t, key, jwt.MapClaims{
		"iss": issuer,
		"sub": "repo:org@1/repo@2:ref:refs/heads/main",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})

	claims, err := Validate(context.Background(), token, []string{issuer})
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if claims["iss"] != issuer {
		t.Fatalf("iss = %v, want %q", claims["iss"], issuer)
	}

	// The slug is part of the allowlist entry: sharing keys with the default
	// issuer does not make a token from one acceptable under the other.
	if _, err := Validate(context.Background(), token, []string{srv.URL}); err == nil {
		t.Fatal("Validate() accepted an enterprise token under the bare issuer")
	}
}
