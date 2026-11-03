package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testEnterpriseIssuer = githubActionsIssuer + "/octocat-inc"

func enterprisePolicyYAML(issuer string) []byte {
	return []byte(`issuer: ` + issuer + `
audience: https://sts.example.com
subject: repo:org@1001/source@2001:ref:refs/heads/main
github:
  sources:
    - owner_id: "1001"
      repository_id: "2001"
  target:
    owner_id: "1001"
    repository_id: "2002"
permissions:
  contents: read
`)
}

func TestValidate_DeclaredGitHubIssuer(t *testing.T) {
	missingBlock := validGitHubPolicy()
	missingBlock.Issuer = testEnterpriseIssuer
	missingBlock.GitHub = nil

	emptySources := validGitHubPolicy()
	emptySources.Issuer = testEnterpriseIssuer
	emptySources.GitHub.Sources = nil

	badTarget := validGitHubPolicy()
	badTarget.Issuer = testEnterpriseIssuer
	badTarget.GitHub.Target.RepositoryID = "abc"

	valid := validGitHubPolicy()
	valid.Issuer = testEnterpriseIssuer

	tests := []struct {
		name     string
		policy   *TrustPolicy
		declared []string
		wantErr  string
	}{
		{name: "valid when declared", policy: valid, declared: []string{testEnterpriseIssuer}},
		{name: "github block rejected when not declared", policy: valid, wantErr: "github is only valid"},
		{name: "another issuer declared", policy: valid, declared: []string{githubActionsIssuer + "/other"}, wantErr: "github is only valid"},
		{name: "github block required when declared", policy: missingBlock, declared: []string{testEnterpriseIssuer}, wantErr: "github is required"},
		{name: "sources required when declared", policy: emptySources, declared: []string{testEnterpriseIssuer}, wantErr: "github.sources"},
		{name: "IDs validated when declared", policy: badTarget, declared: []string{testEnterpriseIssuer}, wantErr: "github.target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate(tt.declared...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error: %v", err)
				}
				return
			}
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %v (%T), want *ValidationError", err, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// Declaring an issuer changes nothing for the default issuer or a generic one.
func TestValidate_DeclarationLeavesOtherIssuersAlone(t *testing.T) {
	declared := []string{testEnterpriseIssuer}

	noBlock := validGitHubPolicy()
	noBlock.GitHub = nil
	if err := noBlock.Validate(declared...); err == nil {
		t.Fatal("default issuer without a github block passed validation")
	}

	generic := validGitHubPolicy()
	generic.Issuer = "https://accounts.google.com"
	if err := generic.Validate(declared...); err == nil {
		t.Fatal("generic issuer with a github block passed validation")
	}
}

func TestParsePolicy_DeclaredGitHubIssuer(t *testing.T) {
	data := enterprisePolicyYAML(testEnterpriseIssuer)
	if _, err := ParsePolicy(data, testEnterpriseIssuer); err != nil {
		t.Fatalf("ParsePolicy() with the issuer declared: %v", err)
	}
	if _, err := ParsePolicy(data); err == nil {
		t.Fatal("ParsePolicy() accepted a github block for an undeclared issuer")
	}
}

func TestEvaluateGitHubRelationship_DeclaredIssuer(t *testing.T) {
	p := validGitHubPolicy()
	p.Issuer = testEnterpriseIssuer
	source := GitHubRepository{OwnerID: "1001", RepositoryID: "2001"}
	target := GitHubRepository{OwnerID: "1001", RepositoryID: "2002"}

	if r := p.EvaluateGitHubRelationship(source, target, testEnterpriseIssuer); !r.Allowed {
		t.Fatalf("declared issuer denied: %s", r.Reason)
	}
	if r := p.EvaluateGitHubRelationship(source, target); r.Allowed {
		t.Fatal("undeclared issuer allowed")
	}
	if r := p.EvaluateGitHubRelationship(GitHubRepository{OwnerID: "1001", RepositoryID: "9"}, target, testEnterpriseIssuer); r.Allowed {
		t.Fatal("unlisted source allowed")
	}
	if r := p.EvaluateGitHubRelationship(source, GitHubRepository{OwnerID: "1001", RepositoryID: "9"}, testEnterpriseIssuer); r.Allowed {
		t.Fatal("wrong target allowed")
	}
}

type fixedTokenProvider struct{}

func (fixedTokenProvider) GetInstallationToken(context.Context, string, map[string]string, []string, string) (string, string, error) {
	return "token", "default", nil
}

func TestGitHubPolicyLoader_DeclaredGitHubIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(enterprisePolicyYAML(testEnterpriseIssuer))
	}))
	t.Cleanup(srv.Close)

	newLoader := func() *GitHubPolicyLoader {
		return NewGitHubLoader(map[string]TokenProvider{"deploy": fixedTokenProvider{}}, nil, nil, srv.URL, "", time.Minute, nil, srv.Client())
	}
	request := LoadRequest{Scope: "org/target", TargetOwnerID: "1001", TargetRepositoryID: "2002", AppName: "deploy", Identity: "ci"}

	declared := newLoader()
	declared.SetGitHubIssuers([]string{testEnterpriseIssuer})
	pol, err := declared.Load(context.Background(), request)
	if err != nil {
		t.Fatalf("Load() with the issuer declared: %v", err)
	}
	if pol == nil || pol.Issuer != testEnterpriseIssuer {
		t.Fatalf("policy = %+v, want issuer %q", pol, testEnterpriseIssuer)
	}

	_, err = newLoader().Load(context.Background(), request)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Load() without a declaration: error = %v, want *ValidationError", err)
	}
}

// The published schema cannot know the declared issuers, so it may no longer
// forbid the github block on other issuers. It must keep requiring the block on
// the default issuer, which is what protects a policy author in an editor.
func TestSchemaLeavesTheGitHubBlockRuleToTheServer(t *testing.T) {
	schema := loadSchema(t)
	rules, ok := dig(t, schema, "allOf").([]any)
	if !ok {
		t.Fatal("schema: allOf is not an array")
	}
	var issuerRule map[string]any
	for _, rule := range rules {
		if object, ok := rule.(map[string]any); ok && object["if"] != nil {
			issuerRule = object
		}
	}
	if issuerRule == nil {
		t.Fatal("schema: no conditional issuer rule in allOf")
	}
	if _, ok := issuerRule["else"]; ok {
		t.Error("schema: the issuer rule still has an else branch, which rejects a github block on a declared issuer")
	}
	if got := dig(t, issuerRule, "if", "properties", "issuer", "const"); got != githubActionsIssuer {
		t.Errorf("schema: issuer rule applies to %v, want %q", got, githubActionsIssuer)
	}
	required := enumStrings(t, dig(t, issuerRule, "then", "required"), "then.required")
	if !required["github"] {
		t.Error("schema: github is no longer required for the default issuer")
	}
}
