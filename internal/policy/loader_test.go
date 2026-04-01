package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockTokenProvider implements TokenProvider for tests.
type mockTokenProvider struct {
	token string
	err   error
}

func (m *mockTokenProvider) GetInstallationToken(_ context.Context, _ string, _ map[string]string, _ []string, _ string) (string, error) {
	return m.token, m.err
}

func TestGitHubLoader_RepoLevel(t *testing.T) {
	policyYAML := `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
permissions:
  contents: read
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect: /repos/myorg/myrepo/contents/.github/sts/default/ci.sts.yaml
		if !strings.Contains(r.URL.Path, "myorg/myrepo") {
			t.Errorf("expected repo-level path, got %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/vnd.github.raw+json" {
			t.Errorf("unexpected Accept: %s", r.Header.Get("Accept"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, srv.URL, "sts-policies", "", 5*time.Minute, nil)

	policy, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
	if policy.Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("unexpected issuer: %s", policy.Issuer)
	}
}

func TestGitHubLoader_OrgLevel(t *testing.T) {
	policyYAML := `
issuer: https://token.actions.githubusercontent.com
permissions:
  contents: read
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect: /repos/myorg/sts-policies/contents/...
		if !strings.Contains(r.URL.Path, "myorg/sts-policies") {
			t.Errorf("expected org-level path with policy repo, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, srv.URL, "sts-policies", "", 5*time.Minute, nil)

	policy, err := loader.Load(context.Background(), "myorg", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestGitHubLoader_OrgLevel_MissingPolicyRepo(t *testing.T) {
	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, "http://localhost", "", "", 5*time.Minute, nil)

	_, err := loader.Load(context.Background(), "myorg", "default", "ci")
	if err == nil {
		t.Fatal("expected error for missing org_policy_repo")
	}
	if !strings.Contains(err.Error(), "org_policy_repo required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGitHubLoader_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, srv.URL, "sts-policies", "", 5*time.Minute, nil)

	policy, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Fatal("expected nil policy for 404")
	}
}

func TestGitHubLoader_CacheHit(t *testing.T) {
	fetchCount := 0
	policyYAML := `
issuer: https://iss.example.com
permissions:
  contents: read
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, srv.URL, "sts-policies", "", 5*time.Minute, nil)

	// First call — cache miss.
	_, _ = loader.Load(context.Background(), "myorg/myrepo", "default", "ci")

	// Second call — cache hit.
	_, _ = loader.Load(context.Background(), "myorg/myrepo", "default", "ci")

	if fetchCount != 1 {
		t.Fatalf("expected 1 fetch (cached), got %d", fetchCount)
	}
}

func TestGitHubLoader_ParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not: [valid: yaml"))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := NewGitHubLoader(tp, srv.URL, "sts-policies", "", 5*time.Minute, nil)

	policy, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err == nil {
		t.Fatal("expected error for parse failure, got nil")
	}
	if policy != nil {
		t.Fatal("expected nil policy for parse error")
	}
}
