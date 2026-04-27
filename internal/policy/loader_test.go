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
	token  string
	err    error
	scopes []string // captures the scope passed to each call, in order
}

func (m *mockTokenProvider) GetInstallationToken(_ context.Context, scope string, _ map[string]string, _ []string, _ string) (string, error) {
	m.scopes = append(m.scopes, scope)
	return m.token, m.err
}

// testLoader creates a loader with a single app "default" for convenience.
func testLoader(tp TokenProvider, apiURL, orgPolicyRepo string, cacheTTL time.Duration) *GitHubPolicyLoader {
	tps := map[string]TokenProvider{"default": tp}
	repos := map[string]string{}
	if orgPolicyRepo != "" {
		repos["default"] = orgPolicyRepo
	}
	return NewGitHubLoader(tps, repos, apiURL, "", cacheTTL, nil, nil)
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
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

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
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

	policy, err := loader.Load(context.Background(), "myorg", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestGitHubLoader_RepoLevel_FallsBackToOrgPolicyRepo(t *testing.T) {
	policyYAML := `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
permissions:
  contents: read
`
	var pathsRequested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathsRequested = append(pathsRequested, r.URL.Path)
		// First request (repo-local) → 404. Subsequent (org repo) → 200.
		if strings.Contains(r.URL.Path, "myorg/myrepo/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !strings.Contains(r.URL.Path, "myorg/sts-policies/") {
			t.Errorf("fallback should hit org policy repo, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol == nil {
		t.Fatal("expected policy from org repo fallback, got nil")
	}
	if !pol.Centralized() {
		t.Error("policy from org repo fallback must be marked Centralized()")
	}
	if len(pathsRequested) != 2 {
		t.Fatalf("expected 2 fetches (repo + org repo), got %d: %v", len(pathsRequested), pathsRequested)
	}

	// Two install tokens were minted: first scoped to the requesting repo,
	// second scoped to the org policy repo. Neither should ever be scoped
	// org-wide for the policy fetch step.
	if len(tp.scopes) != 2 {
		t.Fatalf("expected 2 token requests, got %d: %v", len(tp.scopes), tp.scopes)
	}
	if tp.scopes[0] != "myorg/myrepo" {
		t.Errorf("first policy-fetch token scope = %q, want %q", tp.scopes[0], "myorg/myrepo")
	}
	if tp.scopes[1] != "myorg/sts-policies" {
		t.Errorf("fallback policy-fetch token scope = %q, want %q", tp.scopes[1], "myorg/sts-policies")
	}
}

func TestGitHubLoader_RepoLevel_NoFallbackWhenOrgPolicyRepoUnset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	// No org policy repo configured → no fallback, returns nil.
	loader := testLoader(tp, srv.URL, "", 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol != nil {
		t.Errorf("expected nil policy, got %+v", pol)
	}
	if len(tp.scopes) != 1 {
		t.Errorf("expected single fetch attempt, got %d: %v", len(tp.scopes), tp.scopes)
	}
}

func TestGitHubLoader_OrgLevel_MarksCentralized(t *testing.T) {
	policyYAML := `
issuer: https://token.actions.githubusercontent.com
permissions:
  contents: read
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol == nil || !pol.Centralized() {
		t.Fatal("org-level policy must be marked Centralized()")
	}
}

func TestGitHubLoader_OrgLevel_MissingPolicyRepo(t *testing.T) {
	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoader(tp, "http://localhost", "", 5*time.Minute)

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
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

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
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

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
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

	policy, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err == nil {
		t.Fatal("expected error for parse failure, got nil")
	}
	if policy != nil {
		t.Fatal("expected nil policy for parse error")
	}
}

func TestGitHubLoader_MultiApp_UsesCorrectProvider(t *testing.T) {
	policyYAML := `
issuer: https://iss.example.com
permissions:
  contents: read
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(policyYAML))
	}))
	defer srv.Close()

	// Create two providers — only app-b has a valid token.
	tpA := &mockTokenProvider{token: "", err: errForTest("app-a should not be called")}
	tpB := &mockTokenProvider{token: "ghs_correct"}
	tps := map[string]TokenProvider{"app-a": tpA, "app-b": tpB}

	loader := NewGitHubLoader(tps, nil, srv.URL, "", 5*time.Minute, nil, nil)

	// Load for app-b should use tpB, not tpA.
	policy, err := loader.Load(context.Background(), "myorg/myrepo", "app-b", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestGitHubLoader_UnknownApp(t *testing.T) {
	tps := map[string]TokenProvider{"app-a": &mockTokenProvider{token: "ghs_test"}}
	loader := NewGitHubLoader(tps, nil, "http://localhost", "", 5*time.Minute, nil, nil)

	_, err := loader.Load(context.Background(), "myorg/myrepo", "nonexistent", "ci")
	if err == nil {
		t.Fatal("expected error for unknown app")
	}
	if !strings.Contains(err.Error(), "no token provider configured for app") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type testErr string

func errForTest(msg string) error { return testErr(msg) }
func (e testErr) Error() string   { return string(e) }
