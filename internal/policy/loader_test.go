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
// The default resolution mode is org_first when an org policy repo is set;
// pass mode="" to take that default, or override with an explicit mode.
func testLoader(tp TokenProvider, apiURL, orgPolicyRepo string, cacheTTL time.Duration) *GitHubPolicyLoader {
	return testLoaderWithMode(tp, apiURL, orgPolicyRepo, "", cacheTTL)
}

func testLoaderWithMode(tp TokenProvider, apiURL, orgPolicyRepo string, mode Resolution, cacheTTL time.Duration) *GitHubPolicyLoader {
	tps := map[string]TokenProvider{"default": tp}
	repos := map[string]string{}
	if orgPolicyRepo != "" {
		repos["default"] = orgPolicyRepo
	}
	modes := map[string]Resolution{}
	if mode != "" {
		modes["default"] = mode
	} else if orgPolicyRepo != "" {
		modes["default"] = ResolutionOrgFirst
	}
	return NewGitHubLoader(tps, repos, modes, apiURL, "", cacheTTL, nil, nil)
}

func TestGitHubLoader_RepoLevel(t *testing.T) {
	policyYAML := `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/myrepo:.*"
audience: https://sts.example.com
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
	// repo_first mode preserves the original assertion that the requesting
	// repo is fetched first. Under the new default (org_first) the org
	// policy repo would be probed first; that path is covered by the
	// resolution-matrix tests below.
	loader := testLoaderWithMode(tp, srv.URL, "sts-policies", ResolutionRepoFirst, 5*time.Minute)

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
audience: https://sts.example.com
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

// In repo_first (legacy) mode, repo-local is tried first and falls back to
// the org policy repo on 404. Preserved for backwards compatibility.
func TestGitHubLoader_RepoFirst_FallsBackToOrgPolicyRepo(t *testing.T) {
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
	loader := testLoaderWithMode(tp, srv.URL, "sts-policies", ResolutionRepoFirst, 5*time.Minute)

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
audience: https://sts.example.com
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
audience: https://sts.example.com
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

	loader := NewGitHubLoader(tps, nil, nil, srv.URL, "", 5*time.Minute, nil, nil)

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
	loader := NewGitHubLoader(tps, nil, nil, "http://localhost", "", 5*time.Minute, nil, nil)

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

// fakeRepoMux serves policy files keyed by repo path. A nil/missing entry
// returns 404, mimicking GitHub's "file not found" response. Records the
// path of every request for call-order assertions.
type fakeRepoMux struct {
	files     map[string]string // repo path fragment ("myorg/myrepo/") → policy YAML body
	requested []string
}

func (f *fakeRepoMux) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requested = append(f.requested, r.URL.Path)
		for prefix, body := range f.files {
			if strings.Contains(r.URL.Path, prefix) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

const samplePolicyYAML = `
issuer: https://token.actions.githubusercontent.com
subject_pattern: "repo:myorg/.*"
permissions:
  contents: read
`

// TestPolicyResolution_Matrix walks every (mode × repo-file × org-file)
// combination and asserts the loader picks the correct source, sets
// centralized correctly, and (for org_first / org_only) does NOT fetch the
// repo-local file when the org has it.
func TestPolicyResolution_Matrix(t *testing.T) {
	const (
		repoPrefix = "/repos/myorg/myrepo/contents/"
		orgPrefix  = "/repos/myorg/sts-policies/contents/"
	)

	type expect struct {
		policyFound bool
		centralized bool
		// requestedPaths lists URL substrings expected to be hit, in order.
		// Use exact prefixes (repoPrefix/orgPrefix). An empty slice means
		// "exactly zero requests."
		requestedPaths []string
	}

	cases := []struct {
		name      string
		mode      Resolution
		repoHas   bool
		orgHas    bool
		want      expect
		wantError bool
	}{
		// ─── org_first ──────────────────────────────────────────────────
		{
			name: "org_first/both_present_org_wins",
			mode: ResolutionOrgFirst, repoHas: true, orgHas: true,
			want: expect{policyFound: true, centralized: true, requestedPaths: []string{orgPrefix}},
		},
		{
			name: "org_first/only_repo_falls_back",
			mode: ResolutionOrgFirst, repoHas: true, orgHas: false,
			want: expect{policyFound: true, centralized: false, requestedPaths: []string{orgPrefix, repoPrefix}},
		},
		{
			name: "org_first/only_org",
			mode: ResolutionOrgFirst, repoHas: false, orgHas: true,
			want: expect{policyFound: true, centralized: true, requestedPaths: []string{orgPrefix}},
		},
		{
			name: "org_first/neither",
			mode: ResolutionOrgFirst, repoHas: false, orgHas: false,
			want: expect{policyFound: false, requestedPaths: []string{orgPrefix, repoPrefix}},
		},

		// ─── repo_first (legacy) ────────────────────────────────────────
		{
			name: "repo_first/both_present_repo_wins",
			mode: ResolutionRepoFirst, repoHas: true, orgHas: true,
			want: expect{policyFound: true, centralized: false, requestedPaths: []string{repoPrefix}},
		},
		{
			name: "repo_first/only_repo",
			mode: ResolutionRepoFirst, repoHas: true, orgHas: false,
			want: expect{policyFound: true, centralized: false, requestedPaths: []string{repoPrefix}},
		},
		{
			name: "repo_first/only_org_falls_back",
			mode: ResolutionRepoFirst, repoHas: false, orgHas: true,
			want: expect{policyFound: true, centralized: true, requestedPaths: []string{repoPrefix, orgPrefix}},
		},
		{
			name: "repo_first/neither",
			mode: ResolutionRepoFirst, repoHas: false, orgHas: false,
			want: expect{policyFound: false, requestedPaths: []string{repoPrefix, orgPrefix}},
		},

		// ─── org_only (strict) ──────────────────────────────────────────
		{
			name: "org_only/both_present_org_wins_repo_never_fetched",
			mode: ResolutionOrgOnly, repoHas: true, orgHas: true,
			want: expect{policyFound: true, centralized: true, requestedPaths: []string{orgPrefix}},
		},
		{
			name: "org_only/only_repo_denied",
			mode: ResolutionOrgOnly, repoHas: true, orgHas: false,
			want: expect{policyFound: false, requestedPaths: []string{orgPrefix}},
		},
		{
			name: "org_only/only_org",
			mode: ResolutionOrgOnly, repoHas: false, orgHas: true,
			want: expect{policyFound: true, centralized: true, requestedPaths: []string{orgPrefix}},
		},
		{
			name: "org_only/neither",
			mode: ResolutionOrgOnly, repoHas: false, orgHas: false,
			want: expect{policyFound: false, requestedPaths: []string{orgPrefix}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.repoHas {
				files["myorg/myrepo/"] = samplePolicyYAML
			}
			if tc.orgHas {
				files["myorg/sts-policies/"] = samplePolicyYAML
			}
			fake := &fakeRepoMux{files: files}
			srv := httptest.NewServer(fake.handler(t))
			defer srv.Close()

			tp := &mockTokenProvider{token: "ghs_test"}
			loader := testLoaderWithMode(tp, srv.URL, "sts-policies", tc.mode, 5*time.Minute)

			pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if (pol != nil) != tc.want.policyFound {
				t.Fatalf("policy found=%v, want %v", pol != nil, tc.want.policyFound)
			}
			if pol != nil && pol.Centralized() != tc.want.centralized {
				t.Errorf("centralized=%v, want %v", pol.Centralized(), tc.want.centralized)
			}

			// Verify the call order matches expectations exactly. This
			// catches modes that probe the wrong source first.
			if len(fake.requested) != len(tc.want.requestedPaths) {
				t.Fatalf("got %d requests %v, want %d %v",
					len(fake.requested), fake.requested,
					len(tc.want.requestedPaths), tc.want.requestedPaths)
			}
			for i, want := range tc.want.requestedPaths {
				if !strings.Contains(fake.requested[i], want) {
					t.Errorf("request %d = %q, want substring %q",
						i, fake.requested[i], want)
				}
			}
		})
	}
}

// TestPolicyResolution_OrgFirst_DoesNotFetchRepoOnHit makes the
// security-critical assertion explicit: when the org has the file in
// org_first mode, the repo is NEVER probed. A repo owner cannot trigger a
// policy fetch against their own repo as a side channel.
func TestPolicyResolution_OrgFirst_DoesNotFetchRepoOnHit(t *testing.T) {
	fake := &fakeRepoMux{files: map[string]string{
		"myorg/myrepo/":      samplePolicyYAML, // would shadow under repo_first
		"myorg/sts-policies/": samplePolicyYAML,
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoaderWithMode(tp, srv.URL, "sts-policies", ResolutionOrgFirst, 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol == nil || !pol.Centralized() {
		t.Fatal("org_first with both files: policy must be from org repo (centralized=true)")
	}
	for _, p := range fake.requested {
		if strings.Contains(p, "myorg/myrepo/") {
			t.Errorf("repo-local must not be fetched when org has the file; saw %s", p)
		}
	}
	for _, scope := range tp.scopes {
		if scope == "myorg/myrepo" {
			t.Errorf("repo-local installation token must not be minted; saw scope %q", scope)
		}
	}
}

// TestPolicyResolution_OrgOnly_NeverFallsBack asserts org_only does not
// silently fall through to repo-local when the org file is missing.
func TestPolicyResolution_OrgOnly_NeverFallsBack(t *testing.T) {
	fake := &fakeRepoMux{files: map[string]string{
		"myorg/myrepo/": samplePolicyYAML, // would otherwise be a fallback
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoaderWithMode(tp, srv.URL, "sts-policies", ResolutionOrgOnly, 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol != nil {
		t.Fatal("org_only must not fall back to repo-local")
	}
	for _, p := range fake.requested {
		if strings.Contains(p, "myorg/myrepo/") {
			t.Errorf("repo-local must not be fetched in org_only mode; saw %s", p)
		}
	}
}

// TestPolicyResolution_DefaultIsOrgFirst confirms the loader applies
// org_first when no mode is set explicitly.
func TestPolicyResolution_DefaultIsOrgFirst(t *testing.T) {
	fake := &fakeRepoMux{files: map[string]string{
		"myorg/myrepo/":      samplePolicyYAML,
		"myorg/sts-policies/": samplePolicyYAML,
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	// Pass empty mode — the helper still seeds org_first via the default
	// branch, mirroring how config.Validate populates the field.
	loader := testLoader(tp, srv.URL, "sts-policies", 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol == nil || !pol.Centralized() {
		t.Fatal("default mode must behave like org_first (org wins on collision)")
	}
}

// TestPolicyResolution_NoOrgRepo_RepoOnly verifies that with no org policy
// repo configured, only the requesting repo is consulted regardless of mode.
func TestPolicyResolution_NoOrgRepo_RepoOnly(t *testing.T) {
	fake := &fakeRepoMux{files: map[string]string{
		"myorg/myrepo/": samplePolicyYAML,
	}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	tp := &mockTokenProvider{token: "ghs_test"}
	loader := testLoader(tp, srv.URL, "", 5*time.Minute)

	pol, err := loader.Load(context.Background(), "myorg/myrepo", "default", "ci")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol == nil {
		t.Fatal("expected policy from requesting repo")
	}
	if pol.Centralized() {
		t.Error("repo-only fetch must not be marked centralized")
	}
	if len(fake.requested) != 1 {
		t.Fatalf("expected exactly 1 fetch (repo only), got %d: %v",
			len(fake.requested), fake.requested)
	}
}
