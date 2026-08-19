package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

func TestAppTokenProvider_GenerateAppJWT(t *testing.T) {
	key := generateTestKey(t)
	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, "https://api.github.com", nil)
	jwt, err := p.GenerateAppJWT()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwt == "" {
		t.Fatal("expected non-empty JWT")
	}
}

func TestAppTokenProvider_GetInstallationID_OrgOnly(t *testing.T) {
	key := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should always use /orgs/{org}/installation.
		if !strings.Contains(r.URL.Path, "/orgs/") {
			t.Errorf("expected org endpoint, got %s", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "/repos/") {
			t.Errorf("should not call repo endpoint, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)

	// Repo-level scope should still use org endpoint.
	id, err := p.GetInstallationID(context.Background(), "myorg/myrepo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 42 {
		t.Fatalf("expected 42, got %d", id)
	}
}

func TestAppTokenProvider_GetInstallationID_Caching(t *testing.T) {
	key := generateTestKey(t)
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)

	_, _ = p.GetInstallationID(context.Background(), "myorg")
	_, _ = p.GetInstallationID(context.Background(), "myorg")

	if callCount != 1 {
		t.Fatalf("expected 1 API call (cached), got %d", callCount)
	}
}

func TestAppTokenProvider_GetInstallationToken_WithPermissions(t *testing.T) {
	key := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			// Verify the request body contains permissions.
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)

			perms, ok := body["permissions"].(map[string]any)
			if !ok {
				t.Error("expected permissions in body")
			}
			if perms["contents"] != "read" {
				t.Errorf("expected contents:read, got %v", perms["contents"])
			}

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_scoped"})
		}
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)

	token, err := p.GetInstallationToken(context.Background(), "myorg",
		map[string]string{"contents": "read"}, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_scoped" {
		t.Fatalf("unexpected token: %s", token)
	}
}

func TestAppTokenProvider_GetInstallationToken_RepoRestriction(t *testing.T) {
	key := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)

			repos, ok := body["repositories"].([]any)
			if !ok {
				t.Error("expected repositories in body for repo-level scope")
			}
			if len(repos) != 1 || repos[0] != "myrepo" {
				t.Errorf("expected [myrepo], got %v", repos)
			}

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_repo"})
		}
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)

	token, err := p.GetInstallationToken(context.Background(), "myorg/myrepo",
		map[string]string{"contents": "read"}, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_repo" {
		t.Fatalf("unexpected token: %s", token)
	}
}

func TestExtractRateLimitHeaders(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"X-Ratelimit-Limit":     {"5000"},
			"X-Ratelimit-Remaining": {"4999"},
			"X-Ratelimit-Used":      {"1"},
			"X-Ratelimit-Reset":     {"1711900000"},
			"X-Ratelimit-Resource":  {"core"},
		},
	}

	// Should not panic.
	ExtractRateLimitHeaders(resp, "test-app", "test-instance", "test")
}

func TestExtractRateLimitHeaders_403_PrimaryExceeded(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"X-Ratelimit-Remaining": {"0"},
			"X-Ratelimit-Limit":     {"5000"},
			"X-Ratelimit-Resource":  {"core"},
		},
	}

	// Should not panic — logs a warning.
	ExtractRateLimitHeaders(resp, "test-app", "test-instance", "test")
}

func TestExtractRateLimitHeaders_403_SecondaryLimit(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"Retry-After": {"60"},
		},
	}

	// Should not panic — logs a warning.
	ExtractRateLimitHeaders(resp, "test-app", "test-instance", "test")
}

func TestDiffPermissions(t *testing.T) {
	tests := []struct {
		name      string
		requested map[string]string
		granted   map[string]string
		want      map[string]string // permission → status
	}{
		{
			name:      "all ok",
			requested: map[string]string{"contents": "read"},
			granted:   map[string]string{"contents": "read", "metadata": "read"},
			want:      map[string]string{"contents": "ok"},
		},
		{
			name:      "granted exceeds requested",
			requested: map[string]string{"contents": "read"},
			granted:   map[string]string{"contents": "write"},
			want:      map[string]string{"contents": "ok"},
		},
		{
			name:      "insufficient",
			requested: map[string]string{"contents": "write"},
			granted:   map[string]string{"contents": "read"},
			want:      map[string]string{"contents": "insufficient"},
		},
		{
			name:      "missing",
			requested: map[string]string{"administration": "write"},
			granted:   map[string]string{"contents": "read"},
			want:      map[string]string{"administration": "missing"},
		},
		{
			name:      "mixed",
			requested: map[string]string{"contents": "write", "metadata": "read", "issues": "write"},
			granted:   map[string]string{"contents": "read", "metadata": "read"},
			want:      map[string]string{"contents": "insufficient", "issues": "missing", "metadata": "ok"},
		},
		{
			name:      "granted nil → unknown",
			requested: map[string]string{"contents": "read"},
			granted:   nil,
			want:      map[string]string{"contents": "unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := DiffPermissions(tt.requested, tt.granted)
			if len(diff) != len(tt.want) {
				t.Fatalf("len(diff) = %d, want %d (%v)", len(diff), len(tt.want), diff)
			}
			for _, e := range diff {
				if got := e.Status; got != tt.want[e.Permission] {
					t.Errorf("%s status = %q, want %q", e.Permission, got, tt.want[e.Permission])
				}
			}
			// Verify deterministic alphabetical ordering.
			for i := 1; i < len(diff); i++ {
				if diff[i-1].Permission > diff[i].Permission {
					t.Errorf("diff not sorted: %s before %s", diff[i-1].Permission, diff[i].Permission)
				}
			}
		})
	}
}

func TestAppTokenProvider_GetInstallationToken_422CapturesDiff(t *testing.T) {
	key := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			// Installation has only contents:read.
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 42,
				"permissions": map[string]string{
					"contents": "read",
					"metadata": "read",
				},
			})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			// Reject — caller asked for administration:write which isn't granted.
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"The permissions requested are not granted to this installation."}`))
		}
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)

	_, err := p.GetInstallationToken(context.Background(), "myorg/myrepo",
		map[string]string{"administration": "write", "contents": "write"}, nil, "test")
	if err == nil {
		t.Fatal("expected error from 422")
	}
	if !strings.Contains(err.Error(), "HTTP 422") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Granted permissions should now be cached and queryable for diff.
	granted := p.GetGrantedPermissions("myorg/myrepo")
	if granted == nil {
		t.Fatal("expected cached granted permissions, got nil")
	}
	if granted["contents"] != "read" || granted["metadata"] != "read" {
		t.Errorf("unexpected granted perms: %v", granted)
	}
	if _, found := granted["administration"]; found {
		t.Errorf("administration should not be in granted perms: %v", granted)
	}

	// And the diff should classify the failure correctly.
	diff := DiffPermissions(map[string]string{"administration": "write", "contents": "write"}, granted)
	if len(diff) != 2 {
		t.Fatalf("expected 2 diff entries, got %d", len(diff))
	}
	statuses := map[string]string{}
	for _, e := range diff {
		statuses[e.Permission] = e.Status
	}
	if statuses["administration"] != "missing" {
		t.Errorf("administration status = %q, want missing", statuses["administration"])
	}
	if statuses["contents"] != "insufficient" {
		t.Errorf("contents status = %q, want insufficient", statuses["contents"])
	}
}

func TestExtractOrg(t *testing.T) {
	tests := []struct {
		scope string
		want  string
	}{
		{"myorg", "myorg"},
		{"myorg/myrepo", "myorg"},
		{"myorg/sub/path", "myorg"},
	}

	for _, tt := range tests {
		got := extractOrg(tt.scope)
		if got != tt.want {
			t.Errorf("extractOrg(%q) = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

// --- TokenMintError retryability classification (design doc §5.2.1) ---
//
// This table is the contract AppPool's failover logic depends on, so it's
// tested directly against GetInstallationToken/GetInstallationID rather
// than only indirectly through pool-level behavior (see app_pool_test.go).

func TestGetInstallationToken_RetryabilityClassification(t *testing.T) {
	tests := []struct {
		name          string
		handler       http.HandlerFunc
		closeServer   bool // simulate a network/transport error
		wantRetryable bool
		wantStatus    int // 0 = don't check (transport error has no status)
	}{
		{
			name:          "403 primary rate limit exceeded",
			handler:       statusHandler(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}),
			wantRetryable: true,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "403 secondary/abuse rate limit",
			handler:       statusHandler(http.StatusForbidden, map[string]string{"Retry-After": "30"}),
			wantRetryable: true,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "bare 403 with neither rate-limit signal",
			handler:       statusHandler(http.StatusForbidden, nil),
			wantRetryable: false,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "5xx",
			handler:       statusHandler(http.StatusServiceUnavailable, nil),
			wantRetryable: true,
			wantStatus:    http.StatusServiceUnavailable,
		},
		{
			name:          "422 permission mismatch",
			handler:       statusHandler(http.StatusUnprocessableEntity, nil),
			wantRetryable: false,
			wantStatus:    http.StatusUnprocessableEntity,
		},
		{
			name:          "unrecognized future status",
			handler:       statusHandler(http.StatusTeapot, nil),
			wantRetryable: false,
			wantStatus:    http.StatusTeapot,
		},
		{
			name:          "network/transport error",
			closeServer:   true,
			wantRetryable: true,
			wantStatus:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.handler
			if handler == nil {
				handler = succeedHandler("unused")
			}
			srv := newMockGitHubServer(42, handler)
			apiURL := srv.URL
			if tt.closeServer {
				srv.Close()
			} else {
				defer srv.Close()
			}

			key := generateTestKey(t)
			p := NewAppTokenProvider("test-app", "test-instance", 12345, key, apiURL, nil)
			_, err := p.GetInstallationToken(context.Background(), "myorg/myrepo", map[string]string{"contents": "read"}, nil, "test")
			if err == nil {
				t.Fatal("expected an error")
			}
			var mintErr *TokenMintError
			if !errors.As(err, &mintErr) {
				t.Fatalf("expected *TokenMintError, got %T: %v", err, err)
			}
			if mintErr.Retryable != tt.wantRetryable {
				t.Errorf("Retryable = %v, want %v", mintErr.Retryable, tt.wantRetryable)
			}
			if tt.wantStatus != 0 && mintErr.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", mintErr.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestFetchInstallationID_FailuresAreRetryable(t *testing.T) {
	// Every fetchInstallationID failure is a property of this specific
	// instance's credentials/installation — another pool member's
	// independent credentials may well succeed where this one didn't (see
	// design doc §5.6). Unlike GetInstallationToken's 422, there is no
	// "retrying elsewhere can't help" case here.
	tests := []struct {
		name   string
		status int
	}{
		{"not installed", http.StatusNotFound},
		{"auth failed", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
		{"server error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			key := generateTestKey(t)
			p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)
			_, err := p.GetInstallationID(context.Background(), "myorg")
			if err == nil {
				t.Fatal("expected an error")
			}
			var mintErr *TokenMintError
			if !errors.As(err, &mintErr) {
				t.Fatalf("expected *TokenMintError, got %T: %v", err, err)
			}
			if !mintErr.Retryable {
				t.Errorf("Retryable = false for HTTP %d, want true", tt.status)
			}
		})
	}
}

func TestFetchInstallationID_TransportErrorIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // already closed — every request is a transport error

	key := generateTestKey(t)
	p := NewAppTokenProvider("test-app", "test-instance", 12345, key, srv.URL, nil)
	_, err := p.GetInstallationID(context.Background(), "myorg")
	if err == nil {
		t.Fatal("expected an error")
	}
	var mintErr *TokenMintError
	if !errors.As(err, &mintErr) {
		t.Fatalf("expected *TokenMintError, got %T: %v", err, err)
	}
	if !mintErr.Retryable {
		t.Error("expected Retryable = true for a transport error")
	}
}
