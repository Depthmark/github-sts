package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
	p := NewAppTokenProvider("test-app", 12345, key, "https://api.github.com", nil)
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

	p := NewAppTokenProvider("test-app", 12345, key, srv.URL, nil)

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

	p := NewAppTokenProvider("test-app", 12345, key, srv.URL, nil)

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

	p := NewAppTokenProvider("test-app", 12345, key, srv.URL, nil)

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

	p := NewAppTokenProvider("test-app", 12345, key, srv.URL, nil)

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
	ExtractRateLimitHeaders(resp, "test-app", "test")
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
	ExtractRateLimitHeaders(resp, "test-app", "test")
}

func TestExtractRateLimitHeaders_403_SecondaryLimit(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"Retry-After": {"60"},
		},
	}

	// Should not panic — logs a warning.
	ExtractRateLimitHeaders(resp, "test-app", "test")
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
