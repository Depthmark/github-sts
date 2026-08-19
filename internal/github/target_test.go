package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRepositoryScope(t *testing.T) {
	scope, err := ParseRepositoryScope("Depthmark/github-sts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.Owner != "Depthmark" || scope.Repository != "github-sts" {
		t.Fatalf("unexpected scope: %+v", scope)
	}
}

func TestParseRepositoryScope_RejectsOrganizationScope(t *testing.T) {
	_, err := ParseRepositoryScope("Depthmark")
	if !errors.Is(err, ErrOrganizationScopeUnsupported) {
		t.Fatalf("error = %v, want ErrOrganizationScopeUnsupported", err)
	}
}

func TestParseRepositoryScope_RejectsMalformed(t *testing.T) {
	for _, scope := range []string{
		"", "/", "/repo", "org/", "org//repo", "org/repo/extra",
		".", "..", "org/.", "org/..", "org--name/repo", "org/repo name",
	} {
		t.Run(scope, func(t *testing.T) {
			if _, err := ParseRepositoryScope(scope); err == nil {
				t.Fatalf("expected %q to fail", scope)
			}
		})
	}
}

func TestAppTokenProvider_ResolveTarget(t *testing.T) {
	key := generateTestKey(t)
	requestCounts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			requestCounts["installation"]++
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			requestCounts["token"]++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if repositories, ok := body["repositories"].([]any); !ok || len(repositories) != 1 || repositories[0] != "github-sts" {
				t.Errorf("target-resolution repositories = %v", body["repositories"])
			}
			permissions, _ := body["permissions"].(map[string]any)
			if permissions["metadata"] != "read" {
				t.Errorf("target-resolution permissions = %v", permissions)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_lookup"})
		case r.URL.Path == "/repos/Depthmark/github-sts":
			requestCounts["repository"]++
			if r.Header.Get("Authorization") != "Bearer ghs_lookup" {
				t.Errorf("unexpected repository authorization header")
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": 1198676434, "name": "github-sts", "full_name": "Depthmark/github-sts",
				"owner": map[string]any{"id": 268749784, "login": "Depthmark"},
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-app", 12345, key, srv.URL, nil)
	scope := RepositoryScope{Owner: "Depthmark", Repository: "github-sts"}
	for range 2 {
		identity, err := p.ResolveTarget(context.Background(), scope)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if identity.Scope != "Depthmark/github-sts" || identity.OwnerID != "268749784" || identity.RepositoryID != "1198676434" {
			t.Fatalf("unexpected identity: %+v", identity)
		}
	}
	if requestCounts["installation"] != 1 || requestCounts["token"] != 1 || requestCounts["repository"] != 1 {
		t.Fatalf("expected one resolution sequence, got %v", requestCounts)
	}
}

func TestAppTokenProvider_ResolveTarget_RejectsNonCanonicalScope(t *testing.T) {
	srv := targetTestServer(t, "Depthmark", "github-sts", 268749784, 1198676434, nil)
	defer srv.Close()
	p := NewAppTokenProvider("test-app", "test-app", 12345, generateTestKey(t), srv.URL, nil)

	_, err := p.ResolveTarget(context.Background(), RepositoryScope{Owner: "depthmark", Repository: "github-sts"})
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("expected non-canonical scope error, got %v", err)
	}
}

func TestAppTokenProvider_ResolveTarget_RejectsInvalidIdentity(t *testing.T) {
	srv := targetTestServer(t, "Depthmark", "github-sts", 0, 1198676434, nil)
	defer srv.Close()
	p := NewAppTokenProvider("test-app", "test-app", 12345, generateTestKey(t), srv.URL, nil)

	_, err := p.ResolveTarget(context.Background(), RepositoryScope{Owner: "Depthmark", Repository: "github-sts"})
	if err == nil || !strings.Contains(err.Error(), "invalid immutable identity") {
		t.Fatalf("expected invalid identity error, got %v", err)
	}
}

func TestAppTokenProvider_GetInstallationTokenForTarget_UsesRepositoryID(t *testing.T) {
	var repositoryIDs []any
	srv := targetTestServer(t, "Depthmark", "github-sts", 268749784, 1198676434, func(body map[string]any) {
		repositoryIDs, _ = body["repository_ids"].([]any)
		if _, ok := body["repositories"]; ok {
			t.Error("repository names must not be sent for final target mint")
		}
	})
	defer srv.Close()
	p := NewAppTokenProvider("test-app", "test-app", 12345, generateTestKey(t), srv.URL, nil)

	token, _, err := p.GetInstallationTokenForTarget(context.Background(), TargetIdentity{
		Scope: "Depthmark/github-sts", RepositoryID: "1198676434",
	}, map[string]string{"contents": "read"}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_test" {
		t.Fatalf("token = %q", token)
	}
	if len(repositoryIDs) != 1 || repositoryIDs[0] != float64(1198676434) {
		t.Fatalf("repository_ids = %v", repositoryIDs)
	}
}

func targetTestServer(t *testing.T, owner, repository string, ownerID, repositoryID int64, inspectToken func(map[string]any)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if inspectToken != nil {
				inspectToken(body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_test"})
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": repositoryID, "name": repository, "full_name": owner + "/" + repository,
				"owner": map[string]any{"id": ownerID, "login": owner},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
