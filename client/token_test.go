package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestNewAppTokenProvider_ValidPEM(t *testing.T) {
	pemData := generateTestPEM(t)
	p, err := NewAppTokenProvider(12345, pemData, "myorg", "https://api.github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewAppTokenProvider_InvalidPEM(t *testing.T) {
	_, err := NewAppTokenProvider(12345, []byte("not-a-pem"), "myorg", "https://api.github.com")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "parsing RSA private key") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestNewAppTokenProvider_WithHTTPClient(t *testing.T) {
	pemData := generateTestPEM(t)
	custom := &http.Client{Timeout: 30 * time.Second}
	p, err := NewAppTokenProvider(12345, pemData, "myorg", "https://api.github.com", WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.httpClient != custom {
		t.Fatal("expected custom HTTP client to be set")
	}
}

func TestAppTokenProvider_Token_HappyPath(t *testing.T) {
	pemData := generateTestPEM(t)

	installationCalled := false
	tokenCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer auth on %s %s", r.Method, r.URL.Path)
		}
		accept := r.Header.Get("Accept")
		if accept != "application/vnd.github+json" {
			t.Errorf("unexpected Accept header: %s", accept)
		}

		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/installation"):
			installationCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			tokenCalled = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_test123"})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p, err := NewAppTokenProvider(12345, pemData, "myorg", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_test123" {
		t.Fatalf("unexpected token: %s", token)
	}
	if !installationCalled {
		t.Error("installation ID was not resolved")
	}
	if !tokenCalled {
		t.Error("token creation was not called")
	}
}

func TestAppTokenProvider_Token_LazyInstallationID(t *testing.T) {
	pemData := generateTestPEM(t)
	installationCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			installationCalls++
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_tok"})
		}
	}))
	defer srv.Close()

	p, err := NewAppTokenProvider(12345, pemData, "myorg", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First call resolves installation ID.
	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("first Token() call: %v", err)
	}
	if installationCalls != 1 {
		t.Fatalf("expected 1 installation call, got %d", installationCalls)
	}

	// Second call reuses cached ID.
	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("second Token() call: %v", err)
	}
	if installationCalls != 1 {
		t.Fatalf("expected still 1 installation call, got %d", installationCalls)
	}
}

func TestAppTokenProvider_Token_404Retry(t *testing.T) {
	pemData := generateTestPEM(t)
	tokenAttempts := 0
	installationCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			installationCalls++
			newID := int64(42)
			if installationCalls > 1 {
				newID = 99 // New installation ID after reinstall.
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": newID})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			tokenAttempts++
			if tokenAttempts == 1 {
				// First attempt with stale ID returns 404.
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_retried"})
		}
	}))
	defer srv.Close()

	p, err := NewAppTokenProvider(12345, pemData, "myorg", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Pre-cache a stale installation ID.
	p.installationID = 42

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_retried" {
		t.Fatalf("unexpected token: %s", token)
	}
	if tokenAttempts != 2 {
		t.Fatalf("expected 2 token attempts, got %d", tokenAttempts)
	}
	if installationCalls != 1 {
		t.Fatalf("expected 1 re-resolution call, got %d", installationCalls)
	}
}

func TestAppTokenProvider_Token_ContextCancelled(t *testing.T) {
	pemData := generateTestPEM(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the request context is done.
		<-r.Context().Done()
	}))
	defer srv.Close()

	p, err := NewAppTokenProvider(12345, pemData, "myorg", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err = p.Token(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestSTSTokenProvider_Token_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/sts/exchange") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("scope") != "myorg/myrepo" {
			t.Errorf("unexpected scope: %s", q.Get("scope"))
		}
		if q.Get("identity") != "ci" {
			t.Errorf("unexpected identity: %s", q.Get("identity"))
		}
		if q.Get("app") != "default" {
			t.Errorf("unexpected app: %s", q.Get("app"))
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer fake-sa-token" {
			t.Errorf("unexpected auth: %s", auth)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_sts_tok"})
	}))
	defer srv.Close()

	// Write a temporary SA token file.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("fake-sa-token"), 0600); err != nil {
		t.Fatalf("writing temp token: %v", err)
	}

	p := &STSTokenProvider{
		STSURL:      srv.URL,
		Identity:    "ci",
		Scope:       "myorg/myrepo",
		SATokenPath: tokenPath,
	}

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_sts_tok" {
		t.Fatalf("unexpected token: %s", token)
	}
}

func TestSTSTokenProvider_Token_WithAudience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("audience") != "my-audience" {
			t.Errorf("expected audience=my-audience, got %s", q.Get("audience"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_aud"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token"), 0600); err != nil {
		t.Fatalf("writing temp token: %v", err)
	}

	p := &STSTokenProvider{
		STSURL:      srv.URL,
		Identity:    "ci",
		Scope:       "myorg",
		Audience:    "my-audience",
		SATokenPath: tokenPath,
	}

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ghs_aud" {
		t.Fatalf("unexpected token: %s", token)
	}
}

func TestSTSTokenProvider_Token_DefaultAppName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("app") != "default" {
			t.Errorf("expected app=default, got %s", r.URL.Query().Get("app"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa"), 0600); err != nil {
		t.Fatalf("writing temp token: %v", err)
	}

	p := &STSTokenProvider{
		STSURL:      srv.URL,
		Identity:    "ci",
		Scope:       "myorg",
		App:         "", // Empty — should default to "default".
		SATokenPath: tokenPath,
	}

	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSTSTokenProvider_Token_FileReadError(t *testing.T) {
	p := &STSTokenProvider{
		STSURL:      "http://localhost",
		Identity:    "ci",
		Scope:       "myorg",
		SATokenPath: "/nonexistent/path/token",
	}

	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for missing SA token file")
	}
	if !strings.Contains(err.Error(), "reading service account token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSTSTokenProvider_SetHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 30 * time.Second}
	p := &STSTokenProvider{}
	p.SetHTTPClient(custom)
	if p.httpClient != custom {
		t.Fatal("expected custom HTTP client to be set")
	}
}
