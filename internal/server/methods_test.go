package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/handler"
	"github.com/prometheus/client_golang/prometheus"
)

// TestNew_RefusedMethodsGetJSON405 goes through the handler chain New
// builds, so it proves what the mux routes, not only what each handler does
// on its own: a method pattern on a route would answer these with plain
// text before the handler ran.
func TestNew_RefusedMethodsGetJSON405(t *testing.T) {
	h := newRoutingTestHandler(t)
	endpoints := []struct {
		path  string
		allow string
	}{
		{path: "/sts/exchange", allow: "GET, POST"},
		{path: "/sts/v1/trust-policy/validate", allow: "POST"},
		{path: "/sts/v1/trust-policy.json", allow: "GET, HEAD"},
	}
	for _, endpoint := range endpoints {
		for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(method+" "+endpoint.path, func(t *testing.T) {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, endpoint.path, nil))

				if w.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusMethodNotAllowed, w.Body.String())
				}
				if got := w.Header().Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", got)
				}
				if got := w.Header().Get("Allow"); got != endpoint.allow {
					t.Errorf("Allow = %q, want %q", got, endpoint.allow)
				}
				var resp handler.ErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v; body=%q", err, w.Body.String())
				}
				if resp.Code != handler.CodeMethodNotAllowed {
					t.Errorf("code = %q, want %q", resp.Code, handler.CodeMethodNotAllowed)
				}
			})
		}
	}
}

// TestNew_AcceptedMethodsReachTheirHandler checks each accepted method gets
// its handler's own answer: a JSON code the mux never produces.
func TestNew_AcceptedMethodsReachTheirHandler(t *testing.T) {
	h := newRoutingTestHandler(t)
	tests := []struct {
		name   string
		method string
		path   string
		status int
		code   string
	}{
		{name: "exchange GET", method: http.MethodGet, path: "/sts/exchange", status: http.StatusBadRequest, code: handler.CodeBadRequest},
		{name: "exchange POST", method: http.MethodPost, path: "/sts/exchange", status: http.StatusBadRequest, code: handler.CodeBadRequest},
		{name: "validate POST", method: http.MethodPost, path: "/sts/v1/trust-policy/validate", status: http.StatusBadRequest, code: handler.CodeBadRequest},
		{name: "schema GET", method: http.MethodGet, path: "/sts/v1/trust-policy.json", status: http.StatusServiceUnavailable, code: "bundle_disabled"},
		{name: "schema HEAD", method: http.MethodHead, path: "/sts/v1/trust-policy.json", status: http.StatusServiceUnavailable, code: "bundle_disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			if w.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.status, w.Body.String())
			}
			var resp handler.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode body: %v; body=%q", err, w.Body.String())
			}
			if resp.Code != tt.code {
				t.Errorf("code = %q, want %q", resp.Code, tt.code)
			}
		})
	}
}

// newRoutingTestHandler builds the server's full handler chain with one App
// and no bundle, and shuts the server down when the test ends.
func newRoutingTestHandler(t *testing.T) http.Handler {
	t.Helper()
	// metrics.Register panics on a second call against one registry, and New
	// calls it, so every server here registers into its own.
	previousRegisterer := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = previousRegisterer })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cfg := &config.Settings{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8080, ShutdownTimeout: time.Second},
		Apps: map[string]config.AppConfig{
			"test": {Instances: []config.AppInstanceConfig{{AppID: 1, ParsedKey: key}}},
		},
		OIDC:              config.OIDCConfig{AllowedIssuers: []string{"https://issuer.example.com"}},
		JTI:               config.JTIConfig{Backend: "memory", TTL: time.Minute},
		Policy:            config.PolicyConfig{BasePath: ".github/sts", CacheTTL: time.Minute},
		BundleEnforcement: config.BundleEnforcementOptional,
		Audit:             config.AuditConfig{BufferSize: 1},
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}
	})
	return srv.httpServer.Handler
}
