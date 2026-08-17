package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/handler"
)

func TestTraceIDMiddleware_SetsHeaderAndContext(t *testing.T) {
	var capturedTraceID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(handler.TraceIDKey).(string); ok {
			capturedTraceID = v
		}
		w.WriteHeader(200)
	})

	h := traceIDMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	headerID := w.Header().Get("X-Trace-ID")
	if headerID == "" {
		t.Error("X-Trace-ID header not set")
	}
	if capturedTraceID == "" {
		t.Error("trace ID not in context")
	}
	if headerID != capturedTraceID {
		t.Errorf("header %q != context %q", headerID, capturedTraceID)
	}
	if len(headerID) != 16 {
		t.Errorf("trace ID length = %d, want 16", len(headerID))
	}
}

func TestAccessLogMiddleware_LogsRequest(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	})

	h := accessLogMiddleware(inner, slogger, false)
	req := httptest.NewRequest(http.MethodPost, "/sts/exchange", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	logOutput := buf.String()
	if logOutput == "" {
		t.Error("no log output")
	}
	// Should contain key fields.
	for _, want := range []string{"method", "path", "status", "duration_ms"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("log missing field %q", want)
		}
	}
}

func TestAccessLogMiddleware_ErrorLevelOn5xx(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})

	h := accessLogMiddleware(inner, slogger, false)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !bytes.Contains(buf.Bytes(), []byte(`"level":"ERROR"`)) {
		t.Errorf("expected ERROR level for 500 response, got: %s", buf.String())
	}
}

func TestAccessLogMiddleware_WarnLevelOn4xx(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})

	h := accessLogMiddleware(inner, slogger, false)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !bytes.Contains(buf.Bytes(), []byte(`"level":"WARN"`)) {
		t.Errorf("expected WARN level for 403 response, got: %s", buf.String())
	}
}

func TestAccessLogMiddleware_SuppressHealthAtInfo(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	h := accessLogMiddleware(inner, slogger, true)

	// Health path should be logged at DEBUG, which is suppressed at INFO level.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if buf.Len() > 0 {
		t.Error("health path should be suppressed at INFO level")
	}

	// Non-health path should be logged.
	buf.Reset()
	req = httptest.NewRequest(http.MethodGet, "/sts/exchange", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if buf.Len() == 0 {
		t.Error("non-health path should be logged at INFO level")
	}
}

func TestStatusWriter_CapturesCode(t *testing.T) {
	w := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: w, status: 200}
	sw.WriteHeader(404)
	if sw.status != 404 {
		t.Errorf("status = %d, want 404", sw.status)
	}
}

func TestStatusWriter_DefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: w, status: 200}
	// Write without WriteHeader — status should remain 200.
	_, _ = sw.Write([]byte("hello"))
	if sw.status != 200 {
		t.Errorf("default status = %d, want 200", sw.status)
	}
}

func TestStatusWriter_DoubleWriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: w, status: 200}
	sw.WriteHeader(404)
	sw.WriteHeader(500) // Second call should be ignored.
	if sw.status != 404 {
		t.Errorf("status = %d, want 404 (first call)", sw.status)
	}
}

func TestGenerateTraceID(t *testing.T) {
	id := generateTraceID()
	if len(id) != 16 {
		t.Errorf("trace ID length = %d, want 16", len(id))
	}

	// Should be unique.
	id2 := generateTraceID()
	if id == id2 {
		t.Error("two trace IDs should be unique")
	}
}

func TestIsHealthPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/health", true},
		{"/ready", true},
		{"/metrics", true},
		{"/healthz", true},
		{"/readyz", true},
		{"/sts/exchange", false},
		{"/other", false},
	}
	for _, tt := range tests {
		if got := isHealthPath(tt.path); got != tt.want {
			t.Errorf("isHealthPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRoutePattern(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/sts/exchange", "/sts/exchange"},
		{"/sts/exchange?scope=x", "/sts/exchange"},
		{"/health", "/health"},
		{"/ready", "/ready"},
		{"/metrics", "/metrics"},
		{"/unknown", "other"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		if got := routePattern(req); got != tt.want {
			t.Errorf("routePattern(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestYAMLOnlyAuthorizationPossible(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Settings
		want bool
	}{
		{
			name: "optional no bundles",
			cfg: config.Settings{
				BundleEnforcement: config.BundleEnforcementOptional,
				Apps:              map[string]config.AppConfig{"app": {}},
			},
			want: true,
		},
		{
			name: "optional partial coverage",
			cfg: config.Settings{
				BundleEnforcement: config.BundleEnforcementOptional,
				Apps:              map[string]config.AppConfig{"covered": {}, "uncovered": {}},
				Bundles:           []config.BundleConfig{{Apps: []string{"covered"}}},
			},
			want: true,
		},
		{
			name: "optional complete scoped coverage",
			cfg: config.Settings{
				BundleEnforcement: config.BundleEnforcementOptional,
				Apps:              map[string]config.AppConfig{"one": {}, "two": {}},
				Bundles:           []config.BundleConfig{{Apps: []string{"one", "two"}}},
			},
		},
		{
			name: "optional global coverage",
			cfg: config.Settings{
				BundleEnforcement: config.BundleEnforcementOptional,
				Apps:              map[string]config.AppConfig{"one": {}, "two": {}},
				Bundles:           []config.BundleConfig{{Apps: nil}},
			},
		},
		{
			name: "required",
			cfg: config.Settings{
				BundleEnforcement: config.BundleEnforcementRequired,
				Apps:              map[string]config.AppConfig{"app": {}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := yamlOnlyAuthorizationPossible(&tt.cfg); got != tt.want {
				t.Fatalf("yamlOnlyAuthorizationPossible() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitBundleManager_WiresExpectedPolicyRevision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	writeServerTestBundle(t, path, "3")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := &config.Settings{
		BundleEnforcement: config.BundleEnforcementOptional,
		Bundles: []config.BundleConfig{{
			Name: "revision", Ref: "file://" + path, ExpectedPolicyRevision: "4",
			PollInterval: time.Minute, MaxStaleness: time.Minute, FailMode: config.BundleFailModeClosed,
		}},
	}
	_, lifecycle, err := initBundleManager(cfg, logger)
	if lifecycle != nil {
		lifecycle.Stop()
	}
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("expected policy revision \"4\" does not match bundle manifest revision \"3\"")) {
		t.Fatalf("initBundleManager error = %v, want wired revision mismatch", err)
	}
}

func writeServerTestBundle(t *testing.T, path, revision string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	files := map[string]string{
		"policies/policy.rego": `package sts.enterprise.server_test
import rego.v1
decision := {"allow": false, "reasons": ["deny"]}
`,
		".manifest": `{"revision":"` + revision + `"}`,
	}
	for name, body := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
