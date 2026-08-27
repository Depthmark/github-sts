package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
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

func TestAccessLogMiddleware_LogsSuppressedHealthFailureAtWarn(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	h := accessLogMiddleware(inner, slogger, true)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if !bytes.Contains(buf.Bytes(), []byte(`"level":"WARN"`)) {
		t.Errorf("expected WARN level for suppressed health 401, got: %s", buf.String())
	}
}

func TestAccessLogMiddleware_SuppressesReadyAndMetricsFailures(t *testing.T) {
	for _, tt := range []struct {
		path   string
		status int
	}{
		{path: "/ready", status: http.StatusServiceUnavailable},
		{path: "/metrics", status: http.StatusUnauthorized},
	} {
		t.Run(tt.path, func(t *testing.T) {
			var buf bytes.Buffer
			slogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			h := accessLogMiddleware(inner, slogger, true)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if buf.Len() != 0 {
				t.Errorf("expected suppressed log for %s status %d, got: %s", tt.path, tt.status, buf.String())
			}
		})
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

func TestNew_WiresEndpointAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cfg := &config.Settings{
		Server: config.ServerConfig{
			Host:            "127.0.0.1",
			Port:            8080,
			ShutdownTimeout: time.Second,
		},
		Apps: map[string]config.AppConfig{
			"test": {Instances: []config.AppInstanceConfig{{AppID: 1, ParsedKey: key}}},
		},
		OIDC: config.OIDCConfig{
			AllowedIssuers: []string{"https://issuer.example.com"},
		},
		JTI: config.JTIConfig{
			Backend: "memory",
			TTL:     time.Minute,
		},
		Policy: config.PolicyConfig{
			BasePath: ".github/sts",
			CacheTTL: time.Minute,
		},
		BundleEnforcement: config.BundleEnforcementOptional,
		Audit:             config.AuditConfig{BufferSize: 1},
		Health:            config.HealthConfig{AuthToken: "health-secret"},
		Metrics: config.MetricsConfig{
			Enabled:   true,
			AuthToken: "metrics-secret",
		},
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

	for _, tt := range []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
	}{
		{name: "health missing token", path: "/health", wantStatus: http.StatusUnauthorized},
		{name: "health valid token", path: "/health", authorization: "Bearer health-secret", wantStatus: http.StatusOK},
		{name: "ready remains unauthenticated", path: "/ready", wantStatus: http.StatusServiceUnavailable},
		{name: "metrics missing token", path: "/metrics", wantStatus: http.StatusUnauthorized},
		{name: "metrics valid token", path: "/metrics", authorization: "Bearer metrics-secret", wantStatus: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}

	defaultHealth := config.HealthConfig{}
	defaultMux := http.NewServeMux()
	defaultMux.Handle("GET /health", handler.OptionalBearerAuth(
		defaultHealth.AuthToken,
		"health",
		handler.HealthHandler(nil),
	))
	w := httptest.NewRecorder()
	defaultMux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("default health status = %d, want %d", w.Code, http.StatusOK)
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

// writeTestTLSFiles generates a self-signed server certificate and key and
// writes them to temporary files, returning their paths.
func writeTestTLSFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "github-sts"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certFile, keyFile
}

func TestBuildTLSConfig_Disabled(t *testing.T) {
	cfg := &config.Settings{}
	tlsCfg, reloader, err := buildTLSConfig(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if tlsCfg != nil {
		t.Error("expected nil TLS config when TLS is disabled")
	}
	if reloader != nil {
		t.Error("expected nil cert reloader when TLS is disabled")
	}
}

func TestBuildTLSConfig_ServerOnly(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile

	tlsCfg, reloader, err := buildTLSConfig(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if reloader == nil {
		t.Fatal("expected non-nil cert reloader")
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Errorf("expected empty Certificates (hot-reload uses GetCertificate), got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("min version = %d, want %d", tlsCfg.MinVersion, tls.VersionTLS12)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("client auth = %d, want NoClientCert", tlsCfg.ClientAuth)
	}
}

func TestBuildTLSConfig_WithClientCA(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile
	// Reuse the self-signed cert as the trusted client CA for the test.
	cfg.Server.TLS.ClientCAFile = certFile

	tlsCfg, _, err := buildTLSConfig(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("client auth = %d, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("expected non-nil client CA pool")
	}
}

func TestBuildTLSConfig_InvalidCert(t *testing.T) {
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = "/does/not/exist.crt"
	cfg.Server.TLS.KeyFile = "/does/not/exist.key"

	if _, _, err := buildTLSConfig(cfg, slog.Default()); err == nil {
		t.Error("expected error for invalid certificate paths")
	}
}

func TestBuildTLSConfig_InvalidClientCA(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile
	cfg.Server.TLS.ClientCAFile = "/does/not/exist/ca.crt"

	if _, _, err := buildTLSConfig(cfg, slog.Default()); err == nil {
		t.Error("expected error for invalid client CA path")
	}
}

func TestBuildTLSConfig_MinVersionTLS13(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile
	cfg.Server.TLS.MinVersion = "1.3"

	tlsCfg, _, err := buildTLSConfig(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("min version = %d, want %d", tlsCfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBuildTLSConfig_WithCipherSuites(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	cfg := &config.Settings{}
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile
	cfg.Server.TLS.CipherSuites = []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	tlsCfg, _, err := buildTLSConfig(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if len(tlsCfg.CipherSuites) != 2 {
		t.Errorf("cipher suites = %d, want 2", len(tlsCfg.CipherSuites))
	}
}

func TestCertReloader_GetCertificate(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	r, err := newCertReloader(certFile, keyFile, 0, slog.Default())
	if err != nil {
		t.Fatalf("newCertReloader() error: %v", err)
	}
	defer r.Stop()

	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestCertReloader_Load_UpdatesCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	writeTLSFilesToDir(t, dir, big.NewInt(1))
	r, err := newCertReloader(certFile, keyFile, 0, slog.Default())
	if err != nil {
		t.Fatalf("newCertReloader() error: %v", err)
	}
	defer r.Stop()

	firstCert, _ := r.GetCertificate(nil)
	firstDER := firstCert.Certificate[0]

	// Overwrite with a new cert (different serial).
	writeTLSFilesToDir(t, dir, big.NewInt(2))
	if err := r.load(); err != nil {
		t.Fatalf("load() error: %v", err)
	}

	secondCert, _ := r.GetCertificate(nil)
	secondDER := secondCert.Certificate[0]

	if string(firstDER) == string(secondDER) {
		t.Error("expected cert to differ after reload")
	}
}

func TestCertReloader_StopWithoutGoroutine(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	r, err := newCertReloader(certFile, keyFile, 0, slog.Default())
	if err != nil {
		t.Fatalf("newCertReloader() error: %v", err)
	}
	// Stop with no goroutine must not panic.
	r.Stop()
}

// writeTLSFilesToDir writes a self-signed cert+key with the given serial into dir.
func writeTLSFilesToDir(t *testing.T, dir string, serial *big.Int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "github-sts"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
}
