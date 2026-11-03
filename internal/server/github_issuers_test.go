package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/handler"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
)

const testEnterpriseIssuer = oidc.GitHubActionsIssuer + "/octocat-inc"

// fakeGitHubOIDC answers for token.actions.githubusercontent.com in this test,
// in the shape GitHub serves: discovery under the slug, one jwks_uri at the root
// of the host. The OIDC client refuses other hosts, so the test redirects the
// default transport's TLS dial here rather than using a test server URL.
func fakeGitHubOIDC(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/octocat-inc/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   testEnterpriseIssuer,
			"jwks_uri": oidc.GitHubActionsIssuer + "/.well-known/jwks",
		})
	})
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport is %T", http.DefaultTransport)
	}
	previous := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // local httptest server in a test
		return dialer.DialContext(ctx, network, srv.Listener.Addr().String())
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		transport.DialTLSContext = previous
	})
	oidc.ResetCacheForTesting()
	t.Cleanup(oidc.ResetCacheForTesting)
	return key
}

func enterpriseToken(t *testing.T, key *rsa.PrivateKey, repositoryID string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                 testEnterpriseIssuer,
		"sub":                 "repo:myorg@123456/source@456789:ref:refs/heads/main",
		"aud":                 "https://sts.example.com",
		"exp":                 now.Add(5 * time.Minute).Unix(),
		"iat":                 now.Unix(),
		"jti":                 "enterprise-jti-" + repositoryID,
		"repository":          "myorg/source",
		"repository_owner":    "myorg",
		"repository_id":       repositoryID,
		"repository_owner_id": "123456",
	})
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newDeclaredIssuerServer(t *testing.T, allowed []string, declared []config.GitHubIssuerConfig, logs io.Writer) *Server {
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
	instance := []config.AppInstanceConfig{{AppID: 1, ParsedKey: key}}
	cfg := &config.Settings{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8080, ShutdownTimeout: time.Second},
		Apps: map[string]config.AppConfig{
			"deploy": {Instances: instance},
			"other":  {Instances: instance},
		},
		OIDC:              config.OIDCConfig{AllowedIssuers: allowed, GitHubIssuers: declared},
		JTI:               config.JTIConfig{Backend: "memory", TTL: time.Minute},
		Policy:            config.PolicyConfig{BasePath: ".github/sts", CacheTTL: time.Minute},
		BundleEnforcement: config.BundleEnforcementOptional,
		Audit:             config.AuditConfig{BufferSize: 1},
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("Shutdown() error: %v", err)
		}
	})
	return srv
}

// TestNew_WiresDeclaredIssuers sends real signed tokens through the handler New
// builds, so it fails if a declaration stops reaching the exchange path.
func TestNew_WiresDeclaredIssuers(t *testing.T) {
	key := fakeGitHubOIDC(t)
	srv := newDeclaredIssuerServer(t,
		[]string{testEnterpriseIssuer},
		[]config.GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"deploy"}}},
		io.Discard,
	)

	tests := []struct {
		name         string
		app          string
		repositoryID string
		wantCode     string
	}{
		{name: "mismatched repository_id", app: "deploy", repositoryID: "999", wantCode: handler.CodeGitHubIdentityInvalid},
		{name: "valid token for an app that does not list the issuer", app: "other", repositoryID: "456789", wantCode: handler.CodeIssuerNotEnabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=myorg/target&identity=ci&app="+tt.app, nil)
			req.Header.Set("Authorization", "Bearer "+enterpriseToken(t, key, tt.repositoryID))
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			var body handler.ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", body.Code, tt.wantCode)
			}
		})
	}

	t.Run("health reports the issuer", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body struct {
			Security handler.SecurityPosture `json:"security"`
		}
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		issuers := body.Security.GitHubIssuers
		if len(issuers) != 1 || issuers[0].Issuer != testEnterpriseIssuer || issuers[0].Instance != oidc.GitHubDotComInstance || !issuers[0].RequireImmutableSubjectClaims {
			t.Fatalf("github_issuers = %+v", issuers)
		}
	})

	t.Run("policy validation accepts a github block for the issuer", func(t *testing.T) {
		policy := []byte(`issuer: ` + testEnterpriseIssuer + `
audience: https://sts.example.com
subject: repo:myorg@123456/source@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456790"
permissions:
  contents: read
`)
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewReader(policy)))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
	})
}

func TestNew_WarnsAboutAllowedButUndeclaredEnterpriseIssuer(t *testing.T) {
	const warning = "enterprise issuer is allowed but not declared"
	tests := []struct {
		name     string
		allowed  []string
		declared []config.GitHubIssuerConfig
		wantWarn bool
	}{
		{name: "allowed only", allowed: []string{testEnterpriseIssuer}, wantWarn: true},
		{
			name:     "declared",
			allowed:  []string{testEnterpriseIssuer},
			declared: []config.GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"deploy"}}},
		},
		{name: "default issuer", allowed: []string{oidc.GitHubActionsIssuer}},
		{name: "generic issuer", allowed: []string{"https://accounts.google.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			newDeclaredIssuerServer(t, tt.allowed, tt.declared, &logs)
			if got := strings.Contains(logs.String(), warning); got != tt.wantWarn {
				t.Fatalf("warning logged = %v, want %v; logs:\n%s", got, tt.wantWarn, logs.String())
			}
		})
	}
}
