package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

// vaultRefusal stands in for a key held in a vault that refuses to sign.
type vaultRefusal struct{}

func (vaultRefusal) SignRS256(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("azure key vault: signing with https://example.vault.azure.net/keys/checkout-1: HTTP 403 Forbidden")
}

func TestExchange_KeyThatCannotSignIsAnUpstreamError(t *testing.T) {
	oidcProvider := newOIDCTestProvider(t)

	var githubCalls int
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		githubCalls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ghSrv.Close()

	credential := github.NewAppCredentialSource("checkout", "checkout-1", 1, vaultRefusal{})
	pool := github.NewAppPool("checkout",
		[]github.PoolMember{{Instance: "checkout-1", Provider: github.NewAppTokenProvider(credential, ghSrv.URL, nil)}},
		"round_robin", 0, 1, nil,
	)

	var logs bytes.Buffer
	al := &recordingAuditLogger{}
	h := NewExchangeHandler(
		&mockJTICache{isNew: true},
		&mockPolicyLoader{pol: &policy.TrustPolicy{
			Issuer:      oidcProvider.srv.URL,
			Audience:    "test-audience",
			Subject:     "repo:myorg/myrepo:ref:refs/heads/main",
			Permissions: map[string]string{"contents": "read"},
		}},
		map[string]github.ExchangeApp{"checkout": pool},
		[]string{oidcProvider.srv.URL},
		"",
		false,
		al,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		false,
		nil,
	)

	now := time.Now()
	token := oidcProvider.sign(t, jwt.MapClaims{
		"iss": oidcProvider.srv.URL,
		"sub": "repo:myorg/myrepo:ref:refs/heads/main",
		"aud": "test-audience",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "test-jti-signer",
	})
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=myorg/myrepo&identity=ci&app=checkout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body = %s", w.Code, w.Body.String())
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Code != CodeUpstream || resp.TraceID == "" {
		t.Fatalf("response = %+v, want code %s with a trace_id", resp, CodeUpstream)
	}
	if githubCalls != 0 {
		t.Errorf("GitHub received %d requests although no App JWT could be signed", githubCalls)
	}

	event := al.lastEvent()
	if event.Result != audit.ResultGitHubError {
		t.Errorf("audit result = %q, want %q", event.Result, audit.ResultGitHubError)
	}
	logged := logs.String() + event.ErrorReason
	for _, want := range []string{`instance \"checkout-1\"`, "https://example.vault.azure.net/keys/checkout-1"} {
		if !strings.Contains(logged, want) {
			t.Errorf("logs and audit do not name %s:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, "eyJ") {
		t.Errorf("a JWT reached the logs or the audit record:\n%s", logged)
	}
}
