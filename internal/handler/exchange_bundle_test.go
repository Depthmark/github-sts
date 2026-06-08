package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	gh "github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
)

// discardSlogger drops all log output; tests don't care about log lines.
func discardSlogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// spyManager is a bundle.Manager fake that records every Eval call so a
// test can prove the engine was (or wasn't) consulted, and lets the
// test prescribe a Decision or an error per call.
type spyManager struct {
	enabled  bool
	digest   string
	decision bundle.Decision
	err      error

	calls atomic.Int32
	last  bundle.Input
}

func (m *spyManager) Eval(_ context.Context, in bundle.Input) (bundle.Decision, error) {
	m.calls.Add(1)
	m.last = in
	return m.decision, m.err
}
func (m *spyManager) Digest() string                    { return m.digest }
func (m *spyManager) Enabled() bool                     { return m.enabled }
func (m *spyManager) BundleFile(string) ([]byte, error) { return nil, bundle.ErrFileNotFound }
func (m *spyManager) BundleStatuses() []bundle.Status {
	return []bundle.Status{{Name: "test", Enabled: m.enabled, Digest: m.digest}}
}

// failOnHitServer is an httptest.Server that fails the test if any path
// is requested. Used to prove that the broker never reaches the GitHub
// API mint call when the bundle denies the request.
func failOnHitServer(t *testing.T, label string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("%s: GitHub API was hit (counter-validation failure): %s %s", label, r.Method, r.URL.Path)
	}))
}

// newBundleTestHandler constructs a handler driven past OIDC and policy
// straight to the bundle eval block. The validator stub injects synthetic
// claims; the policy loader returns an allow-everything-for-this-test
// policy; the bundle manager's behaviour is the test variable.
//
// The provider points at a fail-on-hit httptest.Server so any GitHub API
// call (mint) becomes a test failure. This is the counter-validation
// signal: when the bundle denies, we expect the spy server never to be
// hit; if it is, the test fails loudly.
func newBundleTestHandler(t *testing.T, mgr bundle.Manager) (*ExchangeHandler, *recordingAuditLogger, *httptest.Server) {
	t.Helper()
	githubSpy := failOnHitServer(t, "spy github API")
	t.Cleanup(githubSpy.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key gen: %v", err)
	}
	provider := gh.NewAppTokenProvider("test-app", 12345, key, githubSpy.URL, githubSpy.Client())

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     "repo:org/repo:ref:refs/heads/main",
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:       &mockJTICache{isNew: true},
		policyLoader:   &mockPolicyLoader{pol: pol},
		appProviders:   map[string]*gh.AppTokenProvider{"test-app": provider},
		allowedIssuers: []string{"https://token.actions.githubusercontent.com"},
		auditLogger:    al,
		slogger:        discardSlogger(),
		bundleManager:  mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss": "https://token.actions.githubusercontent.com",
				"sub": "repo:org/repo:ref:refs/heads/main",
				"aud": "https://example.test/sts",
				"jti": fmt.Sprintf("test-%d", time.Now().UnixNano()),
			}, nil
		},
	}
	return h, al, githubSpy
}

func bundleExchangeRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci&app=test-app", nil)
	req.Header.Set("Authorization", "Bearer fake-but-validator-accepts")
	return req
}

// TestExchange_BundleDeny_NoMintCall counter-validates that a bundle
// deny short-circuits before the GitHub mint. The fail-on-hit spy
// server proves the mint was never attempted; the response code and
// audit result prove the deny was surfaced correctly.
func TestExchange_BundleDeny_NoMintCall(t *testing.T) {
	mgr := &spyManager{
		enabled:  true,
		digest:   "sha256:test-digest",
		decision: bundle.Decision{Allow: false, Reasons: []string{"forbidden by org policy"}},
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Code != CodeOrgPolicyDenied {
		t.Errorf("error code = %q, want %q", resp.Code, CodeOrgPolicyDenied)
	}
	if mgr.calls.Load() != 1 {
		t.Errorf("bundle Eval calls = %d, want 1", mgr.calls.Load())
	}
	last := al.lastEvent()
	if last.Result != audit.ResultOrgPolicyDenied {
		t.Errorf("audit result = %q, want %q", last.Result, audit.ResultOrgPolicyDenied)
	}
	if last.BundleDigest != "sha256:test-digest" {
		t.Errorf("audit bundle_digest = %q, want sha256:test-digest", last.BundleDigest)
	}
	if last.OrgDecision == nil || last.OrgDecision.Allow {
		t.Errorf("audit org_decision should be deny, got %+v", last.OrgDecision)
	}
}

// TestExchange_BundleEngineError_FailsClosed counter-validates that an
// engine error becomes a 403 (not a 500, not a silent allow). A Rego
// compile bug in production must never accidentally allow tokens.
func TestExchange_BundleEngineError_FailsClosed(t *testing.T) {
	mgr := &spyManager{
		enabled: true,
		digest:  "sha256:err-digest",
		err:     errors.New("simulated engine error"),
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail-closed)", w.Code)
	}
	if got := al.lastEvent().Result; got != audit.ResultOrgPolicyDenied {
		t.Errorf("audit result = %q, want %q", got, audit.ResultOrgPolicyDenied)
	}
}

// TestExchange_BundleDisabled_NoEngineCall counter-validates that the
// Enabled() flag is the single switch — when false, the engine is
// never called and no bundle_digest appears in the audit. A bug that
// defaulted Enabled to true on a misconfigured manager would slip
// through any test that only checks behaviour when enabled is set.
func TestExchange_BundleDisabled_NoEngineCall(t *testing.T) {
	// Bypass the fail-on-hit spy and use a recording mock instead — in
	// disabled mode we *expect* the mint to be attempted; what we're
	// testing is that the bundle was skipped, not that mint was skipped.
	githubMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "mock mint failure", http.StatusInternalServerError)
	}))
	t.Cleanup(githubMock.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key gen: %v", err)
	}
	provider := gh.NewAppTokenProvider("test-app", 12345, key, githubMock.URL, githubMock.Client())

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     "repo:org/repo:ref:refs/heads/main",
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	mgr := &spyManager{enabled: false} // Disabled-shaped fake
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:       &mockJTICache{isNew: true},
		policyLoader:   &mockPolicyLoader{pol: pol},
		appProviders:   map[string]*gh.AppTokenProvider{"test-app": provider},
		allowedIssuers: []string{"https://token.actions.githubusercontent.com"},
		auditLogger:    al,
		slogger:        discardSlogger(),
		bundleManager:  mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss": "https://token.actions.githubusercontent.com",
				"sub": "repo:org/repo:ref:refs/heads/main",
				"aud": "https://example.test/sts",
				"jti": "test-disabled-1",
			}, nil
		},
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if mgr.calls.Load() != 0 {
		t.Errorf("bundle Eval calls when disabled = %d, want 0", mgr.calls.Load())
	}
	if al.lastEvent().BundleDigest != "" {
		t.Errorf("audit bundle_digest when disabled = %q, want empty", al.lastEvent().BundleDigest)
	}
	if al.lastEvent().OrgDecision != nil {
		t.Errorf("audit org_decision when disabled = %+v, want nil", al.lastEvent().OrgDecision)
	}
	_ = w.Code
}

// TestExchange_AuditFingerprint_OnAllowPath counter-validates that
// when the bundle allows, the audit event still carries the
// bundle_digest fingerprint — proving which bundle made the call. The
// spy server will be hit (it's the next step) so this test uses a
// recording server that returns 500 (mint fails) rather than fail-
// on-hit; what matters here is that the bundle digest is recorded
// before the mint attempt.
func TestExchange_AuditFingerprint_OnAllowPath(t *testing.T) {
	mintHit := atomic.Bool{}
	githubMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mintHit.Store(true)
		http.Error(w, "mock mint failure", http.StatusInternalServerError)
	}))
	t.Cleanup(githubMock.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key gen: %v", err)
	}
	provider := gh.NewAppTokenProvider("test-app", 12345, key, githubMock.URL, githubMock.Client())

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     "repo:org/repo:ref:refs/heads/main",
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	mgr := &spyManager{
		enabled:  true,
		digest:   "sha256:allow-digest",
		decision: bundle.Decision{Allow: true, Reasons: []string{"green-light"}},
	}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:       &mockJTICache{isNew: true},
		policyLoader:   &mockPolicyLoader{pol: pol},
		appProviders:   map[string]*gh.AppTokenProvider{"test-app": provider},
		allowedIssuers: []string{"https://token.actions.githubusercontent.com"},
		auditLogger:    al,
		slogger:        discardSlogger(),
		bundleManager:  mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss": "https://token.actions.githubusercontent.com",
				"sub": "repo:org/repo:ref:refs/heads/main",
				"aud": "https://example.test/sts",
				"jti": "test-allow-1",
			}, nil
		},
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if mgr.calls.Load() != 1 {
		t.Errorf("bundle Eval calls on allow path = %d, want 1", mgr.calls.Load())
	}
	if !mintHit.Load() {
		t.Errorf("expected mint to be attempted after bundle allow, but spy was not hit")
	}
	last := al.lastEvent()
	if last.BundleDigest != "sha256:allow-digest" {
		t.Errorf("audit bundle_digest on allow = %q, want sha256:allow-digest", last.BundleDigest)
	}
	if last.OrgDecision == nil || !last.OrgDecision.Allow {
		t.Errorf("audit org_decision should be allow with reasons, got %+v", last.OrgDecision)
	}
}

// TestExchange_BundleStale_503 counter-validates that ErrBundleStale
// from the manager surfaces as a 503 bundle_stale (not 403, not 500).
// Stale is a server-side dependency degradation, not a policy
// decision — clients should back off and retry, not surface the
// failure as an authorization error to end users.
func TestExchange_BundleStale_503(t *testing.T) {
	mgr := &spyManager{
		enabled: true,
		digest:  "sha256:stale-digest",
		err:     bundle.ErrBundleStale,
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing on stale 503")
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Code != CodeBundleStale {
		t.Errorf("error code = %q, want %q", resp.Code, CodeBundleStale)
	}
	last := al.lastEvent()
	if last.BundleDigest != "sha256:stale-digest" {
		t.Errorf("audit bundle_digest = %q, want sha256:stale-digest", last.BundleDigest)
	}
	if last.OrgDecision == nil || last.OrgDecision.Allow {
		t.Errorf("audit org_decision should be deny on stale, got %+v", last.OrgDecision)
	}
}

// TestExchange_BundleInputShape counter-validates that the handler
// builds a well-formed bundle.Input — mode is exchange, request fields
// are populated, claims and yaml_policy are passed through. A drift
// here would silently break the contract with github-sts-policy.
func TestExchange_BundleInputShape(t *testing.T) {
	mgr := &spyManager{
		enabled:  true,
		digest:   "sha256:shape-digest",
		decision: bundle.Decision{Allow: false, Reasons: []string{"shape-test"}},
	}
	h, _, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if mgr.calls.Load() != 1 {
		t.Fatalf("expected one Eval call, got %d", mgr.calls.Load())
	}
	in := mgr.last
	if in.Mode != bundle.ModeExchange {
		t.Errorf("input.Mode = %q, want %q", in.Mode, bundle.ModeExchange)
	}
	if in.Request.Scope != "org/repo" || in.Request.App != "test-app" || in.Request.Identity != "ci" {
		t.Errorf("input.Request = %+v, missing expected fields", in.Request)
	}
	if in.Claims["sub"] != "repo:org/repo:ref:refs/heads/main" {
		t.Errorf("input.Claims missing or wrong sub: %v", in.Claims["sub"])
	}
	if in.YAMLPolicy.Audience != "https://example.test/sts" {
		t.Errorf("input.YAMLPolicy.Audience = %q, want https://example.test/sts", in.YAMLPolicy.Audience)
	}
	if in.Requested == nil || in.Requested.Permissions["contents"] != "read" {
		t.Errorf("input.Requested malformed: %+v", in.Requested)
	}
}
