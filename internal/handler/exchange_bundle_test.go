package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
)

const bundleTestSubject = "repo:org@1001/repo@2002:ref:refs/heads/main"

func bundleTestClaims(jtiValue string) oidc.Claims {
	return oidc.Claims{
		"iss":                 oidc.GitHubActionsIssuer,
		"sub":                 bundleTestSubject,
		"aud":                 "https://example.test/sts",
		"jti":                 jtiValue,
		"repository":          "org/repo",
		"repository_owner":    "org",
		"repository_id":       "2002",
		"repository_owner_id": "1001",
	}
}

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
func (m *spyManager) Enforcement() string               { return bundle.EnforcementOptional }
func (m *spyManager) BundleFile(string) ([]byte, error) { return nil, bundle.ErrFileNotFound }
func (m *spyManager) BundleStatuses() []bundle.Status {
	return []bundle.Status{{Name: "test", Enabled: m.enabled, Digest: m.digest}}
}

// newBundleTestHandler constructs a handler driven past OIDC and policy
// straight to the bundle eval block. The validator stub injects synthetic
// claims; the policy loader returns an allow-everything-for-this-test
// policy; the bundle manager's behaviour is the test variable.
//
// The fake App records target resolution and final mint separately so tests
// can prove a bundle denial occurs after resolution but before minting.
func newBundleTestHandler(t *testing.T, mgr bundle.Manager) (*ExchangeHandler, *recordingAuditLogger, *mockExchangeApp) {
	t.Helper()
	provider := &mockExchangeApp{}

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     bundleTestSubject,
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
		GitHub: &policy.GitHubPolicy{
			Sources: []policy.GitHubRepository{{OwnerID: "1001", RepositoryID: "2002"}},
			Target:  policy.GitHubRepository{OwnerID: "1001", RepositoryID: "2002"},
		},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  &mockPolicyLoader{pol: pol},
		appProviders:                  map[string]github.ExchangeApp{"test-app": provider},
		allowedIssuers:                []string{"https://token.actions.githubusercontent.com"},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		slogger:                       discardSlogger(),
		bundleManager:                 mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return bundleTestClaims(fmt.Sprintf("test-%d", time.Now().UnixNano())), nil
		},
	}
	return h, al, provider
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
		enabled: true,
		digest:  "sha256:test-digest",
		decision: bundle.Decision{
			Applicable: true, Evaluated: true, EvaluatedDigest: "sha256:test-digest",
			Allow: false, Reasons: []string{"forbidden by org policy"},
		},
	}
	h, al, provider := newBundleTestHandler(t, mgr)

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
	if provider.resolveCalls != 1 || provider.mintCalls != 0 {
		t.Errorf("resolve calls=%d mint calls=%d, want 1 and 0", provider.resolveCalls, provider.mintCalls)
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
// engine error becomes a retryable 503 (not a policy denial or silent allow). A Rego
// compile bug in production must never accidentally allow tokens.
func TestExchange_BundleEngineError_FailsClosed(t *testing.T) {
	mgr := &spyManager{
		enabled:  true,
		digest:   "sha256:err-digest",
		decision: bundle.Decision{Applicable: true, SnapshotDigest: "sha256:err-digest"},
		err:      errors.New("simulated engine error"),
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed)", w.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Code != CodeBundleEvaluationFailed {
		t.Errorf("error code = %q, want %q", resp.Code, CodeBundleEvaluationFailed)
	}
	if got := al.lastEvent().Result; got != audit.ResultBundleEvaluationFailed {
		t.Errorf("audit result = %q, want %q", got, audit.ResultBundleEvaluationFailed)
	}
}

func TestExchange_BundleUnavailable_503(t *testing.T) {
	mgr := &spyManager{
		enabled: true,
		digest:  "sha256:unavailable-digest",
		err:     bundle.ErrBundleUnavailable,
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Code != CodeBundleUnavailable {
		t.Errorf("error code = %q, want %q", resp.Code, CodeBundleUnavailable)
	}
	if got := al.lastEvent().Result; got != audit.ResultBundleUnavailable {
		t.Errorf("audit result = %q, want %q", got, audit.ResultBundleUnavailable)
	}
}

// TestExchange_BundleDisabled_NoEngineCall counter-validates that the
// Enabled() flag is the single switch — when false, the engine is
// never called and no bundle_digest appears in the audit. A bug that
// defaulted Enabled to true on a misconfigured manager would slip
// through any test that only checks behaviour when enabled is set.
func TestExchange_BundleDisabled_NoEngineCall(t *testing.T) {
	provider := &mockExchangeApp{mintErr: errors.New("mock mint failure")}

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     bundleTestSubject,
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
		GitHub: &policy.GitHubPolicy{
			Sources: []policy.GitHubRepository{{OwnerID: "1001", RepositoryID: "2002"}},
			Target:  policy.GitHubRepository{OwnerID: "1001", RepositoryID: "2002"},
		},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	mgr := &spyManager{enabled: false} // Disabled-shaped fake
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  &mockPolicyLoader{pol: pol},
		appProviders:                  map[string]github.ExchangeApp{"test-app": provider},
		allowedIssuers:                []string{"https://token.actions.githubusercontent.com"},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		slogger:                       discardSlogger(),
		bundleManager:                 mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return bundleTestClaims("test-disabled-1"), nil
		},
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if mgr.calls.Load() != 0 {
		t.Errorf("bundle Eval calls when disabled = %d, want 0", mgr.calls.Load())
	}
	if provider.mintCalls != 1 {
		t.Errorf("mint calls when bundle disabled = %d, want 1", provider.mintCalls)
	}
	if al.lastEvent().BundleDigest != "" {
		t.Errorf("audit bundle_digest when disabled = %q, want empty", al.lastEvent().BundleDigest)
	}
	if al.lastEvent().OrgDecision != nil {
		t.Errorf("audit org_decision when disabled = %+v, want nil", al.lastEvent().OrgDecision)
	}
	if al.lastEvent().BundleEnforcement != bundle.EnforcementOptional {
		t.Errorf("audit bundle_enforcement = %q, want optional", al.lastEvent().BundleEnforcement)
	}
	_ = w.Code
}

func TestExchange_OptionalBundleNotApplicableHasNoDigestAttribution(t *testing.T) {
	mgr := &spyManager{
		enabled:  true,
		digest:   "optional-loaded=sha256:loaded-but-not-evaluated",
		decision: bundle.Decision{Allow: true},
	}
	h, al, provider := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if provider.mintCalls != 1 {
		t.Fatalf("mint calls = %d, want 1", provider.mintCalls)
	}
	event := al.lastEvent()
	if event.BundleDigest != "" || len(event.BundleDecisions) != 0 {
		t.Fatalf("non-participating bundle was attributed in audit: digest=%q decisions=%+v", event.BundleDigest, event.BundleDecisions)
	}
	if event.OrgDecision == nil || event.OrgDecision.Applicable || event.OrgDecision.Evaluated || !event.OrgDecision.Allow {
		t.Fatalf("org decision does not expose non-participation: %+v", event.OrgDecision)
	}
}

func TestExchange_BundleErrorAttributesFaultingSnapshot(t *testing.T) {
	mgr := &spyManager{
		enabled: true,
		decision: bundle.Decision{
			Applicable: true, Evaluated: true,
			SnapshotDigest:  "first=sha256:one,second=sha256:two",
			EvaluatedDigest: "first=sha256:one",
			Packages:        []bundle.PackageDecision{{BundleName: "first", Digest: "sha256:one", Allow: true}},
		},
		err: errors.New("second bundle failed"),
	}
	h, al, _ := newBundleTestHandler(t, mgr)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	event := al.lastEvent()
	if event.BundleDigest != "first=sha256:one,second=sha256:two" {
		t.Fatalf("bundle_digest = %q, want complete faulting snapshot", event.BundleDigest)
	}
	if len(event.BundleDecisions) != 1 || event.BundleDecisions[0].BundleName != "first" {
		t.Fatalf("prior participating decision was lost: %+v", event.BundleDecisions)
	}
}

// TestExchange_AuditFingerprint_OnAllowPath counter-validates that
// when the bundle allows, the audit event still carries the
// bundle_digest fingerprint — proving which bundle made the call. The
// spy server will be hit (it's the next step) so this test uses a
// recording server that returns 500 (mint fails) rather than fail-
// on-hit; what matters here is that the bundle digest is recorded
// before the mint attempt.
func TestExchange_AuditFingerprint_OnAllowPath(t *testing.T) {
	provider := &mockExchangeApp{mintErr: errors.New("mock mint failure")}

	pol := &policy.TrustPolicy{
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     bundleTestSubject,
		Audience:    "https://example.test/sts",
		Permissions: map[string]string{"contents": "read"},
		GitHub: &policy.GitHubPolicy{
			Sources: []policy.GitHubRepository{{OwnerID: "1001", RepositoryID: "2002"}},
			Target:  policy.GitHubRepository{OwnerID: "1001", RepositoryID: "2002"},
		},
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}

	mgr := &spyManager{
		enabled: true,
		digest:  "sha256:allow-digest",
		decision: bundle.Decision{
			Applicable: true, Evaluated: true, EvaluatedDigest: "sha256:allow-digest",
			Allow: true, Reasons: []string{"green-light"},
		},
	}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  &mockPolicyLoader{pol: pol},
		appProviders:                  map[string]github.ExchangeApp{"test-app": provider},
		allowedIssuers:                []string{"https://token.actions.githubusercontent.com"},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		slogger:                       discardSlogger(),
		bundleManager:                 mgr,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return bundleTestClaims("test-allow-1"), nil
		},
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest())

	if mgr.calls.Load() != 1 {
		t.Errorf("bundle Eval calls on allow path = %d, want 1", mgr.calls.Load())
	}
	if provider.mintCalls != 1 {
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
		enabled:  true,
		digest:   "sha256:stale-digest",
		decision: bundle.Decision{Applicable: true, SnapshotDigest: "sha256:stale-digest"},
		err:      bundle.ErrBundleStale,
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
	if last.Result != audit.ResultBundleStale {
		t.Errorf("audit result = %q, want %q", last.Result, audit.ResultBundleStale)
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
	if in.Claims["sub"] != bundleTestSubject {
		t.Errorf("input.Claims missing or wrong sub: %v", in.Claims["sub"])
	}
	if in.SourceIdentity == nil {
		t.Fatal("input.SourceIdentity is nil")
	}
	if in.SourceIdentity.Version != bundle.SourceIdentityVersionV1 ||
		in.SourceIdentity.Repository != "org/repo" ||
		in.SourceIdentity.RepositoryOwnerID != "1001" ||
		in.SourceIdentity.RepositoryID != "2002" ||
		!in.SourceIdentity.ImmutableSubject ||
		!in.SourceIdentity.ImmutableSubjectRequired {
		t.Errorf("input.SourceIdentity malformed: %+v", in.SourceIdentity)
	}
	if in.YAMLPolicy.Audience != "https://example.test/sts" {
		t.Errorf("input.YAMLPolicy.Audience = %q, want https://example.test/sts", in.YAMLPolicy.Audience)
	}
	if in.YAMLPolicy.GitHub == nil || in.YAMLPolicy.GitHub.Target.RepositoryID != "2002" || len(in.YAMLPolicy.GitHub.Sources) != 1 {
		t.Errorf("input.YAMLPolicy.GitHub malformed: %+v", in.YAMLPolicy.GitHub)
	}
	if in.TargetIdentity == nil || in.TargetIdentity.Version != bundle.TargetIdentityVersionV1 ||
		in.TargetIdentity.Scope != "org/repo" || in.TargetIdentity.RepositoryOwnerID != "1001" || in.TargetIdentity.RepositoryID != "2002" {
		t.Errorf("input.TargetIdentity malformed: %+v", in.TargetIdentity)
	}
	if in.Requested == nil || in.Requested.Permissions["contents"] != "read" {
		t.Errorf("input.Requested malformed: %+v", in.Requested)
	}
	if len(in.Requested.RepositoryIDs) != 1 || in.Requested.RepositoryIDs[0] != "2002" || in.Requested.OrganizationWide {
		t.Errorf("input.Requested target restriction malformed: %+v", in.Requested)
	}
}

func TestExchange_ExamplePolicyRegoConformance(t *testing.T) {
	manager := examplePolicyManager(t)
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "example-org/example-repo", Owner: "example-org", OwnerID: "123456",
		Repository: "example-repo", RepositoryID: "456789",
	}}
	subject := "repo:example-org@123456/example-repo@456789:ref:refs/heads/main"
	rawPolicy, err := os.ReadFile("../../config/examples/ci.sts.yaml")
	if err != nil {
		t.Fatalf("read CI example trust policy: %v", err)
	}
	pol, err := policy.ParsePolicy(rawPolicy)
	if err != nil {
		t.Fatalf("parse CI example trust policy: %v", err)
	}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  &mockPolicyLoader{pol: pol},
		appProviders:                  map[string]github.ExchangeApp{"default": app},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		slogger:                       discardSlogger(),
		bundleManager:                 manager,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss": oidc.GitHubActionsIssuer, "sub": subject, "aud": "https://sts.example.com", "jti": "rego-example-conformance",
				"ref":        "refs/heads/main",
				"repository": "example-org/example-repo", "repository_owner": "example-org",
				"repository_id": "456789", "repository_owner_id": "123456",
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=example-org/example-repo&identity=ci&app=default", nil)
	req.Header.Set("Authorization", "Bearer accepted")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if app.mintCalls != 1 || app.lastTarget.RepositoryID != "456789" {
		t.Fatalf("immutable target was not minted exactly once: calls=%d target=%+v", app.mintCalls, app.lastTarget)
	}
	event := al.lastEvent()
	if event.BundleEnforcement != bundle.EnforcementRequired {
		t.Fatalf("bundle_enforcement = %q, want required", event.BundleEnforcement)
	}
	if event.OrgDecision == nil || !event.OrgDecision.Applicable || !event.OrgDecision.Evaluated || !event.OrgDecision.Allow {
		t.Fatalf("org decision does not prove mandatory participation: %+v", event.OrgDecision)
	}
	if len(event.BundleDecisions) != 1 || event.BundleDecisions[0].BundleName != "example-enterprise-baseline" || event.BundleDecisions[0].Digest == "" {
		t.Fatalf("bundle decisions missing exact participant: %+v", event.BundleDecisions)
	}
	if event.BundleDigest != "example-enterprise-baseline="+event.BundleDecisions[0].Digest {
		t.Fatalf("bundle_digest = %q, package digest = %q", event.BundleDigest, event.BundleDecisions[0].Digest)
	}
}

func examplePolicyManager(t *testing.T) bundle.Manager {
	t.Helper()
	rego, err := os.ReadFile("../../policies/example_enterprise_baseline.rego")
	if err != nil {
		t.Fatalf("read example baseline: %v", err)
	}
	data, err := os.ReadFile("../../policies/example_data.json")
	if err != nil {
		t.Fatalf("read example baseline data: %v", err)
	}

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range map[string][]byte{
		"policies/example_enterprise_baseline.rego": rego,
		"data.json": data,
	} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatalf("write bundle header: %v", err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatalf("write bundle content: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close bundle tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close bundle gzip: %v", err)
	}
	path := t.TempDir() + "/bundle.tar.gz"
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write example baseline bundle: %v", err)
	}
	live := bundle.NewLiveManager(
		bundle.FilesystemLoader{}, bundle.Source{Raw: "file://" + path}, bundle.VerifyConfig{}, discardSlogger(),
		bundle.LiveOpts{Name: "example-enterprise-baseline", Mandatory: true},
	)
	if err := live.Init(context.Background()); err != nil {
		t.Fatalf("initialize example mandatory baseline: %v", err)
	}
	return bundle.NewMultiManager([]bundle.LifecycleManager{live}, bundle.EnforcementRequired)
}
