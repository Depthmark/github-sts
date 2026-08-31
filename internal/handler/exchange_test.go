package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

// mockJTICache implements jti.Cache for testing.
type mockJTICache struct {
	isNew        bool
	reserveErr   error
	releaseErr   error
	reserveCalls int
}

func (m *mockJTICache) Reserve(_ context.Context, _ string, _ time.Time) (bool, error) {
	m.reserveCalls++
	return m.isNew, m.reserveErr
}

func (m *mockJTICache) Release(_ context.Context, _ string) error {
	return m.releaseErr
}

// mockPolicyLoader implements policy.Loader for testing.
type mockPolicyLoader struct {
	pol       *policy.TrustPolicy
	err       error
	loadCalls int
	last      policy.LoadRequest
}

func (m *mockPolicyLoader) Load(_ context.Context, request policy.LoadRequest) (*policy.TrustPolicy, error) {
	m.loadCalls++
	m.last = request
	return m.pol, m.err
}

type mockExchangeApp struct {
	target     github.TargetIdentity
	resolveErr error
	token      string
	// expiresAt overrides the minted token's expiry. Zero means "behave like
	// GitHub and report one hour out"; noExpiry forces the degraded case
	// where GitHub sent nothing usable.
	expiresAt    time.Time
	noExpiry     bool
	instance     string
	mintErr      error
	resolveCalls int
	mintCalls    int
	lastScope    github.RepositoryScope
	lastTarget   github.TargetIdentity
	lastPerms    map[string]string
}

func (m *mockExchangeApp) ResolveTarget(_ context.Context, scope github.RepositoryScope) (github.TargetIdentity, error) {
	m.resolveCalls++
	m.lastScope = scope
	if m.resolveErr != nil {
		return github.TargetIdentity{}, m.resolveErr
	}
	if m.target.Scope == "" {
		return github.TargetIdentity{
			Scope: scope.String(), Owner: scope.Owner, OwnerID: "1001",
			Repository: scope.Repository, RepositoryID: "2002",
		}, nil
	}
	return m.target, nil
}

func (m *mockExchangeApp) GetInstallationTokenForTarget(_ context.Context, target github.TargetIdentity, permissions map[string]string, _ string) (github.IssuedToken, string, error) {
	m.mintCalls++
	m.lastTarget = target
	m.lastPerms = permissions
	if m.mintErr != nil {
		return github.IssuedToken{}, "", m.mintErr
	}
	token := m.token
	if token == "" {
		token = "ghs_test"
	}
	expiresAt := m.expiresAt
	if expiresAt.IsZero() && !m.noExpiry {
		expiresAt = time.Now().Add(time.Hour)
	}
	if m.noExpiry {
		expiresAt = time.Time{}
	}
	return github.IssuedToken{Token: token, ExpiresAt: expiresAt}, m.instance, nil
}

// recordingAuditLogger captures audit events for assertion.
type recordingAuditLogger struct {
	events []audit.Event
}

func (r *recordingAuditLogger) Log(e audit.Event) {
	r.events = append(r.events, e)
}

func (r *recordingAuditLogger) Close() error { return nil }

func (r *recordingAuditLogger) lastEvent() audit.Event {
	if len(r.events) == 0 {
		return audit.Event{}
	}
	return r.events[len(r.events)-1]
}

// mockOIDCValidator replaces oidc.Validate for testing.
// Since oidc.Validate is a package-level function, we test the handler
// by providing a bearer that the real validator would reject, and check
// the handler's response codes.

func newTestHandler(jtiNew bool, jtiErr error, pol *policy.TrustPolicy, polErr error) (*ExchangeHandler, *recordingAuditLogger) {
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: jtiNew, reserveErr: jtiErr},
		policyLoader:                  &mockPolicyLoader{pol: pol, err: polErr},
		appProviders:                  map[string]github.ExchangeApp{},
		allowedIssuers:                []string{},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
	}
	return h, al
}

func TestExchange_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPut, "/sts/exchange", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestExchange_MissingScope(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?identity=ci", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExchange_MissingAuth(t *testing.T) {
	h, al := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// All auth failures return 403 to prevent enumeration.
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if al.lastEvent().Result != audit.ResultOIDCInvalid {
		t.Errorf("audit result = %q, want oidc_invalid", al.lastEvent().Result)
	}
}

func TestExchange_InvalidAuth(t *testing.T) {
	h, al := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if al.lastEvent().Result != audit.ResultOIDCInvalid {
		t.Errorf("audit result = %q, want oidc_invalid", al.lastEvent().Result)
	}
}

func TestExchange_GitHubIdentityInvalidBeforeStateOrPolicy(t *testing.T) {
	jtiCache := &mockJTICache{isNew: true}
	loader := &mockPolicyLoader{}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      jtiCache,
		policyLoader:                  loader,
		appProviders:                  map[string]github.ExchangeApp{},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss":                 oidc.GitHubActionsIssuer,
				"sub":                 "repo:org/repo:ref:refs/heads/main",
				"repository":          "org/repo",
				"repository_owner":    "org",
				"repository_id":       "2002",
				"repository_owner_id": "1001",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci", nil)
	req.Header.Set("Authorization", "Bearer validator-accepts")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != CodeGitHubIdentityInvalid {
		t.Fatalf("code = %q, want %q", resp.Code, CodeGitHubIdentityInvalid)
	}
	if jtiCache.reserveCalls != 0 {
		t.Fatalf("JTI Reserve calls = %d, want 0", jtiCache.reserveCalls)
	}
	if loader.loadCalls != 0 {
		t.Fatalf("policy Load calls = %d, want 0", loader.loadCalls)
	}
	event := al.lastEvent()
	if event.ImmutableSubjectRequired == nil || !*event.ImmutableSubjectRequired {
		t.Fatalf("audit immutable_subject_required = %v, want true", event.ImmutableSubjectRequired)
	}
}

func TestExchange_LegacySubjectOptOutStillRequiresIDs(t *testing.T) {
	jtiCache := &mockJTICache{isNew: true}
	loader := &mockPolicyLoader{}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      jtiCache,
		policyLoader:                  loader,
		appProviders:                  map[string]github.ExchangeApp{},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer},
		requireImmutableSubjectClaims: false,
		auditLogger:                   al,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss":              oidc.GitHubActionsIssuer,
				"sub":              "repo:org/repo:ref:refs/heads/main",
				"repository":       "org/repo",
				"repository_owner": "org",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci", nil)
	req.Header.Set("Authorization", "Bearer validator-accepts")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != CodeGitHubIdentityInvalid {
		t.Fatalf("code = %q, want %q", resp.Code, CodeGitHubIdentityInvalid)
	}
	if jtiCache.reserveCalls != 0 || loader.loadCalls != 0 {
		t.Fatalf("invalid legacy identity reached state or policy: reserve=%d load=%d", jtiCache.reserveCalls, loader.loadCalls)
	}
	event := al.lastEvent()
	if event.ImmutableSubjectRequired == nil || *event.ImmutableSubjectRequired {
		t.Fatalf("audit immutable_subject_required = %v, want false", event.ImmutableSubjectRequired)
	}
}

func TestExchange_LegacySubjectOptOutWithIDsPassesIdentityValidation(t *testing.T) {
	jtiCache := &mockJTICache{isNew: true}
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:                      jtiCache,
		policyLoader:                  &mockPolicyLoader{},
		appProviders:                  map[string]github.ExchangeApp{},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer},
		requireImmutableSubjectClaims: false,
		auditLogger:                   al,
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss":                 oidc.GitHubActionsIssuer,
				"sub":                 "repo:org/repo:ref:refs/heads/main",
				"repository":          "org/repo",
				"repository_owner":    "org",
				"repository_id":       "2002",
				"repository_owner_id": "1001",
				"jti":                 "legacy-valid",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo&identity=ci", nil)
	req.Header.Set("Authorization", "Bearer validator-accepts")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if jtiCache.reserveCalls != 1 {
		t.Fatalf("JTI Reserve calls = %d, want 1 after valid identity", jtiCache.reserveCalls)
	}
	event := al.lastEvent()
	if event.SourceRepositoryID != "2002" || event.SourceRepositoryOwnerID != "1001" {
		t.Fatalf("audit source identity missing: %+v", event)
	}
	if event.ImmutableSubject == nil || *event.ImmutableSubject {
		t.Fatalf("audit immutable_subject = %v, want false", event.ImmutableSubject)
	}
	if event.ImmutableSubjectRequired == nil || *event.ImmutableSubjectRequired {
		t.Fatalf("audit immutable_subject_required = %v, want false", event.ImmutableSubjectRequired)
	}
}

func TestExchange_ExactSourceToTargetRelationship(t *testing.T) {
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
	loader := &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}
	al := &recordingAuditLogger{}
	h := authorizedExchangeHandler(app, loader, al)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if app.resolveCalls != 1 || app.mintCalls != 1 {
		t.Fatalf("resolve calls=%d mint calls=%d, want 1 each", app.resolveCalls, app.mintCalls)
	}
	if app.lastTarget.RepositoryID != "3001" {
		t.Fatalf("mint target = %+v", app.lastTarget)
	}
	if loader.last.TargetOwnerID != "1001" || loader.last.TargetRepositoryID != "3001" || loader.last.Scope != "org/target" {
		t.Fatalf("policy load request = %+v", loader.last)
	}
	event := al.lastEvent()
	if event.TargetRepositoryOwnerID != "1001" || event.TargetRepositoryID != "3001" || event.TargetRepository != "org/target" {
		t.Fatalf("audit target identity missing: %+v", event)
	}
}

func TestExchange_SourceRelationshipMismatchDeniesBeforeMint(t *testing.T) {
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
	loader := &mockPolicyLoader{pol: validExchangePolicy("9999", "3001")}
	h := authorizedExchangeHandler(app, loader, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	assertErrorCode(t, w, http.StatusForbidden, CodePolicyDenied)
	if app.mintCalls != 0 {
		t.Fatalf("mint calls = %d, want 0", app.mintCalls)
	}
}

func TestExchange_TargetRelationshipMismatchDeniesBeforeMint(t *testing.T) {
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
	loader := &mockPolicyLoader{pol: validExchangePolicy("2001", "9999")}
	h := authorizedExchangeHandler(app, loader, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	assertErrorCode(t, w, http.StatusForbidden, CodePolicyDenied)
	if app.mintCalls != 0 {
		t.Fatalf("mint calls = %d, want 0", app.mintCalls)
	}
}

func TestExchange_SourceRenamePreservingIDsAllows(t *testing.T) {
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}, &recordingAuditLogger{})
	h.validator = func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
		return oidc.Claims{
			"iss": oidc.GitHubActionsIssuer,
			"sub": "repo:renamed-org@1001/renamed-source@2001:ref:refs/heads/main",
			"aud": "https://example.test/sts", "jti": "renamed-source-jti", "ref": "refs/heads/main",
			"repository": "renamed-org/renamed-source", "repository_owner": "renamed-org",
			"repository_id": "2001", "repository_owner_id": "1001",
		}, nil
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if app.mintCalls != 1 {
		t.Fatalf("mint calls = %d, want 1", app.mintCalls)
	}
}

func TestExchange_InvalidTrustPolicyHasDistinctCode(t *testing.T) {
	app := &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
	loader := &mockPolicyLoader{pol: &policy.TrustPolicy{
		Issuer: oidc.GitHubActionsIssuer, Subject: authorizedSubject,
		Audience: "https://example.test/sts", Permissions: map[string]string{"contents": "read"},
	}}
	al := &recordingAuditLogger{}
	h := authorizedExchangeHandler(app, loader, al)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	assertErrorCode(t, w, http.StatusForbidden, CodeTrustPolicyInvalid)
	if app.mintCalls != 0 {
		t.Fatalf("mint calls = %d, want 0", app.mintCalls)
	}
	if al.lastEvent().Result != audit.ResultPolicyInvalid {
		t.Fatalf("audit result = %q, want %q", al.lastEvent().Result, audit.ResultPolicyInvalid)
	}
}

const authorizedSubject = "repo:org@1001/source@2001:ref:refs/heads/main"

func authorizedExchangeHandler(app github.ExchangeApp, loader *mockPolicyLoader, al *recordingAuditLogger) *ExchangeHandler {
	return &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  loader,
		appProviders:                  map[string]github.ExchangeApp{"test-app": app},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		bundleManager:                 bundle.Disabled{},
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return oidc.Claims{
				"iss": oidc.GitHubActionsIssuer, "sub": authorizedSubject,
				"aud": "https://example.test/sts", "jti": "authorized-jti", "ref": "refs/heads/main",
				"repository": "org/source", "repository_owner": "org",
				"repository_id": "2001", "repository_owner_id": "1001",
			}, nil
		},
	}
}

func authorizedExchangeRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/target&identity=ci&app=test-app", nil)
	req.Header.Set("Authorization", "Bearer accepted")
	return req
}

func validExchangePolicy(sourceRepositoryID, targetRepositoryID string) *policy.TrustPolicy {
	return &policy.TrustPolicy{
		Issuer: oidc.GitHubActionsIssuer, ClaimPattern: map[string]string{"ref": "refs/heads/main"},
		Audience: "https://example.test/sts", Permissions: map[string]string{"contents": "read"},
		GitHub: &policy.GitHubPolicy{
			Sources: []policy.GitHubRepository{{OwnerID: "1001", RepositoryID: policy.GitHubID(sourceRepositoryID)}},
			Target:  policy.GitHubRepository{OwnerID: "1001", RepositoryID: policy.GitHubID(targetRepositoryID)},
		},
	}
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, status, w.Body.String())
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != code {
		t.Fatalf("code = %q, want %q", resp.Code, code)
	}
}

func TestExchange_PostInvalidJSON(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/sts/exchange", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExchange_PostUnsupportedContentType(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/sts/exchange", bytes.NewBufferString("<xml/>"))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExchange_PostParsesBody(t *testing.T) {
	h, al := newTestHandler(true, nil, nil, nil)
	body := `{"scope":"org/repo","identity":"ci"}`
	req := httptest.NewRequest(http.MethodPost, "/sts/exchange", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// No auth header → 403, but scope/identity should be parsed.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if al.lastEvent().Scope != "org/repo" {
		t.Errorf("audit scope = %q, want org/repo", al.lastEvent().Scope)
	}
}

func TestExchange_MultiAppWithoutParam(t *testing.T) {
	// Test app resolution with multiple apps and no app param.
	al := &recordingAuditLogger{}
	h := &ExchangeHandler{
		jtiCache:     &mockJTICache{isNew: true},
		policyLoader: &mockPolicyLoader{},
		appProviders: map[string]github.ExchangeApp{
			"app1": nil,
			"app2": nil,
		},
		allowedIssuers: []string{},
		auditLogger:    al,
	}

	_, _, err := h.resolveApp("")
	if err == nil {
		t.Error("expected error for multi-app without param")
	}
}

func TestResolveApp_SingleApp(t *testing.T) {
	h := &ExchangeHandler{
		appProviders: map[string]github.ExchangeApp{
			"default": nil,
		},
	}
	name, _, err := h.resolveApp("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "default" {
		t.Errorf("name = %q, want default", name)
	}
}

func TestResolveApp_UnknownApp(t *testing.T) {
	h := &ExchangeHandler{
		appProviders: map[string]github.ExchangeApp{
			"default": nil,
		},
	}
	_, _, err := h.resolveApp("nonexistent")
	if err == nil {
		t.Error("expected error for unknown app")
	}
}

func TestAudienceMatches(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		expected string
		want     bool
	}{
		{
			name:     "string match",
			claims:   map[string]any{"aud": "https://github.com/myorg"},
			expected: "https://github.com/myorg",
			want:     true,
		},
		{
			name:     "string mismatch",
			claims:   map[string]any{"aud": "other"},
			expected: "https://github.com/myorg",
			want:     false,
		},
		{
			name:     "list match",
			claims:   map[string]any{"aud": []any{"a", "https://github.com/myorg"}},
			expected: "https://github.com/myorg",
			want:     true,
		},
		{
			name:     "list no match",
			claims:   map[string]any{"aud": []any{"a", "b"}},
			expected: "https://github.com/myorg",
			want:     false,
		},
		{
			name:     "missing aud",
			claims:   map[string]any{},
			expected: "https://github.com/myorg",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := audienceMatches(tt.claims, tt.expected); got != tt.want {
				t.Errorf("audienceMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExchange_OrganizationScopeRejectedBeforeAuth(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org&identity=ci", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != CodeBadRequest {
		t.Fatalf("code = %q, want %q", resp.Code, CodeBadRequest)
	}
}

func TestExtractBearer(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer mytoken", "mytoken"},
		{"bearer mytoken", ""},
		{"Basic dXNlcjpwYXNz", ""},
		{"", ""},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tt.header != "" {
			r.Header.Set("Authorization", tt.header)
		}
		if got := extractBearer(r); got != tt.want {
			t.Errorf("extractBearer(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestRemoteIP(t *testing.T) {
	// Without trust_forwarded_headers, XFF is ignored.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	if got := remoteIP(r, false); got != "10.0.0.1" {
		t.Errorf("remoteIP (untrusted XFF) = %q, want 10.0.0.1", got)
	}

	// With trust_forwarded_headers, XFF is used.
	if got := remoteIP(r, true); got != "1.2.3.4" {
		t.Errorf("remoteIP (trusted XFF) = %q, want 1.2.3.4", got)
	}

	// Without XFF header, always use RemoteAddr.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	if got := remoteIP(r2, true); got != "10.0.0.1" {
		t.Errorf("remoteIP (no XFF) = %q, want 10.0.0.1", got)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("key = %q, want value", result["key"])
	}
}

func TestClaimExpiry(t *testing.T) {
	// float64 (standard JSON number)
	claims := map[string]any{"exp": float64(1700000000)}
	exp := claimExpiry(claims)
	if exp.Unix() != 1700000000 {
		t.Errorf("exp = %d, want 1700000000", exp.Unix())
	}

	// Missing exp — default to ~1 hour from now.
	exp = claimExpiry(map[string]any{})
	if time.Until(exp) < 59*time.Minute {
		t.Error("missing exp should default to ~1h from now")
	}
}

// Ensure ErrorResponse has the right JSON shape.
func TestErrorResponse_JSON(t *testing.T) {
	// code/trace_id are omitempty — bare error keeps the legacy shape.
	resp := ErrorResponse{Error: "something failed"}
	data, _ := json.Marshal(resp)
	if string(data) != `{"error":"something failed"}` {
		t.Errorf("unexpected JSON: %s", data)
	}

	// With code + trace_id populated.
	resp = ErrorResponse{Error: "forbidden", Code: CodePolicyDenied, TraceID: "abc-123"}
	data, _ = json.Marshal(resp)
	want := `{"error":"forbidden","code":"policy_denied","trace_id":"abc-123"}`
	if string(data) != want {
		t.Errorf("unexpected JSON:\n got: %s\nwant: %s", data, want)
	}
}

// TestErrorCodes_Stable pins the wire values of the public error codes.
// These appear in operator runbooks; renaming them is a breaking change.
func TestErrorCodes_Stable(t *testing.T) {
	pairs := []struct {
		name string
		got  string
		want string
	}{
		{"CodeBadRequest", CodeBadRequest, "bad_request"},
		{"CodeOIDCInvalid", CodeOIDCInvalid, "oidc_invalid"},
		{"CodeGitHubIdentityInvalid", CodeGitHubIdentityInvalid, "github_identity_invalid"},
		{"CodeAudienceMismatch", CodeAudienceMismatch, "audience_mismatch"},
		{"CodeAppUnknown", CodeAppUnknown, "app_unknown"},
		{"CodePolicyNotFound", CodePolicyNotFound, "policy_not_found"},
		{"CodeTrustPolicyInvalid", CodeTrustPolicyInvalid, "trust_policy_invalid"},
		{"CodePolicyDenied", CodePolicyDenied, "policy_denied"},
		{"CodeMethodNotAllowed", CodeMethodNotAllowed, "method_not_allowed"},
		{"CodeReplay", CodeReplay, "replay_detected"},
		{"CodeInternal", CodeInternal, "internal_error"},
		{"CodeUpstream", CodeUpstream, "upstream_error"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("%s = %q, want %q", p.name, p.got, p.want)
		}
	}
}

// Ensure ExchangeResponse has the right JSON shape.
func TestExchangeResponse_JSON(t *testing.T) {
	resp := ExchangeResponse{
		Token:       "ghu_abc123",
		Scope:       "org/repo",
		App:         "default",
		Identity:    "ci",
		Permissions: map[string]string{"contents": "read"},
	}
	data, _ := json.Marshal(resp)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	if raw["token"] != "ghu_abc123" {
		t.Errorf("token = %v", raw["token"])
	}
	if raw["scope"] != "org/repo" {
		t.Errorf("scope = %v", raw["scope"])
	}

	_ = fmt.Sprintf("%v", raw) // prevent unused import
}

func TestExchange_InvalidScopeChars(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/repo%20;DROP&identity=ci", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExchange_ScopeTooLong(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	longScope := strings.Repeat("a", 201)
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope="+longScope+"&identity=ci", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExchange_ValidScopeChars(t *testing.T) {
	h, _ := newTestHandler(true, nil, nil, nil)
	// Valid chars should pass validation and proceed to auth check (403).
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=my-org/my.repo_v2&identity=ci-deploy", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (should fail at auth, not validation)", w.Code, http.StatusForbidden)
	}
}

// --- End-to-end exchange flow over a 2-instance AppPool ---
//
// Everything else in this file mocks the app provider (resolveApp is
// exercised in isolation). This exercises the real *github.AppPool wired in
// the way server.go wires it, with a real OIDC-validated token, to prove
// the exchange still succeeds when the first instance a request lands on
// always 403s, and that the response/audit event correctly attribute the
// success to whichever instance actually served it (design doc §5.4.1).

// oidcTestProvider stands up a mock OIDC discovery+JWKS endpoint and can
// sign tokens against it.
type oidcTestProvider struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	oidc.ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": fmt.Sprintf("http://%s/jwks", r.Host),
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-kid-1",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &oidcTestProvider{key: key, srv: srv}
}

func (p *oidcTestProvider) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid-1"
	signed, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

// newGitHubInstanceServer returns a mock GitHub API server that resolves
// any installation lookup to installationID and delegates token-minting
// requests to tokenHandler.
func newGitHubInstanceServer(installationID int64, tokenHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": installationID})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			tokenHandler(w, r)
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			// Target resolution (ResolveTarget) always uses a metadata:read
			// token minted against this same server, then GETs the repo here
			// to canonicalize owner/repo into immutable IDs.
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 2)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        1001,
				"name":      parts[1],
				"full_name": parts[0] + "/" + parts[1],
				"owner":     map[string]any{"login": parts[0], "id": 2002},
			})
		}
	}))
}

func TestExchange_TwoInstancePool_FailsOverAndAttributesInstance(t *testing.T) {
	oidcProvider := newOIDCTestProvider(t)

	var failCalls int32
	failSrv := newGitHubInstanceServer(1, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&failCalls, 1)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	})
	defer failSrv.Close()
	okSrv := newGitHubInstanceServer(1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_from_checkout_2"})
	})
	defer okSrv.Close()

	newMember := func(instance, apiURL string) github.PoolMember {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating RSA key: %v", err)
		}
		return github.PoolMember{
			Instance: instance,
			Provider: github.NewAppTokenProvider("checkout", instance, 1, key, apiURL, nil),
		}
	}
	// Ring index 1 (the first candidate a fresh pool's cursor lands on) is
	// checkout-1, so this exercises a real failover to checkout-2 whenever
	// the ring starts there.
	pool := github.NewAppPool("checkout",
		[]github.PoolMember{
			newMember("checkout-2", okSrv.URL),
			newMember("checkout-1", failSrv.URL),
		},
		"round_robin", 0, 2, nil,
	)

	pol := &policy.TrustPolicy{
		Issuer:      oidcProvider.srv.URL,
		Audience:    "test-audience",
		Subject:     "repo:myorg/myrepo:ref:refs/heads/main",
		Permissions: map[string]string{"contents": "read"},
	}

	al := &recordingAuditLogger{}
	h := NewExchangeHandler(
		&mockJTICache{isNew: true},
		&mockPolicyLoader{pol: pol},
		map[string]github.ExchangeApp{"checkout": pool},
		[]string{oidcProvider.srv.URL},
		"",
		false,
		al,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		false,
		nil,
	)

	sawFailover := false
	for i := 0; i < 2; i++ {
		now := time.Now()
		token := oidcProvider.sign(t, jwt.MapClaims{
			"iss": oidcProvider.srv.URL,
			"sub": "repo:myorg/myrepo:ref:refs/heads/main",
			"aud": "test-audience",
			"exp": now.Add(10 * time.Minute).Unix(),
			"iat": now.Unix(),
			"jti": fmt.Sprintf("test-jti-%d", i),
		})

		req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=myorg/myrepo&identity=ci&app=checkout", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("call %d: status = %d, body = %s", i, w.Code, w.Body.String())
		}

		var resp ExchangeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("call %d: decoding response: %v", i, err)
		}
		if resp.Token != "ghs_from_checkout_2" {
			t.Errorf("call %d: token = %q, want ghs_from_checkout_2 (must always resolve to the succeeding instance)", i, resp.Token)
		}
		if resp.App != "checkout" {
			t.Errorf("call %d: app = %q, want checkout (the logical name, never an instance)", i, resp.App)
		}

		event := al.lastEvent()
		if event.Result != audit.ResultSuccess {
			t.Errorf("call %d: audit result = %q, want success", i, event.Result)
		}
		if event.Instance != "checkout-2" {
			t.Errorf("call %d: audit instance = %q, want checkout-2", i, event.Instance)
		}
		if event.AppName != "checkout" {
			t.Errorf("call %d: audit app = %q, want checkout", i, event.AppName)
		}

		if atomic.LoadInt32(&failCalls) > 0 {
			sawFailover = true
		}
	}

	if !sawFailover {
		t.Fatal("checkout-1 was never tried across 2 calls — this test never actually exercised failover")
	}
}

func TestValidateField(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		maxLen  int
		wantErr bool
	}{
		{"valid", "org/repo", 200, false},
		{"valid_with_special", "my-org/my.repo_v2", 200, false},
		{"too_long", strings.Repeat("a", 201), 200, true},
		{"invalid_chars_space", "org repo", 200, true},
		{"invalid_chars_semicolon", "org;repo", 200, true},
		{"empty", "", 200, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateField("test", tt.value, tt.maxLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateField(%q) error = %v, wantErr = %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

// expires_in is what lets a caller schedule its own refresh instead of
// hardcoding GitHub's one-hour default, so it must reflect the expiry GitHub
// actually returned — measured at response time, rounded down.
func TestExchange_ReportsExpiresIn(t *testing.T) {
	app := &mockExchangeApp{
		target: github.TargetIdentity{
			Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
		},
		expiresAt: time.Now().Add(30 * time.Minute),
	}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp ExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	// A few seconds of slack for test-machine scheduling; the point is that
	// the value tracks the mint's expiry rather than a constant.
	if resp.ExpiresIn > 1800 || resp.ExpiresIn < 1795 {
		t.Fatalf("expires_in = %d, want just under 1800", resp.ExpiresIn)
	}
}

// When GitHub gives no usable expiry the broker must stay silent rather than
// invent one — a caller that trusts a guessed lifetime refreshes at the wrong
// time, which is worse than falling back to its own heuristic.
func TestExchange_OmitsExpiresInWhenUnknown(t *testing.T) {
	app := &mockExchangeApp{
		target: github.TargetIdentity{
			Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
		},
		noExpiry: true,
	}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, present := raw["expires_in"]; present {
		t.Fatalf("expires_in = %v, want the key absent when the lifetime is unknown", raw["expires_in"])
	}
	if raw["token"] != "ghs_test" {
		t.Fatalf("token = %v, want the exchange to still succeed", raw["token"])
	}
}

func TestExpiresIn(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		expiresAt time.Time
		want      int64
	}{
		{"one hour out", now.Add(time.Hour), 3600},
		{"rounds down to whole seconds", now.Add(time.Hour + 999*time.Millisecond), 3600},
		{"unknown expiry", time.Time{}, 0},
		{"already elapsed", now.Add(-time.Minute), 0},
		{"expiring now", now, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expiresIn(tt.expiresAt, now); got != tt.want {
				t.Fatalf("expiresIn(%v) = %d, want %d", tt.expiresAt, got, tt.want)
			}
		})
	}
}
