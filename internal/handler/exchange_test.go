package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	gh "github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
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
	target       gh.TargetIdentity
	resolveErr   error
	token        string
	mintErr      error
	resolveCalls int
	mintCalls    int
	lastScope    gh.RepositoryScope
	lastTarget   gh.TargetIdentity
	lastPerms    map[string]string
}

func (m *mockExchangeApp) ResolveTarget(_ context.Context, scope gh.RepositoryScope) (gh.TargetIdentity, error) {
	m.resolveCalls++
	m.lastScope = scope
	if m.resolveErr != nil {
		return gh.TargetIdentity{}, m.resolveErr
	}
	if m.target.Scope == "" {
		return gh.TargetIdentity{
			Scope: scope.String(), Owner: scope.Owner, OwnerID: "1001",
			Repository: scope.Repository, RepositoryID: "2002",
		}, nil
	}
	return m.target, nil
}

func (m *mockExchangeApp) GetInstallationTokenForTarget(_ context.Context, target gh.TargetIdentity, permissions map[string]string, _ string) (string, error) {
	m.mintCalls++
	m.lastTarget = target
	m.lastPerms = permissions
	if m.mintErr != nil {
		return "", m.mintErr
	}
	if m.token == "" {
		return "ghs_test", nil
	}
	return m.token, nil
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
		appProviders:                  map[string]gh.ExchangeApp{},
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
		appProviders:                  map[string]gh.ExchangeApp{},
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
		appProviders:                  map[string]gh.ExchangeApp{},
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
		appProviders:                  map[string]gh.ExchangeApp{},
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
	app := &mockExchangeApp{target: gh.TargetIdentity{
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
	app := &mockExchangeApp{target: gh.TargetIdentity{
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
	app := &mockExchangeApp{target: gh.TargetIdentity{
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
	app := &mockExchangeApp{target: gh.TargetIdentity{
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
	app := &mockExchangeApp{target: gh.TargetIdentity{
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

func authorizedExchangeHandler(app gh.ExchangeApp, loader *mockPolicyLoader, al *recordingAuditLogger) *ExchangeHandler {
	return &ExchangeHandler{
		jtiCache:                      &mockJTICache{isNew: true},
		policyLoader:                  loader,
		appProviders:                  map[string]gh.ExchangeApp{"test-app": app},
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
		appProviders: map[string]gh.ExchangeApp{
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
		appProviders: map[string]gh.ExchangeApp{
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
		appProviders: map[string]gh.ExchangeApp{
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
