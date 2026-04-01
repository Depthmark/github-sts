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
	gh "github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/policy"
)

// mockJTICache implements jti.Cache for testing.
type mockJTICache struct {
	isNew      bool
	reserveErr error
	releaseErr error
}

func (m *mockJTICache) Reserve(_ context.Context, _ string, _ time.Time) (bool, error) {
	return m.isNew, m.reserveErr
}

func (m *mockJTICache) Release(_ context.Context, _ string) error {
	return m.releaseErr
}

// mockPolicyLoader implements policy.Loader for testing.
type mockPolicyLoader struct {
	pol *policy.TrustPolicy
	err error
}

func (m *mockPolicyLoader) Load(_ context.Context, _, _, _ string) (*policy.TrustPolicy, error) {
	return m.pol, m.err
}

// mockAppTokenProvider wraps github.AppTokenProvider for testing.
// We can't easily mock github.AppTokenProvider since it's a struct,
// so we test via the handler's integration with httptest servers.

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
		jtiCache:       &mockJTICache{isNew: jtiNew, reserveErr: jtiErr},
		policyLoader:   &mockPolicyLoader{pol: pol, err: polErr},
		appProviders:   map[string]*gh.AppTokenProvider{},
		allowedIssuers: []string{},
		auditLogger:    al,
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
		appProviders: map[string]*gh.AppTokenProvider{
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
		appProviders: map[string]*gh.AppTokenProvider{
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
		appProviders: map[string]*gh.AppTokenProvider{
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

func TestBuildRepositories(t *testing.T) {
	pol := &policy.TrustPolicy{
		Repositories: []string{"repo1", "repo2"},
	}

	// Repo-level scope.
	repos := buildRepositories("org/myrepo", pol)
	if len(repos) != 1 || repos[0] != "myrepo" {
		t.Errorf("repo-level: got %v, want [myrepo]", repos)
	}

	// Org-level scope.
	repos = buildRepositories("org", pol)
	if len(repos) != 2 {
		t.Errorf("org-level: got %v, want [repo1 repo2]", repos)
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
	resp := ErrorResponse{Error: "something failed"}
	data, _ := json.Marshal(resp)
	if string(data) != `{"error":"something failed"}` {
		t.Errorf("unexpected JSON: %s", data)
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
