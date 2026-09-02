package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/policy"
)

// narrowingPolicy is validExchangePolicy with a wider grant, so a request
// has something to narrow away from.
func narrowingPolicy() *policy.TrustPolicy {
	pol := validExchangePolicy("2001", "3001")
	pol.Permissions = map[string]string{"contents": "write", "issues": "write"}
	return pol
}

func narrowingApp() *mockExchangeApp {
	return &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
}

func narrowGETRequest(query string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/target&identity=ci&app=test-app&"+query, nil)
	req.Header.Set("Authorization", "Bearer accepted")
	return req
}

func narrowPOSTRequest(t *testing.T, permissions any) *http.Request {
	t.Helper()
	body := map[string]any{"scope": "org/target", "identity": "ci", "app": "test-app"}
	if permissions != nil {
		body["permissions"] = permissions
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sts/exchange", strings.NewReader(string(encoded)))
	req.Header.Set("Authorization", "Bearer accepted")
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestExchange_NoPermissionsFieldMintsPolicyCeiling is the regression guard
// for every caller that predates narrowing: omitting the field must behave
// exactly as it did before, minting the policy's full permission set.
func TestExchange_NoPermissionsFieldMintsPolicyCeiling(t *testing.T) {
	app := narrowingApp()
	al := &recordingAuditLogger{}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, al)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if app.lastPerms["contents"] != "write" || app.lastPerms["issues"] != "write" || len(app.lastPerms) != 2 {
		t.Fatalf("minted permissions = %v, want the full policy ceiling", app.lastPerms)
	}
	if event := al.lastEvent(); event.RequestedPermissions != nil {
		t.Fatalf("audit requested_permissions = %v, want nil when the caller did not narrow", event.RequestedPermissions)
	}
}

func TestExchange_NarrowsViaPOSTBody(t *testing.T) {
	app := narrowingApp()
	al := &recordingAuditLogger{}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, al)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowPOSTRequest(t, map[string]string{"contents": "read"}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(app.lastPerms) != 1 || app.lastPerms["contents"] != "read" {
		t.Fatalf("minted permissions = %v, want {contents: read}", app.lastPerms)
	}
	// The ceiling still travels alongside the narrowed set, because the
	// issuance metric labels from it.
	if app.lastCeiling["contents"] != "write" || app.lastCeiling["issues"] != "write" {
		t.Fatalf("ceiling = %v, want the untouched policy permissions", app.lastCeiling)
	}

	event := al.lastEvent()
	if event.PolicyPermissions["contents"] != "write" {
		t.Fatalf("audit policy_permissions = %v", event.PolicyPermissions)
	}
	if event.RequestedPermissions["contents"] != "read" {
		t.Fatalf("audit requested_permissions = %v", event.RequestedPermissions)
	}
	if event.GrantedPermissions["contents"] != "read" {
		t.Fatalf("audit granted_permissions = %v", event.GrantedPermissions)
	}
}

func TestExchange_NarrowsViaGETQuery(t *testing.T) {
	app := narrowingApp()
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowGETRequest("permission=contents:read&permission=issues:read"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(app.lastPerms) != 2 || app.lastPerms["contents"] != "read" || app.lastPerms["issues"] != "read" {
		t.Fatalf("minted permissions = %v, want both narrowed to read", app.lastPerms)
	}
}

func TestExchange_NarrowingCanDropAPermissionEntirely(t *testing.T) {
	app := narrowingApp()
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowGETRequest("permission=contents:write"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(app.lastPerms) != 1 {
		t.Fatalf("minted permissions = %v, want issues dropped", app.lastPerms)
	}
}

// TestExchange_EscalationAttemptsRejected covers the security property: a
// request may only ever reduce privilege. Each case must fail with 400
// before any token is minted.
func TestExchange_EscalationAttemptsRejected(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "permission not in policy", query: "permission=packages:write"},
		{name: "level above ceiling", query: "permission=contents:admin"},
		{name: "unknown permission name", query: "permission=not_real:read"},
		{name: "unknown level", query: "permission=contents:bogus"},
		{name: "malformed pair", query: "permission=contents"},
		{name: "one valid one escalating", query: "permission=contents:read&permission=packages:write"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := narrowingApp()
			h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

			w := httptest.NewRecorder()
			h.ServeHTTP(w, narrowGETRequest(tt.query))

			assertErrorCode(t, w, http.StatusBadRequest, CodeBadRequest)
			if app.mintCalls != 0 {
				t.Fatalf("mint calls = %d, want 0 — no token may be issued for a rejected request", app.mintCalls)
			}
		})
	}
}

// TestExchange_EscalationRejectionDoesNotLeakPolicy checks that the 400 body
// says nothing about which permissions the policy does or does not grant. A
// caller that cannot read the trust policy must not be able to map it out by
// probing this endpoint.
func TestExchange_EscalationRejectionDoesNotLeakPolicy(t *testing.T) {
	app := narrowingApp()
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowGETRequest("permission=packages:write"))

	assertErrorCode(t, w, http.StatusBadRequest, CodeBadRequest)
	body := w.Body.String()
	for _, leaked := range []string{"packages", "contents", "issues", "write", "read"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("response body leaks policy detail %q: %s", leaked, body)
		}
	}
}

// TestExchange_EmptyPermissionsObjectRejected: an explicitly empty object is
// not the same as an absent one. Treating it as "everything" would hand a
// full-privilege token to a caller whose intent was clearly the opposite.
func TestExchange_EmptyPermissionsObjectRejected(t *testing.T) {
	app := narrowingApp()
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowPOSTRequest(t, map[string]string{}))

	assertErrorCode(t, w, http.StatusBadRequest, CodeBadRequest)
	if app.mintCalls != 0 {
		t.Fatalf("mint calls = %d, want 0", app.mintCalls)
	}
}

// TestExchange_ResponseReportsGitHubGrantNotPolicy pins the response contract:
// the permissions field describes the token GitHub actually issued. Here the
// fake reports metadata:read on top of the ask, exactly as GitHub does.
func TestExchange_ResponseReportsGitHubGrantNotPolicy(t *testing.T) {
	app := narrowingApp()
	app.grantedPerms = map[string]string{"contents": "read", "metadata": "read"}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{pol: narrowingPolicy()}, &recordingAuditLogger{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, narrowGETRequest("permission=contents:read"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp ExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Permissions["metadata"] != "read" || resp.Permissions["contents"] != "read" {
		t.Fatalf("response permissions = %v, want GitHub's actual grant", resp.Permissions)
	}
	if _, ok := resp.Permissions["issues"]; ok {
		t.Fatalf("response permissions = %v, must not echo the policy ceiling", resp.Permissions)
	}
}

func TestParsePermissionParams(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    map[string]string
		wantErr bool
	}{
		{name: "none means no narrowing", values: nil, want: nil},
		{name: "single pair", values: []string{"contents:read"}, want: map[string]string{"contents": "read"}},
		{
			name:   "multiple pairs",
			values: []string{"contents:read", "issues:write"},
			want:   map[string]string{"contents": "read", "issues": "write"},
		},
		{name: "repeated identical pair collapses", values: []string{"contents:read", "contents:read"}, want: map[string]string{"contents": "read"}},
		{name: "contradictory repeat rejected", values: []string{"contents:read", "contents:write"}, wantErr: true},
		{name: "missing separator rejected", values: []string{"contents"}, wantErr: true},
		{name: "empty value rejected", values: []string{""}, wantErr: true},
		{name: "label-injection characters rejected", values: []string{"contents:read\nx"}, wantErr: true},
		{name: "empty level rejected", values: []string{"contents:"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePermissionParams(tt.values)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}
