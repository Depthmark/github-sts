package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/oidc"
	"github.com/depthmark/github-sts/internal/policy"
)

const testEnterpriseIssuer = oidc.GitHubActionsIssuer + "/octocat-inc"

// enterpriseClaims matches a token from GitHub's enterprise issuer: only iss
// differs from the claims authorizedExchangeHandler uses for the default one.
func enterpriseClaims() oidc.Claims {
	return oidc.Claims{
		"iss": testEnterpriseIssuer, "sub": authorizedSubject,
		"aud": "https://example.test/sts", "jti": "enterprise-jti", "ref": "refs/heads/main",
		"repository": "org/source", "repository_owner": "org",
		"repository_id": "2001", "repository_owner_id": "1001",
		"enterprise": "octocat-inc", "enterprise_id": "42",
	}
}

func enterprisePolicy() *policy.TrustPolicy {
	pol := validExchangePolicy("2001", "3001")
	pol.Issuer = testEnterpriseIssuer
	return pol
}

func targetApp() *mockExchangeApp {
	return &mockExchangeApp{target: github.TargetIdentity{
		Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
	}}
}

func declaredIssuerHandler(t *testing.T, app *mockExchangeApp, loader *mockPolicyLoader, al *recordingAuditLogger, claims oidc.Claims, enabledApps ...string) (*ExchangeHandler, *mockJTICache) {
	t.Helper()
	jtiCache := &mockJTICache{isNew: true}
	h := &ExchangeHandler{
		jtiCache:                      jtiCache,
		policyLoader:                  loader,
		appProviders:                  map[string]github.ExchangeApp{"test-app": app, "other-app": app},
		allowedIssuers:                []string{oidc.GitHubActionsIssuer, testEnterpriseIssuer},
		requireImmutableSubjectClaims: true,
		auditLogger:                   al,
		slogger:                       slog.New(slog.NewTextHandler(io.Discard, nil)),
		bundleManager:                 bundle.Disabled{},
		validator: func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
			return claims, nil
		},
	}
	h.SetGitHubIssuers([]oidc.GitHubIssuer{{
		Issuer:   testEnterpriseIssuer,
		Instance: oidc.GitHubDotComInstance,
		Apps:     enabledApps,
	}})
	return h, jtiCache
}

func TestExchange_DeclaredIssuerSucceedsWithExactIDs(t *testing.T) {
	app := targetApp()
	loader := &mockPolicyLoader{pol: enterprisePolicy()}
	al := &recordingAuditLogger{}
	h, _ := declaredIssuerHandler(t, app, loader, al, enterpriseClaims(), "test-app")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if app.mintCalls != 1 {
		t.Fatalf("mint calls = %d, want 1", app.mintCalls)
	}
	event := al.lastEvent()
	if event.Issuer != testEnterpriseIssuer {
		t.Fatalf("audit issuer = %q, want %q", event.Issuer, testEnterpriseIssuer)
	}
	if event.SourceRepositoryID != "2001" || event.SourceRepositoryOwnerID != "1001" {
		t.Fatalf("audit source identity missing: %+v", event)
	}
	if event.ImmutableSubject == nil || !*event.ImmutableSubject {
		t.Fatalf("audit immutable_subject = %v, want true", event.ImmutableSubject)
	}
	if event.ImmutableSubjectRequired == nil || !*event.ImmutableSubjectRequired {
		t.Fatalf("audit immutable_subject_required = %v, want true", event.ImmutableSubjectRequired)
	}
}

// Each case is a rejection the default issuer also makes, and every one stops
// before state, policy or GitHub.
func TestExchange_DeclaredIssuerIdentityInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(oidc.Claims)
	}{
		{"mismatched repository_id", func(c oidc.Claims) { c["repository_id"] = "9999" }},
		{"mismatched repository_owner_id", func(c oidc.Claims) { c["repository_owner_id"] = "9999" }},
		{"missing repository_id", func(c oidc.Claims) { delete(c, "repository_id") }},
		{"missing repository_owner_id", func(c oidc.Claims) { delete(c, "repository_owner_id") }},
		{"subject names another repository", func(c oidc.Claims) { c["sub"] = "repo:org@1001/other@2001:ref:refs/heads/main" }},
		{"legacy subject", func(c oidc.Claims) { c["sub"] = "repo:org/source:ref:refs/heads/main" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := enterpriseClaims()
			tt.mutate(claims)
			app := targetApp()
			loader := &mockPolicyLoader{pol: enterprisePolicy()}
			al := &recordingAuditLogger{}
			h, jtiCache := declaredIssuerHandler(t, app, loader, al, claims, "test-app")

			w := httptest.NewRecorder()
			h.ServeHTTP(w, authorizedExchangeRequest())

			assertErrorCode(t, w, http.StatusForbidden, CodeGitHubIdentityInvalid)
			if jtiCache.reserveCalls != 0 || loader.loadCalls != 0 || app.resolveCalls != 0 || app.mintCalls != 0 {
				t.Fatalf("work after identity failure: jti=%d load=%d resolve=%d mint=%d",
					jtiCache.reserveCalls, loader.loadCalls, app.resolveCalls, app.mintCalls)
			}
			if result := al.lastEvent().Result; result != audit.ResultOIDCInvalid {
				t.Fatalf("audit result = %q, want %q", result, audit.ResultOIDCInvalid)
			}
		})
	}
}

// A signed token with the right IDs and no immutable sub is still refused when
// the legacy switch is off for GitHub.com: the switch never reaches a declared
// issuer, while the default issuer keeps honouring it.
func TestExchange_LegacySwitchDoesNotRelaxDeclaredIssuer(t *testing.T) {
	claims := enterpriseClaims()
	claims["sub"] = "repo:org/source:ref:refs/heads/main"
	al := &recordingAuditLogger{}
	h, _ := declaredIssuerHandler(t, targetApp(), &mockPolicyLoader{pol: enterprisePolicy()}, al, claims, "test-app")
	h.requireImmutableSubjectClaims = false

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())
	assertErrorCode(t, w, http.StatusForbidden, CodeGitHubIdentityInvalid)
	if required := al.lastEvent().ImmutableSubjectRequired; required == nil || !*required {
		t.Fatalf("audit immutable_subject_required = %v, want true", required)
	}

	defaultClaims := enterpriseClaims()
	defaultClaims["iss"] = oidc.GitHubActionsIssuer
	defaultClaims["sub"] = "repo:org/source:ref:refs/heads/main"
	pol := validExchangePolicy("2001", "3001")
	defaultAudit := &recordingAuditLogger{}
	defaultHandler, _ := declaredIssuerHandler(t, targetApp(), &mockPolicyLoader{pol: pol}, defaultAudit, defaultClaims, "test-app")
	defaultHandler.requireImmutableSubjectClaims = false

	w = httptest.NewRecorder()
	defaultHandler.ServeHTTP(w, authorizedExchangeRequest())
	if w.Code != http.StatusOK {
		t.Fatalf("default issuer under the legacy switch: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if required := defaultAudit.lastEvent().ImmutableSubjectRequired; required == nil || *required {
		t.Fatalf("default issuer audit immutable_subject_required = %v, want false", required)
	}
}

func TestExchange_DeclaredIssuerDeniedForAppThatDoesNotListIt(t *testing.T) {
	tests := []struct {
		name string
		// enabledApps is what the declaration lists; the request always uses test-app.
		enabledApps []string
	}{
		{name: "another app listed", enabledApps: []string{"other-app"}},
		{name: "no app listed", enabledApps: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := targetApp()
			loader := &mockPolicyLoader{pol: enterprisePolicy()}
			al := &recordingAuditLogger{}
			h, jtiCache := declaredIssuerHandler(t, app, loader, al, enterpriseClaims(), tt.enabledApps...)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, authorizedExchangeRequest())

			assertErrorCode(t, w, http.StatusForbidden, CodeIssuerNotEnabled)
			if app.resolveCalls != 0 || app.mintCalls != 0 || loader.loadCalls != 0 {
				t.Fatalf("GitHub reached after denial: resolve=%d mint=%d load=%d", app.resolveCalls, app.mintCalls, loader.loadCalls)
			}
			if jtiCache.reserveCalls != 1 {
				t.Fatalf("jti reserve calls = %d, want 1", jtiCache.reserveCalls)
			}
			event := al.lastEvent()
			if event.Result != audit.ResultPolicyDenied || event.AppName != "test-app" {
				t.Fatalf("audit = %q app %q, want %q app test-app", event.Result, event.AppName, audit.ResultPolicyDenied)
			}
		})
	}
}

// With one configured App, ?app= is optional; the check applies to the App the
// broker resolved, so omitting the parameter cannot skip it.
func TestExchange_DeclaredIssuerDeniedWhenAppIsImplicit(t *testing.T) {
	app := targetApp()
	al := &recordingAuditLogger{}
	h, _ := declaredIssuerHandler(t, app, &mockPolicyLoader{pol: enterprisePolicy()}, al, enterpriseClaims(), "other-app")
	h.appProviders = map[string]github.ExchangeApp{"test-app": app}

	req := httptest.NewRequest(http.MethodGet, "/sts/exchange?scope=org/target&identity=ci", nil)
	req.Header.Set("Authorization", "Bearer accepted")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assertErrorCode(t, w, http.StatusForbidden, CodeIssuerNotEnabled)
	if app.resolveCalls != 0 {
		t.Fatalf("resolve calls = %d, want 0", app.resolveCalls)
	}
}

func TestExchange_DeclaredIssuerRelationshipStillChecked(t *testing.T) {
	tests := []struct {
		name   string
		source string
		target string
	}{
		{name: "source not in the policy", source: "9999", target: "3001"},
		{name: "target not in the policy", source: "2001", target: "9999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := targetApp()
			pol := validExchangePolicy(tt.source, tt.target)
			pol.Issuer = testEnterpriseIssuer
			h, _ := declaredIssuerHandler(t, app, &mockPolicyLoader{pol: pol}, &recordingAuditLogger{}, enterpriseClaims(), "test-app")

			w := httptest.NewRecorder()
			h.ServeHTTP(w, authorizedExchangeRequest())

			assertErrorCode(t, w, http.StatusForbidden, CodePolicyDenied)
			if app.mintCalls != 0 {
				t.Fatalf("mint calls = %d, want 0", app.mintCalls)
			}
		})
	}
}

// A policy for the default issuer must not authorize an enterprise token that
// presents the same repository IDs, and the other way round.
func TestExchange_IssuersDoNotShareAPolicy(t *testing.T) {
	defaultToken := enterpriseClaims()
	defaultToken["iss"] = oidc.GitHubActionsIssuer

	tests := []struct {
		name   string
		claims oidc.Claims
		pol    *policy.TrustPolicy
	}{
		{name: "enterprise token, default issuer policy", claims: enterpriseClaims(), pol: validExchangePolicy("2001", "3001")},
		{name: "default token, enterprise issuer policy", claims: defaultToken, pol: enterprisePolicy()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := targetApp()
			h, _ := declaredIssuerHandler(t, app, &mockPolicyLoader{pol: tt.pol}, &recordingAuditLogger{}, tt.claims, "test-app")

			w := httptest.NewRecorder()
			h.ServeHTTP(w, authorizedExchangeRequest())

			assertErrorCode(t, w, http.StatusForbidden, CodePolicyDenied)
			if app.mintCalls != 0 {
				t.Fatalf("mint calls = %d, want 0", app.mintCalls)
			}
		})
	}
}

// Declaring an enterprise issuer must not limit the default one: it keeps
// reaching every App, including one the declaration leaves out.
func TestExchange_DefaultIssuerUnaffectedByDeclaration(t *testing.T) {
	claims := enterpriseClaims()
	claims["iss"] = oidc.GitHubActionsIssuer
	app := targetApp()
	h, _ := declaredIssuerHandler(t, app, &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}, &recordingAuditLogger{}, claims, "other-app")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// The handler re-validates each policy it loads, so a github block on an issuer
// nobody declared is refused even when the loader let it through.
func TestExchange_UndeclaredEnterpriseIssuerCannotUseGitHubBlock(t *testing.T) {
	app := targetApp()
	al := &recordingAuditLogger{}
	h, _ := declaredIssuerHandler(t, app, &mockPolicyLoader{pol: enterprisePolicy()}, al, enterpriseClaims(), "test-app")
	h.SetGitHubIssuers(nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	assertErrorCode(t, w, http.StatusForbidden, CodeTrustPolicyInvalid)
	if app.mintCalls != 0 {
		t.Fatalf("mint calls = %d, want 0", app.mintCalls)
	}
}

type recordingBundleManager struct {
	bundle.Disabled
	last bundle.Input
}

func (m *recordingBundleManager) Enabled() bool { return true }

func (m *recordingBundleManager) Eval(_ context.Context, input bundle.Input) (bundle.Decision, error) {
	m.last = input
	return bundle.Decision{Applicable: true, Evaluated: true, Allow: true}, nil
}

// The bundle Input contract is unchanged: same shape, with the enterprise issuer
// as the issuer value, so a Rego rule can tell the two issuers apart.
func TestExchange_DeclaredIssuerReachesBundleAsSourceIdentity(t *testing.T) {
	manager := &recordingBundleManager{}
	h, _ := declaredIssuerHandler(t, targetApp(), &mockPolicyLoader{pol: enterprisePolicy()}, &recordingAuditLogger{}, enterpriseClaims(), "test-app")
	h.bundleManager = manager
	h.requireImmutableSubjectClaims = false

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	source := manager.last.SourceIdentity
	if source == nil {
		t.Fatal("bundle input has no source_identity")
	}
	if source.Issuer != testEnterpriseIssuer || source.RepositoryID != "2001" {
		t.Fatalf("source_identity = %+v", source)
	}
	if !source.ImmutableSubjectRequired {
		t.Fatal("source_identity.immutable_subject_required = false, want true for a declared issuer")
	}
}

func TestPolicyValidationHandler_DeclaredIssuer(t *testing.T) {
	content := []byte(`issuer: ` + testEnterpriseIssuer + `
audience: https://sts.example.com
subject: repo:org@123456/repo@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
`)
	tests := []struct {
		name       string
		declared   []string
		wantStatus int
	}{
		{name: "declared", declared: []string{testEnterpriseIssuer}, wantStatus: http.StatusOK},
		{name: "not declared", wantStatus: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewReader(content))
			w := httptest.NewRecorder()
			NewPolicyValidationHandler(tt.declared...).ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestHealthHandler_ReportsDeclaredIssuers(t *testing.T) {
	h := HealthHandler(nil, SecurityPosture{
		BundleEnforcement: bundle.EnforcementRequired,
		GitHubIssuers: []GitHubIssuerPosture{{
			Issuer:                        testEnterpriseIssuer,
			Instance:                      oidc.GitHubDotComInstance,
			RequireImmutableSubjectClaims: true,
		}},
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body struct {
		Security struct {
			GitHubIssuers []map[string]any `json:"github_issuers"`
		} `json:"security"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Security.GitHubIssuers) != 1 {
		t.Fatalf("github_issuers = %v, want one entry", body.Security.GitHubIssuers)
	}
	got := body.Security.GitHubIssuers[0]
	if got["issuer"] != testEnterpriseIssuer || got["instance"] != oidc.GitHubDotComInstance || got["require_immutable_subject_claims"] != true {
		t.Fatalf("github_issuers[0] = %v", got)
	}
	if _, ok := got["apps"]; ok {
		t.Fatalf("github_issuers[0] exposes apps: %v", got)
	}
}
