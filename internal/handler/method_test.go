package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/oidc"
)

// TestExchange_RefusedMethodTouchesNothing proves a refused method is
// answered before the token, the replay cache, the policy or GitHub is
// consulted. HEAD and OPTIONS are included because the exchange serves
// neither.
func TestExchange_RefusedMethodTouchesNothing(t *testing.T) {
	methods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			app := &mockExchangeApp{}
			loader := &mockPolicyLoader{pol: validExchangePolicy("2001", "3001")}
			jtiCache := &mockJTICache{isNew: true}
			h := authorizedExchangeHandler(app, loader, &recordingAuditLogger{})
			h.jtiCache = jtiCache
			h.validator = func(_ context.Context, _ string, _ []string) (oidc.Claims, error) {
				t.Error("refused method reached the OIDC validator")
				return nil, errors.New("validator must not be called")
			}
			req := httptest.NewRequest(method, "/sts/exchange?scope=org/target&identity=ci&app=test-app", nil)
			req.Header.Set("Authorization", "Bearer accepted")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			assertErrorCode(t, w, http.StatusMethodNotAllowed, CodeMethodNotAllowed)
			if got := w.Header().Get("Allow"); got != "GET, POST" {
				t.Errorf("Allow = %q, want %q", got, "GET, POST")
			}
			if jtiCache.reserveCalls != 0 || loader.loadCalls != 0 || app.resolveCalls != 0 || app.mintCalls != 0 {
				t.Errorf("calls: jti reserve %d, policy load %d, resolve %d, mint %d; want all 0",
					jtiCache.reserveCalls, loader.loadCalls, app.resolveCalls, app.mintCalls)
			}
		})
	}
}

func TestRefusedMethod_NamesTheAllowedMethods(t *testing.T) {
	tests := []struct {
		name    string
		handler func(t *testing.T) http.Handler
		path    string
		allow   string
	}{
		{
			name:    "validate",
			handler: func(*testing.T) http.Handler { return NewPolicyValidationHandler() },
			path:    "/sts/v1/trust-policy/validate",
			allow:   "POST",
		},
		{
			name:    "schema",
			handler: func(t *testing.T) http.Handler { return NewSchemaHandler(&refusingManager{t: t}) },
			path:    "/sts/v1/trust-policy.json",
			allow:   "GET, HEAD",
		},
	}
	for _, tt := range tests {
		for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				w := httptest.NewRecorder()
				tt.handler(t).ServeHTTP(w, httptest.NewRequest(method, tt.path, nil))

				assertErrorCode(t, w, http.StatusMethodNotAllowed, CodeMethodNotAllowed)
				if got := w.Header().Get("Allow"); got != tt.allow {
					t.Errorf("Allow = %q, want %q", got, tt.allow)
				}
			})
		}
	}
}

// refusingManager is a bundle.Manager that fails the test on any call, so a
// refused method that reaches the bundle is caught.
type refusingManager struct{ t *testing.T }

func (m *refusingManager) Eval(context.Context, bundle.Input) (bundle.Decision, error) {
	m.t.Error("refused method reached bundle Eval")
	return bundle.Decision{}, nil
}

func (m *refusingManager) Digest() string {
	m.t.Error("refused method reached bundle Digest")
	return ""
}

func (m *refusingManager) Enabled() bool {
	m.t.Error("refused method reached bundle Enabled")
	return false
}

func (m *refusingManager) Enforcement() string {
	m.t.Error("refused method reached bundle Enforcement")
	return ""
}

func (m *refusingManager) BundleFile(string) ([]byte, error) {
	m.t.Error("refused method reached bundle BundleFile")
	return nil, bundle.ErrDisabled
}

func (m *refusingManager) BundleStatuses() []bundle.Status {
	m.t.Error("refused method reached bundle BundleStatuses")
	return nil
}
