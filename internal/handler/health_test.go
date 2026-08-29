package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
)

func TestHealthHandler_Always200(t *testing.T) {
	h := HealthHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
}

func TestHealthHandler_SecurityPosture(t *testing.T) {
	h := HealthHandler(nil, SecurityPosture{
		RequireImmutableSubjectClaims: false,
		BundleEnforcement:             bundle.EnforcementOptional,
		YAMLOnlyAuthorizationPossible: true,
	})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	security, ok := body["security"].(map[string]any)
	if !ok {
		t.Fatalf("body.security missing or wrong shape: %v", body)
	}
	want := map[string]any{
		"require_immutable_subject_claims": false,
		"bundle_enforcement":               bundle.EnforcementOptional,
		"yaml_only_authorization_possible": true,
	}
	if !reflect.DeepEqual(security, want) {
		t.Errorf("security = %#v, want %#v", security, want)
	}
}

// fakeBundleReporter satisfies BundleHealthReporter for testing /health.
type fakeBundleReporter struct {
	digest    string
	enabled   bool
	age       float64
	err       error
	available *bool
}

func (f *fakeBundleReporter) Digest() string { return f.digest }
func (f *fakeBundleReporter) Enabled() bool  { return f.enabled }
func (f *fakeBundleReporter) Available() bool {
	if f.available != nil {
		return *f.available
	}
	return f.enabled
}
func (f *fakeBundleReporter) AgeSeconds() float64  { return f.age }
func (f *fakeBundleReporter) LastPullError() error { return f.err }
func (f *fakeBundleReporter) BundleStatuses() []bundle.Status {
	st := bundle.Status{Name: "test", Enabled: f.enabled, Digest: f.digest, AgeSeconds: f.age}
	if f.err != nil {
		st.LastPullError = f.err.Error()
	}
	return []bundle.Status{st}
}

// TestHealthHandler_BundleStatus counter-validates that /health
// surfaces bundle state to operators without log access: the loaded
// digest, age, and last pull error are all in the response body when
// a reporter is wired. A healthy bundle has no last_pull_error key
// (operators can grep for its presence).
func TestHealthHandler_BundleStatus(t *testing.T) {
	rep := &fakeBundleReporter{
		digest:  "sha256:abc",
		enabled: true,
		age:     42.5,
	}
	h := HealthHandler(rep)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (liveness is independent of bundle freshness)", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	b, ok := body["bundle"].(map[string]any)
	if !ok {
		t.Fatalf("body.bundle missing or wrong shape: %v", body)
	}
	if b["digest"] != "sha256:abc" {
		t.Errorf("bundle.digest = %v, want sha256:abc", b["digest"])
	}
	if b["enabled"] != true {
		t.Errorf("bundle.enabled = %v, want true", b["enabled"])
	}
	if _, has := b["last_pull_error"]; has {
		t.Errorf("bundle.last_pull_error present on healthy bundle; want omitted")
	}
}

// TestHealthHandler_BundleLastPullError counter-validates that a
// non-nil LastPullError surfaces in the JSON. Operators rely on this
// to alert "bundle reload failing without restarting the broker."
func TestHealthHandler_BundleLastPullError(t *testing.T) {
	rep := &fakeBundleReporter{
		digest:  "sha256:def",
		enabled: true,
		age:     900,
		err:     fmt.Errorf("registry timeout"),
	}
	h := HealthHandler(rep)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	b := body["bundle"].(map[string]any)
	if b["last_pull_error"] != "registry timeout" {
		t.Errorf("bundle.last_pull_error = %v, want %q", b["last_pull_error"], "registry timeout")
	}
}

func TestHealthHandler_RequiredBundleUnavailable(t *testing.T) {
	available := false
	rep := &fakeBundleReporter{enabled: true, available: &available}
	h := HealthHandler(rep, SecurityPosture{
		BundleEnforcement: bundle.EnforcementRequired,
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	bundleStatus := body["bundle"].(map[string]any)
	if bundleStatus["enabled"] != false {
		t.Fatalf("bundle.enabled = %v, want false when mandatory policy is unavailable", bundleStatus["enabled"])
	}
}

func TestReadinessHandler_Ready(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	h := ReadinessHandler(ready)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var body map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&body)
	if !body["ready"] {
		t.Error("ready should be true")
	}
}

func TestReadinessHandler_NotReady(t *testing.T) {
	ready := &atomic.Bool{} // defaults to false
	h := ReadinessHandler(ready)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}

	var body map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["ready"] {
		t.Error("ready should be false")
	}
}

func TestOptionalBearerAuth_HealthEndpoint(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	h := OptionalBearerAuth("health-secret", "health", inner)

	tests := []struct {
		name          string
		authorization string
		wantStatus    int
	}{
		{name: "missing token", wantStatus: http.StatusUnauthorized},
		{name: "invalid token", authorization: "Bearer wrong-secret", wantStatus: http.StatusUnauthorized},
		{name: "case-insensitive scheme", authorization: "bearer health-secret", wantStatus: http.StatusOK},
		{name: "valid token", authorization: "Bearer health-secret", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusUnauthorized {
				if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="health"` {
					t.Errorf("WWW-Authenticate = %q, want health Bearer challenge", got)
				}
				if got := w.Header().Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", got)
				}
			}
		})
	}
}

func TestMetricsHandler_NoAuthToken(t *testing.T) {
	h := MetricsHandler("")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Without auth token configured, metrics are publicly accessible.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMetricsHandler_ValidToken(t *testing.T) {
	h := MetricsHandler("secret-token")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMetricsHandler_AuthSchemeIsCaseInsensitive(t *testing.T) {
	h := MetricsHandler("secret-token")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "bearer secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMetricsHandler_InvalidToken(t *testing.T) {
	h := MetricsHandler("secret-token")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="metrics"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", got)
	}
}

func TestMetricsHandler_MissingAuth(t *testing.T) {
	h := MetricsHandler("secret-token")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// Length-mismatch hits a different branch in subtle.ConstantTimeCompare
// (returns 0 without comparing bytes). Verify it still rejects correctly.
func TestMetricsHandler_LengthMismatch(t *testing.T) {
	h := MetricsHandler("secret-token")
	cases := []string{
		"",                                      // empty
		"Bearer ",                               // prefix only
		"Bearer secret-tok",                     // shorter than expected
		"Bearer secret-token-with-extra-suffix", // longer than expected
		"secret-token",                          // missing scheme
		"Basic secret-token",                    // wrong scheme
	}
	for _, hdr := range cases {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization=%q: status = %d, want 401", hdr, w.Code)
		}
	}
}
