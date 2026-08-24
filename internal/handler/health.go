package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// BundleHealthReporter exposes the bits of bundle state the /health
// endpoint surfaces. Implemented by bundle lifecycle managers. Kept as a
// small interface so the reporter is easy to fake in handler tests.
type BundleHealthReporter interface {
	Digest() string
	Enabled() bool
	Available() bool
	AgeSeconds() float64
	LastPullError() error
	BundleStatuses() []bundle.Status
}

// SecurityPosture exposes security-sensitive compatibility switches in health
// output without affecting liveness.
type SecurityPosture struct {
	RequireImmutableSubjectClaims bool   `json:"require_immutable_subject_claims"`
	LegacySubjectOptOut           bool   `json:"legacy_subject_opt_out"`
	BundleEnforcement             string `json:"bundle_enforcement"`
	EnterprisePolicyRequired      bool   `json:"enterprise_policy_required"`
	YAMLOnlyAuthorization         bool   `json:"yaml_only_authorization"`
}

// HealthHandler returns a handler for the liveness probe.
// Always returns 200 — if the process is alive, it's healthy.
//
// When bundle is non-nil, the response body includes bundle status
// (digest, age, last pull error) so operators can confirm "the
// integration is wired and refreshing" without needing log or metric
// access. The endpoint stays 200 even when last_pull_error is set —
// liveness is unaffected; staleness handling lives in the exchange
// path. A future /ready could degrade on bundle_age_seconds, but
// liveness must not (kubelet would restart on every transient pull
// failure).
func HealthHandler(bundle BundleHealthReporter, posture ...SecurityPosture) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"status": "ok"}
		if len(posture) > 0 {
			resp["security"] = posture[0]
		}
		if bundle != nil {
			b := map[string]any{
				"enabled":     bundle.Available(),
				"digest":      bundle.Digest(),
				"age_seconds": bundle.AgeSeconds(),
			}
			if err := bundle.LastPullError(); err != nil {
				b["last_pull_error"] = err.Error()
			}
			resp["bundle"] = b
			if statuses := bundle.BundleStatuses(); len(statuses) > 0 {
				resp["bundles"] = statuses
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// ReadinessHandler returns a handler for the readiness probe.
// Returns 200 when ready, 503 during startup/shutdown.
func ReadinessHandler(ready *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			writeJSON(w, http.StatusOK, map[string]bool{"ready": true})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"ready": false})
		}
	}
}

// MetricsHandler returns the Prometheus metrics exposition handler.
// If authToken is non-empty, requests must include a matching
// Authorization: Bearer <token> header. The comparison is constant-time to
// prevent timing-oracle recovery of the token byte-by-byte.
func MetricsHandler(authToken string) http.Handler {
	inner := promhttp.Handler()
	if authToken == "" {
		return inner
	}
	expected := []byte(authToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, credential, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		// subtle.ConstantTimeCompare returns 0 when the lengths differ,
		// without leaking which prefix bytes match. The expected length is
		// not a secret (it is fixed per deployment), so the length-only
		// fastpath is acceptable.
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(credential), expected) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}
		inner.ServeHTTP(w, r)
	})
}
