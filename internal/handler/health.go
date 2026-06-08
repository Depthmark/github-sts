package handler

import (
	"crypto/subtle"
	"net/http"
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
	AgeSeconds() float64
	LastPullError() error
	BundleStatuses() []bundle.Status
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
func HealthHandler(bundle BundleHealthReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"status": "ok"}
		if bundle != nil {
			b := map[string]any{
				"enabled":     bundle.Enabled(),
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
	expected := []byte("Bearer " + authToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// subtle.ConstantTimeCompare returns 0 when the lengths differ,
		// without leaking which prefix bytes match. The expected length is
		// not a secret (it is fixed per deployment), so the length-only
		// fastpath is acceptable.
		if subtle.ConstantTimeCompare(got, expected) != 1 {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}
		inner.ServeHTTP(w, r)
	})
}
