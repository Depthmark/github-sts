package handler

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HealthHandler returns a handler for the liveness probe.
// Always returns 200 — if the process is alive, it's healthy.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
// Authorization: Bearer <token> header.
func MetricsHandler(authToken string) http.Handler {
	inner := promhttp.Handler()
	if authToken == "" {
		return inner
	}
	expected := "Bearer " + authToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expected {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}
		inner.ServeHTTP(w, r)
	})
}
