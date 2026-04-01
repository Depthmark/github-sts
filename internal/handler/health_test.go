package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHealthHandler_Always200(t *testing.T) {
	h := HealthHandler()
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

func TestMetricsHandler_InvalidToken(t *testing.T) {
	h := MetricsHandler("secret-token")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
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
