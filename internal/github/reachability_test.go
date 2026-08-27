package github

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassifyNetError_Timeout(t *testing.T) {
	err := context.DeadlineExceeded
	if got := classifyNetError(err); got != "timeout" {
		t.Errorf("expected timeout, got %s", got)
	}
}

func TestClassifyNetError_ConnectionError(t *testing.T) {
	err := errors.New("connection refused")
	if got := classifyNetError(err); got != "connection_error" {
		t.Errorf("expected connection_error, got %s", got)
	}
}

func TestClassifyNetError_NetTimeout(t *testing.T) {
	err := &net.DNSError{IsTimeout: true}
	if got := classifyNetError(err); got != "timeout" {
		t.Errorf("expected timeout, got %s", got)
	}
}

func TestReachabilityProber_StartStop(t *testing.T) {
	prober := NewReachabilityProber(nil, "http://localhost", 10*60*1e9)
	prober.Start()
	prober.Stop()
}

func TestReachabilityProber_IsReachable_DefaultsTrueWhenUnknown(t *testing.T) {
	prober := NewReachabilityProber(nil, "http://localhost", time.Hour)
	if !prober.IsReachable("checkout", "checkout-1") {
		t.Error("IsReachable should default to true before any probe has run")
	}
}

func TestReachabilityProber_ProbeInstance_UpdatesStateAndMetrics(t *testing.T) {
	// Exercises the label-arity of every metric probeInstance touches
	// (GitHubReachable, GitHubReachabilityCheckDuration,
	// GitHubReachabilityFailuresTotal — all gained an "instance" label) and
	// the IsReachable accessor AppPool's baseline filter depends on.
	key := generateTestKey(t)

	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upSrv.Close()

	downSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer downSrv.Close()

	// One prober per mock server: apiURL is prober-wide (mirrors
	// production, where every instance is probed against the same GitHub
	// API base URL), so simulating two different outcomes needs two
	// probers rather than one prober with mixed instances.
	up := NewReachabilityProber(
		[]PoolInstanceConfig{{LogicalApp: "checkout", Instance: "checkout-1", AppConfig: AppConfig{AppID: 1, PrivateKey: key}}},
		upSrv.URL, time.Hour,
	)
	up.probeAll(context.Background())
	if !up.IsReachable("checkout", "checkout-1") {
		t.Error("expected checkout-1 to be reachable after a 200 probe")
	}

	down := NewReachabilityProber(
		[]PoolInstanceConfig{{LogicalApp: "checkout", Instance: "checkout-2", AppConfig: AppConfig{AppID: 2, PrivateKey: key}}},
		downSrv.URL, time.Hour,
	)
	down.probeAll(context.Background())
	if down.IsReachable("checkout", "checkout-2") {
		t.Error("expected checkout-2 to be unreachable after a 503 probe")
	}
	// A different (logicalApp, instance) pair than the one just probed must
	// still default to true — confirms the state map is keyed correctly
	// and doesn't leak "unreachable" onto unrelated instances.
	if !down.IsReachable("checkout", "checkout-3") {
		t.Error("expected an unprobed instance to still default to true")
	}
}
