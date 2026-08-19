package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// newMockGitHubServer returns an httptest server that resolves any
// installation lookup to installationID and delegates token-minting
// requests to tokenHandler.
func newMockGitHubServer(installationID int64, tokenHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": installationID})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			tokenHandler(w, r)
		}
	}))
}

// newMockMember builds a PoolMember whose provider talks to apiURL.
func newMockMember(t *testing.T, instance, apiURL string) PoolMember {
	t.Helper()
	key := generateTestKey(t)
	return PoolMember{
		Instance: instance,
		Provider: NewAppTokenProvider("checkout", instance, 1, key, apiURL, nil),
	}
}

func succeedHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func statusHandler(status int, headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
	}
}

func countingHandler(counter *int32, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(counter, 1)
		next(w, r)
	}
}

// fakeReachability implements ReachabilityChecker for tests: every instance
// named in down is reported unreachable, everyone else reachable.
type fakeReachability struct {
	down map[string]bool
}

func (f *fakeReachability) IsReachable(_, instance string) bool {
	return !f.down[instance]
}

func TestAppPool_RoundRobin_DistributesEvenly(t *testing.T) {
	var callsA, callsB, callsC int32
	srvA := newMockGitHubServer(1, countingHandler(&callsA, succeedHandler("tok-a")))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, countingHandler(&callsB, succeedHandler("tok-b")))
	defer srvB.Close()
	srvC := newMockGitHubServer(1, countingHandler(&callsC, succeedHandler("tok-c")))
	defer srvC.Close()

	members := []PoolMember{
		newMockMember(t, "a", srvA.URL),
		newMockMember(t, "b", srvB.URL),
		newMockMember(t, "c", srvC.URL),
	}
	pool := NewAppPool("checkout", members, "round_robin", 0, 3, nil)

	const n = 300
	for i := 0; i < n; i++ {
		if _, _, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test"); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	want := int32(n / 3)
	if callsA != want || callsB != want || callsC != want {
		t.Errorf("call distribution = {a:%d b:%d c:%d}, want {a:%d b:%d c:%d} (perfectly even ring rotation)",
			callsA, callsB, callsC, want, want, want)
	}
}

func TestAppPool_BaselineFilter_SkipsUnreachableInstance(t *testing.T) {
	var callsA, callsB, callsC int32
	srvA := newMockGitHubServer(1, countingHandler(&callsA, succeedHandler("tok-a")))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, countingHandler(&callsB, succeedHandler("tok-b")))
	defer srvB.Close()
	srvC := newMockGitHubServer(1, countingHandler(&callsC, succeedHandler("tok-c")))
	defer srvC.Close()

	members := []PoolMember{
		newMockMember(t, "a", srvA.URL),
		newMockMember(t, "b", srvB.URL),
		newMockMember(t, "c", srvC.URL),
	}
	reach := &fakeReachability{down: map[string]bool{"b": true}}
	pool := NewAppPool("checkout", members, "round_robin", 0, 3, reach)

	for i := 0; i < 30; i++ {
		_, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if instance == "b" {
			t.Fatalf("call %d: instance b was selected despite being reported unreachable", i)
		}
	}

	// Not just "skipped once" — the baseline filter must keep skipping it
	// on every single request, not fall back to hammering it.
	if callsB != 0 {
		t.Errorf("instance b's server received %d calls, want 0", callsB)
	}
	if callsA == 0 || callsC == 0 {
		t.Errorf("expected traffic split across a (%d) and c (%d)", callsA, callsC)
	}
}

func TestAppPool_EmptyCandidateSet_FallsBackToLiveAttempt(t *testing.T) {
	// Every instance looks unreachable per (stale) local state. The pool
	// must not fail pre-emptively on that alone — it should still make a
	// live attempt, since a locally-cached "probably down" is not
	// authoritative the way a live GitHub response is.
	srvA := newMockGitHubServer(1, succeedHandler("tok-a"))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, succeedHandler("tok-b"))
	defer srvB.Close()

	members := []PoolMember{
		newMockMember(t, "a", srvA.URL),
		newMockMember(t, "b", srvB.URL),
	}
	reach := &fakeReachability{down: map[string]bool{"a": true, "b": true}}
	pool := NewAppPool("checkout", members, "round_robin", 0, 2, reach)

	token, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
	if err != nil {
		t.Fatalf("expected a live attempt despite every instance marked unreachable, got error: %v", err)
	}
	if instance != "a" && instance != "b" {
		t.Errorf("instance = %q, want a or b", instance)
	}
	if token == "" {
		t.Error("expected a non-empty token")
	}
}

func TestAppPool_Failover_OnRetryableStatus(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"403 primary rate limit", statusHandler(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"})},
		{"403 secondary rate limit", statusHandler(http.StatusForbidden, map[string]string{"Retry-After": "30"})},
		{"5xx", statusHandler(http.StatusServiceUnavailable, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failCalls int32
			failSrv := newMockGitHubServer(1, countingHandler(&failCalls, tt.handler))
			defer failSrv.Close()
			okSrv := newMockGitHubServer(1, succeedHandler("tok-ok"))
			defer okSrv.Close()

			members := []PoolMember{
				newMockMember(t, "fail-me", failSrv.URL),
				newMockMember(t, "succeed-me", okSrv.URL),
			}
			pool := NewAppPool("checkout", members, "round_robin", 0, 2, nil)

			// Run several calls: whichever position the ring cursor starts
			// at, every single call must still succeed via succeed-me,
			// whether on the first try or after one failover.
			for i := 0; i < 4; i++ {
				token, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
				if err != nil {
					t.Fatalf("call %d: unexpected error: %v", i, err)
				}
				if instance != "succeed-me" || token != "tok-ok" {
					t.Errorf("call %d: instance=%q token=%q, want succeed-me/tok-ok", i, instance, token)
				}
			}
			if atomic.LoadInt32(&failCalls) == 0 {
				t.Error("fail-me was never invoked — this test never actually exercised failover")
			}
		})
	}
}

func TestAppPool_Failover_OnTransportError(t *testing.T) {
	// A closed server simulates a network/transport error.
	deadSrv := newMockGitHubServer(1, succeedHandler("unused"))
	deadSrv.Close()
	okSrv := newMockGitHubServer(1, succeedHandler("tok-ok"))
	defer okSrv.Close()

	members := []PoolMember{
		newMockMember(t, "fail-me", deadSrv.URL),
		newMockMember(t, "succeed-me", okSrv.URL),
	}
	pool := NewAppPool("checkout", members, "round_robin", 0, 2, nil)

	for i := 0; i < 4; i++ {
		token, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if instance != "succeed-me" || token != "tok-ok" {
			t.Errorf("call %d: instance=%q token=%q, want succeed-me/tok-ok", i, instance, token)
		}
	}
}

func TestAppPool_NoFailover_On422(t *testing.T) {
	var okCalls int32
	failSrv := newMockGitHubServer(1, statusHandler(http.StatusUnprocessableEntity, nil))
	defer failSrv.Close()
	okSrv := newMockGitHubServer(1, countingHandler(&okCalls, succeedHandler("tok-ok")))
	defer okSrv.Close()

	// Force the 422 member to be tried first by making it the pool's only
	// reachable-looking candidate on the first attempt is not guaranteed by
	// ring position alone, so instead assert on the pool-of-2 outcome
	// directly: since 422 is never retried, if the ring happens to try
	// "always-422" first, the whole request must fail without ever
	// reaching "succeed-me".
	members := []PoolMember{
		newMockMember(t, "always-422", failSrv.URL),
		newMockMember(t, "succeed-me", okSrv.URL),
	}
	pool := NewAppPool("checkout", members, "round_robin", 0, 2, nil)

	sawFailure := false
	for i := 0; i < 4; i++ {
		_, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if err != nil {
			sawFailure = true
			if instance != "" {
				t.Errorf("call %d: instance = %q on failure, want empty", i, instance)
			}
			if !strings.Contains(err.Error(), "422") {
				t.Errorf("call %d: error = %v, want it to mention 422", i, err)
			}
			continue
		}
		if instance != "succeed-me" {
			t.Errorf("call %d: instance = %q, want succeed-me (422 must never be failed over *into*, only *out of*)", i, instance)
		}
	}
	if !sawFailure {
		t.Fatal("always-422 was never selected first across 4 calls — this test never exercised the no-failover-on-422 path")
	}
	if okCalls == 0 {
		t.Error("succeed-me was never reached — the ring never started on the other member either")
	}
}

func TestAppPool_NoFailover_OnCanceledContext(t *testing.T) {
	var callsA, callsB int32
	srvA := newMockGitHubServer(1, countingHandler(&callsA, statusHandler(http.StatusServiceUnavailable, nil)))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, countingHandler(&callsB, succeedHandler("tok-b")))
	defer srvB.Close()

	members := []PoolMember{
		newMockMember(t, "a", srvA.URL),
		newMockMember(t, "b", srvB.URL),
	}
	pool := NewAppPool("checkout", members, "round_robin", 0, 2, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, instance, err := pool.GetInstallationToken(ctx, "myorg", nil, nil, "test")
	if err == nil {
		t.Fatal("expected an error for an already-canceled context")
	}
	if instance != "" {
		t.Errorf("instance = %q, want empty on failure", instance)
	}
	if total := callsA + callsB; total > 1 {
		t.Errorf("total provider calls across both instances = %d, want at most 1 (no failover once ctx is done)", total)
	}
}

func TestAppPool_Exhaustion(t *testing.T) {
	srvA := newMockGitHubServer(1, statusHandler(http.StatusServiceUnavailable, nil))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, statusHandler(http.StatusServiceUnavailable, nil))
	defer srvB.Close()

	members := []PoolMember{
		newMockMember(t, "a", srvA.URL),
		newMockMember(t, "b", srvB.URL),
	}
	pool := NewAppPool("checkout", members, "round_robin", 0, 2, nil)

	_, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
	if err == nil {
		t.Fatal("expected an error when every instance fails")
	}
	if instance != "" {
		t.Errorf("instance = %q, want empty when the whole pool is exhausted", instance)
	}
	var mintErr *TokenMintError
	if !errors.As(err, &mintErr) {
		t.Fatalf("expected the final error to still be a *TokenMintError, got %T: %v", err, err)
	}
}

// TestAppPool_ZeroMaxAttempts_StillTriesAtLeastOnce guards against a
// zero/unset maxAttempts silently short-circuiting the attempt loop before
// it makes a single try — which would return a false ("", "", nil) success
// rather than actually contacting an instance. Config validation always
// defaults max_attempts to >= 1 before NewAppPool is constructed, but
// NewAppPool clamps defensively too, since that failure mode is severe and
// silent.
func TestAppPool_ZeroMaxAttempts_StillTriesAtLeastOnce(t *testing.T) {
	srv := newMockGitHubServer(1, succeedHandler("tok"))
	defer srv.Close()

	members := []PoolMember{newMockMember(t, "a", srv.URL)}
	pool := NewAppPool("checkout", members, "round_robin", 0, 0, nil)

	token, instance, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok" || instance != "a" {
		t.Errorf("token=%q instance=%q, want tok/a — a maxAttempts=0 pool must still try at least once, not silently no-op", token, instance)
	}
}

// TestAppPool_PoolOfOne_EquivalentToDirectProvider asserts the equivalence
// the backward-compatibility argument in the design doc depends on: a pool
// of exactly one instance must behave identically — same token/error, no
// retry attempts possible — to calling the wrapped *AppTokenProvider
// directly.
func TestAppPool_PoolOfOne_EquivalentToDirectProvider(t *testing.T) {
	t.Run("golden path", func(t *testing.T) {
		srv := newMockGitHubServer(1, succeedHandler("tok-direct"))
		defer srv.Close()

		key := generateTestKey(t)
		provider := NewAppTokenProvider("checkout", "checkout", 1, key, srv.URL, nil)
		directToken, directErr := provider.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if directErr != nil {
			t.Fatalf("direct call: unexpected error: %v", directErr)
		}

		pool := NewAppPool("checkout", []PoolMember{{Instance: "checkout", Provider: provider}}, "round_robin", 0, 1, nil)
		poolToken, poolInstance, poolErr := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if poolErr != nil {
			t.Fatalf("pool call: unexpected error: %v", poolErr)
		}
		if poolInstance != "checkout" {
			t.Errorf("pool instance = %q, want checkout", poolInstance)
		}
		if directToken != poolToken {
			t.Errorf("direct token = %q, pool token = %q, want identical", directToken, poolToken)
		}
	})

	t.Run("failure path", func(t *testing.T) {
		srv := newMockGitHubServer(1, statusHandler(http.StatusServiceUnavailable, nil))
		defer srv.Close()

		key := generateTestKey(t)
		directProvider := NewAppTokenProvider("checkout", "checkout", 1, key, srv.URL, nil)
		_, directErr := directProvider.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if directErr == nil {
			t.Fatal("direct call: expected an error")
		}

		poolProvider := NewAppTokenProvider("checkout", "checkout", 1, key, srv.URL, nil)
		pool := NewAppPool("checkout", []PoolMember{{Instance: "checkout", Provider: poolProvider}}, "round_robin", 0, 1, nil)
		_, poolInstance, poolErr := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "test")
		if poolErr == nil {
			t.Fatal("pool call: expected an error")
		}
		if poolInstance != "" {
			t.Errorf("pool instance = %q, want empty on failure", poolInstance)
		}
		// A pool of 1 has nowhere to fail over to — same error shape as
		// calling the provider directly.
		if directErr.Error() != poolErr.Error() {
			t.Errorf("direct error = %q\npool error   = %q\nwant identical (pool-of-1 has no failover)", directErr.Error(), poolErr.Error())
		}
	})
}
