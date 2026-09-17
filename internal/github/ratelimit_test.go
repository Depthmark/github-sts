package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestParseLinkNext(t *testing.T) {
	tests := []struct {
		name string
		link string
		want string
	}{
		{
			name: "with next",
			link: `<https://api.github.com/app/installations?page=2>; rel="next", <https://api.github.com/app/installations?page=5>; rel="last"`,
			want: "https://api.github.com/app/installations?page=2",
		},
		{
			name: "no next",
			link: `<https://api.github.com/app/installations?page=5>; rel="last"`,
			want: "",
		},
		{
			name: "empty",
			link: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLinkNext(tt.link)
			if got != tt.want {
				t.Errorf("parseLinkNext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitPoller_StartStop(t *testing.T) {
	// Verify start/stop lifecycle doesn't panic.
	poller := NewRateLimitPoller(nil, "http://localhost", 10*time.Minute, nil, 5*time.Minute)
	poller.Start()
	poller.Stop()
}

// fakeBucket is one installation's primary rate-limit bucket.
type fakeBucket struct {
	account   string
	limit     int64
	remaining int64
	reset     int64
}

// fakeGitHub serves the three endpoints the poller uses: the installation
// list, token minting, and the conditional probe. Each installation has its
// own bucket, and like GitHub a 304 does not spend it.
type fakeGitHub struct {
	t *testing.T

	mu       sync.Mutex
	buckets  map[int64]*fakeBucket // installation ID → bucket
	tokens   map[string]int64      // token → installation ID
	mints    int
	probes   int
	etag     string
	omitETag bool

	// probeStatus, when set, overrides the probe response status.
	probeStatus func(n int) int
	// omitRemaining drops X-RateLimit-Remaining from probe responses.
	omitRemaining bool
	// uncountedNotModified makes a 304 report an unused bucket (used=0,
	// reset an hour out) instead of the installation's, which is what GitHub
	// does for installation tokens (V1b).
	uncountedNotModified bool
	// mintedPermissions records every mint request's permissions.
	mintedPermissions []map[string]any
}

func newFakeGitHub(t *testing.T, buckets map[int64]*fakeBucket) (*fakeGitHub, *httptest.Server) {
	t.Helper()
	f := &fakeGitHub{t: t, buckets: buckets, tokens: map[string]int64{}, etag: `W/"emojis-v1"`}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/app/installations":
		var page []map[string]any
		for id, b := range f.buckets {
			page = append(page, map[string]any{"id": id, "account": map[string]string{"login": b.account}})
		}
		_ = json.NewEncoder(w).Encode(page)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens"):
		idText := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app/installations/"), "/access_tokens")
		id, _ := strconv.ParseInt(idText, 10, 64)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		perms, _ := body["permissions"].(map[string]any)
		f.mintedPermissions = append(f.mintedPermissions, perms)
		f.mints++
		token := fmt.Sprintf("ghs_poller_%d_%d", id, f.mints)
		f.tokens[token] = id
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})

	case r.Method == http.MethodGet && r.URL.Path == rateLimitProbePath:
		f.probes++
		id, ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b := f.buckets[id]
		status := http.StatusOK
		if r.Header.Get("If-None-Match") == f.etag {
			status = http.StatusNotModified
		}
		if f.probeStatus != nil {
			status = f.probeStatus(f.probes)
		}
		if status == http.StatusOK && b.remaining > 0 {
			b.remaining--
		}
		remaining, reset := b.remaining, b.reset
		if status == http.StatusNotModified && f.uncountedNotModified {
			remaining, reset = b.limit, time.Now().Add(time.Hour).Unix()
		}
		h := w.Header()
		h.Set("X-RateLimit-Limit", strconv.FormatInt(b.limit, 10))
		if !f.omitRemaining {
			h.Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		}
		h.Set("X-RateLimit-Used", strconv.FormatInt(b.limit-remaining, 10))
		h.Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
		h.Set("X-RateLimit-Resource", "core")
		if status == http.StatusOK && !f.omitETag {
			h.Set("ETag", f.etag)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"+1":"https://github.githubassets.com/images/icons/emoji/unicode/1f44d.png"}`))
		}

	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeGitHub) spend(id, n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[id].remaining -= n
}

func (f *fakeGitHub) counts() (mints, probes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints, f.probes
}

func newTestPoller(t *testing.T, app string, srv *httptest.Server, quota *QuotaStore) *RateLimitPoller {
	t.Helper()
	instances := []PoolInstanceConfig{{
		LogicalApp: app,
		Instance:   "i1",
		AppConfig:  AppConfig{AppID: 1, PrivateKey: generateTestKey(t)},
	}}
	// A long forceCountedInterval here means existing probes stay purely
	// conditional (as before this poller could force a counted re-read);
	// TestRateLimitPoller_ForceCountedAfterStaleness exercises the new path.
	p := NewRateLimitPoller(instances, srv.URL, time.Hour, quota, time.Hour)
	t.Cleanup(p.Stop)
	return p
}

func probeCount(app, result string) float64 {
	return testutil.ToFloat64(metrics.GitHubRateLimitProbeTotal.WithLabelValues(app, "i1", result))
}

func TestRateLimitPoller_ConditionalProbeTracksLiveBucket(t *testing.T) {
	const app = "poller-conditional"
	reset := time.Now().Add(40 * time.Minute).Unix()
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "Depthmark-Lab", limit: 5000, remaining: 4990, reset: reset}})
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)
	ctx := context.Background()

	p.pollAll(ctx) // 200, costs one request, stores the ETag
	fake.spend(7, 25)
	p.pollAll(ctx) // 304, free, sees the 25 spent elsewhere
	p.pollAll(ctx) // 304 again

	q, ok := quota.Lowest(app, "i1", "core")
	if !ok {
		t.Fatal("no quota recorded")
	}
	if q.Remaining != 4964 || q.Used != 36 {
		t.Errorf("quota = remaining %d used %d; want 4964 and 36 (one counted 200, 25 spent elsewhere, two free 304s)", q.Remaining, q.Used)
	}
	if q.Account != "depthmark-lab" {
		t.Errorf("account = %q, want depthmark-lab", q.Account)
	}
	if got := probeCount(app, "ok"); got != 1 {
		t.Errorf("ok probes = %v, want 1", got)
	}
	if got := probeCount(app, "not_modified"); got != 2 {
		t.Errorf("not_modified probes = %v, want 2", got)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitRemaining.WithLabelValues(app, "i1", "core")); got != 4964 {
		t.Errorf("remaining gauge = %v, want 4964", got)
	}

	mints, _ := fake.counts()
	if mints != 1 {
		t.Errorf("mints = %d, want 1 (token reused across probes)", mints)
	}
	for _, perms := range fake.mintedPermissions {
		if len(perms) != 1 || perms["metadata"] != "read" {
			t.Errorf("poller token permissions = %v, want only metadata:read", perms)
		}
	}
}

// TestRateLimitPoller_UncountedNotModifiedDoesNotOverwrite replays what
// github-sts-dev showed on 2026-09-13: counted 200 probes reported the real
// installation bucket, then the first 304 reported used=0 with a reset an
// hour out and, being a "later window", overwrote it. The gauges went back
// to full within one poll.
func TestRateLimitPoller_UncountedNotModifiedDoesNotOverwrite(t *testing.T) {
	const app = "poller-v1b"
	reset := time.Now().Add(40 * time.Minute).Unix()
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 4990, reset: reset}})
	fake.uncountedNotModified = true
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)

	p.pollAll(context.Background()) // 200: counted, real bucket, used 11
	p.pollAll(context.Background()) // 304: uncounted bucket, must be dropped

	q, ok := quota.Lowest(app, "i1", "core")
	if !ok || q.Remaining != 4989 || q.ResetAt.Unix() != reset {
		t.Fatalf("quota = %+v, %v; want the counted reading (4989, reset %d) kept", q, ok, reset)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitRemaining.WithLabelValues(app, "i1", "core")); got != 4989 {
		t.Errorf("remaining gauge = %v, want 4989", got)
	}
}

// TestRateLimitPoller_ForceCountedAfterStaleness reproduces the drain a 304
// hides: something other than this poller (a client token, or in
// github-sts-dev on 2026-09-16 an E2E harness probing the installation
// directly) spends most of the bucket between polls. A 304 reports GitHub's
// fake unused-bucket reading for installation tokens (V1b) and QuotaStore
// correctly drops it, so without a staleness ceiling the drain would stay
// invisible for as long as the token is cached (up to ~55 minutes). Once
// forceCountedInterval has elapsed since the last counted read, the probe
// must drop If-None-Match and pay for a fresh 200 that reveals it.
func TestRateLimitPoller_ForceCountedAfterStaleness(t *testing.T) {
	const app = "poller-force-counted"
	reset := time.Now().Add(40 * time.Minute).Unix()
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 4990, reset: reset}})
	fake.uncountedNotModified = true
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)
	p.forceCountedInterval = 5 * time.Minute
	clock := time.Now()
	p.now = func() time.Time { return clock }

	p.pollAll(context.Background()) // 200: counted, real bucket (remaining 4989)

	// A drain that bypasses this poller entirely, exactly like a client
	// token or an external probe hitting GitHub directly.
	fake.spend(7, 4000)

	clock = clock.Add(4 * time.Minute) // still within forceCountedInterval
	p.pollAll(context.Background())    // 304: cached etag still fresh, sent; fake bucket dropped

	if q, ok := quota.Lowest(app, "i1", "core"); !ok || q.Remaining != 4989 {
		t.Fatalf("quota = %+v, %v; want the stale counted reading (4989) still in force before the staleness ceiling", q, ok)
	}
	if got := probeCount(app, "not_modified"); got != 1 {
		t.Errorf("not_modified probes = %v, want 1 (still within forceCountedInterval)", got)
	}

	clock = clock.Add(2 * time.Minute) // now 6 minutes since the counted read
	p.pollAll(context.Background())    // etag stale: If-None-Match dropped, forces a counted 200

	q, ok := quota.Lowest(app, "i1", "core")
	if !ok || q.Remaining != 988 {
		t.Fatalf("quota = %+v, %v; want the drain (988 remaining: 989 after the spend, minus the forced probe's own request) visible once the etag went stale", q, ok)
	}
	if got := probeCount(app, "ok"); got != 2 {
		t.Errorf("ok probes = %v, want 2 (initial + forced re-read)", got)
	}
	if got := probeCount(app, "not_modified"); got != 1 {
		t.Errorf("not_modified probes = %v, want 1 (unchanged: the third poll was forced counted, not conditional)", got)
	}

	mints, _ := fake.counts()
	if mints != 1 {
		t.Errorf("mints = %d, want 1 (forcing a counted probe reuses the cached token, it does not mint a new one)", mints)
	}
}

func TestRateLimitPoller_UnauthorizedDropsTokenWithoutRecording(t *testing.T) {
	const app = "poller-unauthorized"
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 5000, reset: time.Now().Add(time.Hour).Unix()}})
	fake.probeStatus = func(n int) int {
		if n == 1 {
			return http.StatusUnauthorized
		}
		return http.StatusOK
	}
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)

	p.pollAll(context.Background())
	if _, ok := quota.Lowest(app, "i1", "core"); ok {
		t.Fatal("a 401 probe was recorded as quota")
	}
	p.pollAll(context.Background())

	if mints, _ := fake.counts(); mints != 2 {
		t.Errorf("mints = %d, want 2 (rejected token replaced)", mints)
	}
	if got := probeCount(app, "unauthorized"); got != 1 {
		t.Errorf("unauthorized probes = %v, want 1", got)
	}
	if _, ok := quota.Lowest(app, "i1", "core"); !ok {
		t.Error("quota not recorded after the token was replaced")
	}
}

func TestRateLimitPoller_IncompleteHeadersNotRecorded(t *testing.T) {
	const app = "poller-incomplete"
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 4000, reset: time.Now().Add(time.Hour).Unix()}})
	fake.omitRemaining = true
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)

	p.pollAll(context.Background())

	if _, ok := quota.Lowest(app, "i1", "core"); ok {
		t.Fatal("probe without X-RateLimit-Remaining was recorded")
	}
	if got := probeCount(app, "incomplete_headers"); got != 1 {
		t.Errorf("incomplete_headers probes = %v, want 1", got)
	}
}

func TestRateLimitPoller_ExhaustedBucketRecorded(t *testing.T) {
	const app = "poller-exhausted"
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 0, reset: time.Now().Add(time.Hour).Unix()}})
	fake.probeStatus = func(int) int { return http.StatusForbidden }
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)

	p.pollAll(context.Background())

	q, ok := quota.Lowest(app, "i1", "core")
	if !ok || q.Remaining != 0 {
		t.Fatalf("quota = %+v, %v; want an exhausted bucket recorded", q, ok)
	}
	if got := probeCount(app, "rate_limited"); got != 1 {
		t.Errorf("rate_limited probes = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitExceededTotal.WithLabelValues(app, "i1", "core", "rate_limit_poller")); got != 1 {
		t.Errorf("exceeded counter = %v, want 1", got)
	}
}

func TestRateLimitPoller_MultipleInstallationsReportLowest(t *testing.T) {
	const app = "poller-multi-install"
	reset := time.Now().Add(time.Hour).Unix()
	_, srv := newFakeGitHub(t, map[int64]*fakeBucket{
		7: {account: "org-a", limit: 5000, remaining: 4800, reset: reset},
		8: {account: "org-b", limit: 12500, remaining: 300, reset: reset},
	})
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)

	p.pollAll(context.Background())

	if got := testutil.ToFloat64(metrics.GitHubRateLimitRemaining.WithLabelValues(app, "i1", "core")); got != 299 {
		t.Errorf("remaining gauge = %v, want 299 (org-b, the lowest installation, whatever the poll order)", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

func TestRateLimitPoller_ProbesJustAfterReset(t *testing.T) {
	const app = "poller-reset"
	// Header resets have one-second resolution, so the earliest future reset
	// is the next whole second.
	reset := time.Now().Add(time.Second).Truncate(time.Second).Add(time.Second)
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 1200, reset: reset.Unix()}})
	p := newTestPoller(t, app, srv, NewQuotaStore())
	p.resetDelay = func() time.Duration { return 0 }

	p.Start() // interval is an hour, so only the reset timer can probe again
	waitFor(t, 5*time.Second, func() bool { _, probes := fake.counts(); return probes >= 2 }, "a probe after the reset")

	if time.Now().Before(reset) {
		t.Errorf("second probe ran before the reset")
	}
}

func TestRateLimitPoller_NoResetProbeWhenNothingToRecover(t *testing.T) {
	pendingTimers := func(p *RateLimitPoller) int {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.resetTimers)
	}

	t.Run("full bucket", func(t *testing.T) {
		fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 5000, reset: time.Now().Add(time.Hour).Unix()}})
		fake.probeStatus = func(int) int { return http.StatusNotModified } // free, so the bucket stays full
		p := newTestPoller(t, "poller-full", srv, NewQuotaStore())

		p.pollAll(context.Background())
		if n := pendingTimers(p); n != 0 {
			t.Errorf("a full bucket armed %d reset probes, want 0", n)
		}
	})

	t.Run("reset already passed", func(t *testing.T) {
		_, srv := newFakeGitHub(t, map[int64]*fakeBucket{})
		p := newTestPoller(t, "poller-past-reset", srv, NewQuotaStore())

		p.armResetProbe(poolInstanceKey{logicalApp: "poller-past-reset", instance: "i1"}, time.Now().Add(-time.Second))
		if n := pendingTimers(p); n != 0 {
			t.Errorf("a reset in the past armed %d reset probes, want 0", n)
		}
	})

	t.Run("one timer per instance, earliest reset wins", func(t *testing.T) {
		_, srv := newFakeGitHub(t, map[int64]*fakeBucket{})
		p := newTestPoller(t, "poller-one-timer", srv, NewQuotaStore())
		key := poolInstanceKey{logicalApp: "poller-one-timer", instance: "i1"}
		soon := time.Now().Add(10 * time.Minute)

		p.armResetProbe(key, soon.Add(20*time.Minute))
		p.armResetProbe(key, soon)
		p.armResetProbe(key, soon.Add(40*time.Minute))

		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.resetTimers) != 1 {
			t.Fatalf("pending reset probes = %d, want 1", len(p.resetTimers))
		}
		if at := p.resetTimers[key].at; at.Before(soon) || at.After(soon.Add(5*time.Second)) {
			t.Errorf("reset probe at %v, want just after %v", at, soon)
		}
	})
}

func TestRateLimitPoller_ProbesOnRequest(t *testing.T) {
	const app = "poller-request"
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 5000, reset: time.Now().Add(time.Hour).Unix()}})
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)
	p.minEventProbeSpacing = 0

	p.Start()
	waitFor(t, 5*time.Second, func() bool { _, probes := fake.counts(); return probes >= 1 }, "the initial sweep")

	quota.RequestProbe(app, "i1")
	waitFor(t, 5*time.Second, func() bool { _, probes := fake.counts(); return probes >= 2 }, "a requested probe")

	quota.RequestProbe(app, "unknown-instance") // ignored, must not wedge the loop
	quota.RequestProbe(app, "i1")
	waitFor(t, 5*time.Second, func() bool { _, probes := fake.counts(); return probes >= 3 }, "a second requested probe")
}

func TestRateLimitPoller_RequestedProbesAreSpaced(t *testing.T) {
	const app = "poller-spacing"
	fake, srv := newFakeGitHub(t, map[int64]*fakeBucket{7: {account: "org", limit: 5000, remaining: 5000, reset: time.Now().Add(time.Hour).Unix()}})
	quota := NewQuotaStore()
	p := newTestPoller(t, app, srv, quota)
	p.minEventProbeSpacing = time.Hour

	p.Start()
	waitFor(t, 5*time.Second, func() bool { _, probes := fake.counts(); return probes >= 1 }, "the initial sweep")
	for range 10 {
		quota.RequestProbe(app, "i1")
	}
	waitFor(t, 5*time.Second, func() bool { return len(quota.probeRequests()) == 0 }, "the loop to drain requests")
	time.Sleep(50 * time.Millisecond)

	if _, probes := fake.counts(); probes != 1 {
		t.Errorf("probes = %d, want 1 (requests inside the spacing window are dropped)", probes)
	}
}
