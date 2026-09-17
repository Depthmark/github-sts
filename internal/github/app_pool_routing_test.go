package github

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAppPool_ExchangeMintsRotateEvenly replays the pool calls of real
// exchanges: ResolveTarget, zero to two policy reads, then the mint. Before
// only the mint advanced the cursor, a 2-member pool sent almost every mint
// to one member (1296 against 262 over 7 days in github-sts-dev), because
// each exchange advanced the cursor an even number of times.
func TestAppPool_ExchangeMintsRotateEvenly(t *testing.T) {
	for _, size := range []int{2, 3} {
		for _, policyReads := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%d members, %d policy reads", size, policyReads), func(t *testing.T) {
				members := make([]PoolMember, 0, size)
				for i := range size {
					srv := newMockTargetServer(1, succeedHandler("tok"), succeedRepoHandler("myorg", "myrepo", 9001))
					t.Cleanup(srv.Close)
					members = append(members, newMockMember(t, fmt.Sprintf("m%d", i), srv.URL))
				}
				pool := NewAppPool("rotate-even", members, "round_robin", 0, size, nil)
				ctx := context.Background()

				const exchanges = 60
				mints := map[string]int{}
				for i := range exchanges {
					if _, err := pool.ResolveTarget(ctx, RepositoryScope{Owner: "myorg", Repository: "myrepo"}); err != nil {
						t.Fatalf("exchange %d resolve: %v", i, err)
					}
					var policyInstance string
					for range policyReads {
						_, instance, err := pool.GetInstallationToken(ctx, "myorg/.github-sts", map[string]string{"contents": "read"}, nil, "policy_loader")
						if err != nil {
							t.Fatalf("exchange %d policy read: %v", i, err)
						}
						policyInstance = instance
					}
					instance, err := mintForTarget(pool)
					if err != nil {
						t.Fatalf("exchange %d mint: %v", i, err)
					}
					if policyReads > 0 && policyInstance != instance {
						t.Errorf("exchange %d: policy read on %s but mint on %s; one exchange should stay on one member", i, policyInstance, instance)
					}
					mints[instance]++
				}

				want := exchanges / size
				for _, m := range members {
					if got := mints[m.Instance]; got < want-1 || got > want+1 {
						t.Errorf("mints = %v, want %d ± 1 per member", mints, want)
						break
					}
				}
			})
		}
	}
}

func TestAppPool_PeekingCallsDoNotTakeATurn(t *testing.T) {
	srvA := newMockGitHubServer(1, succeedHandler("tok-a"))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, succeedHandler("tok-b"))
	defer srvB.Close()
	pool := NewAppPool("peek", []PoolMember{newMockMember(t, "a", srvA.URL), newMockMember(t, "b", srvB.URL)}, "round_robin", 0, 2, nil)

	_, first, err := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "policy_loader")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, instance, _ := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "policy_loader"); instance != first {
			t.Fatalf("policy read %d on %s, want %s: a peeking call moved the rotation", i, instance, first)
		}
	}
	minted, err := mintForTarget(pool)
	if err != nil {
		t.Fatal(err)
	}
	if minted != first {
		t.Errorf("mint on %s, want %s: the mint should use the member the peeks pointed at", minted, first)
	}
	if _, next, _ := pool.GetInstallationToken(context.Background(), "myorg", nil, nil, "policy_loader"); next == first {
		t.Errorf("after a mint, policy read still on %s: the mint did not take its turn", next)
	}
}

// rateLimitPool builds a 2-member rate_limit_aware pool whose members count
// the mints they serve.
func rateLimitPool(t *testing.T, name string, minPct float64, maxAttempts int, handlerB http.HandlerFunc) (*AppPool, *QuotaStore, *int32, *int32) {
	t.Helper()
	var callsA, callsB int32
	if handlerB == nil {
		handlerB = succeedHandler("tok-b")
	}
	srvA := newMockGitHubServer(1, countingHandler(&callsA, succeedHandler("tok-a")))
	t.Cleanup(srvA.Close)
	srvB := newMockGitHubServer(1, countingHandler(&callsB, handlerB))
	t.Cleanup(srvB.Close)

	pool := NewAppPool(name, []PoolMember{newMockMember(t, "a", srvA.URL), newMockMember(t, "b", srvB.URL)}, rateLimitAware, minPct, maxAttempts, nil)
	quota := NewQuotaStore()
	pool.SetQuotaStore(quota)
	return pool, quota, &callsA, &callsB
}

func selectionCount(app, instance, outcome string) float64 {
	return testutil.ToFloat64(metrics.AppPoolSelectionTotal.WithLabelValues(app, instance, outcome))
}

func TestAppPool_RateLimitAware_DemotesLowMember(t *testing.T) {
	const app = "rl-demote"
	pool, quota, callsA, callsB := rateLimitPool(t, app, 10, 2, nil)
	quota.Observe(app, "a", "myorg", completeInfo(5000, 100, time.Now().Add(30*time.Minute))) // 2%

	for i := range 20 {
		instance, err := mintForTarget(pool)
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if instance != "b" {
			t.Fatalf("mint %d served by %s, want b while a is below min_remaining_pct", i, instance)
		}
	}
	if *callsA != 0 || *callsB != 20 {
		t.Errorf("calls a=%d b=%d, want 0 and 20", *callsA, *callsB)
	}
	if got := selectionCount(app, "a", "skipped_rate_limited"); got != 20 {
		t.Errorf("skipped_rate_limited{a} = %v, want 20", got)
	}
	if got := selectionCount(app, "b", "selected"); got != 20 {
		t.Errorf("selected{b} = %v, want 20", got)
	}
}

func TestAppPool_RateLimitAware_DemotedMemberStillServesFailover(t *testing.T) {
	const app = "rl-failover"
	pool, quota, callsA, _ := rateLimitPool(t, app, 10, 2, statusHandler(http.StatusServiceUnavailable, nil))
	quota.Observe(app, "a", "myorg", completeInfo(5000, 100, time.Now().Add(30*time.Minute)))

	for i := range 4 {
		instance, err := mintForTarget(pool)
		if err != nil {
			t.Fatalf("mint %d: %v; a demoted member must still be reachable by failover", i, err)
		}
		if instance != "a" {
			t.Fatalf("mint %d served by %s, want a after b failed", i, instance)
		}
	}
	if *callsA != 4 {
		t.Errorf("calls a = %d, want 4", *callsA)
	}
	if got := selectionCount(app, "a", "failover"); got != 4 {
		t.Errorf("failover{a} = %v, want 4", got)
	}
	if got := selectionCount(app, "a", "skipped_rate_limited"); got != 0 {
		t.Errorf("skipped_rate_limited{a} = %v, want 0: a member that was attempted was not skipped", got)
	}
}

func TestAppPool_RateLimitAware_ExhaustionCountsUntriedDemotedMember(t *testing.T) {
	const app = "rl-exhausted"
	pool, quota, callsA, _ := rateLimitPool(t, app, 10, 1, statusHandler(http.StatusServiceUnavailable, nil))
	quota.Observe(app, "a", "myorg", completeInfo(5000, 100, time.Now().Add(30*time.Minute)))
	exhaustedBefore := testutil.ToFloat64(metrics.AppPoolExhaustedTotal.WithLabelValues(app))

	if _, err := mintForTarget(pool); err == nil {
		t.Fatal("expected exhaustion with max_attempts 1 and b failing")
	}
	if *callsA != 0 {
		t.Errorf("calls a = %d, want 0 (max_attempts 1 stops before the demoted member)", *callsA)
	}
	if got := selectionCount(app, "a", "skipped_rate_limited"); got != 1 {
		t.Errorf("skipped_rate_limited{a} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AppPoolExhaustedTotal.WithLabelValues(app)) - exhaustedBefore; got != 1 {
		t.Errorf("exhausted increase = %v, want 1", got)
	}
}

// TestAppPool_RateLimitAware_PlainRotationWhenNothingIsKnownLow covers every
// case where quota must not change the order: rotation stays round robin, so
// both members serve, and nothing is counted as skipped_rate_limited.
func TestAppPool_RateLimitAware_PlainRotationWhenNothingIsKnownLow(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	tests := []struct {
		name   string
		minPct float64
		setup  func(p *AppPool, q *QuotaStore, app string)
	}{
		{name: "no reading", minPct: 10, setup: func(*AppPool, *QuotaStore, string) {}},
		{name: "reading above threshold", minPct: 10, setup: func(_ *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", completeInfo(5000, 4000, soon))
		}},
		{name: "every member low", minPct: 10, setup: func(_ *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", completeInfo(5000, 100, soon))
			q.Observe(app, "b", "myorg", completeInfo(5000, 50, soon))
		}},
		{name: "low reading whose window has reset", minPct: 10, setup: func(p *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", completeInfo(5000, 100, soon))
			p.now = func() time.Time { return soon.Add(time.Second) }
		}},
		{name: "low on another organization's installation", minPct: 10, setup: func(_ *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "otherorg", completeInfo(5000, 100, soon))
		}},
		{name: "uncounted reading", minPct: 10, setup: func(_ *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", RateLimitInfo{Resource: "core", Limit: 5000, Remaining: 0, Used: 0, ResetAt: soon.Truncate(time.Second), Complete: true})
		}},
		{name: "no quota store", minPct: 10, setup: func(p *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", completeInfo(5000, 100, soon))
			p.SetQuotaStore(nil)
		}},
		{name: "round_robin ignores quota", minPct: 10, setup: func(p *AppPool, q *QuotaStore, app string) {
			q.Observe(app, "a", "myorg", completeInfo(5000, 100, soon))
			p.strategy = "round_robin"
		}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fmt.Sprintf("rl-plain-%d", i)
			pool, quota, callsA, callsB := rateLimitPool(t, app, tt.minPct, 2, nil)
			tt.setup(pool, quota, app)

			for j := range 10 {
				if _, err := mintForTarget(pool); err != nil {
					t.Fatalf("mint %d: %v", j, err)
				}
			}
			if *callsA != 5 || *callsB != 5 {
				t.Errorf("calls a=%d b=%d, want 5 and 5 (plain rotation)", *callsA, *callsB)
			}
			for _, instance := range []string{"a", "b"} {
				if got := selectionCount(app, instance, "skipped_rate_limited"); got != 0 {
					t.Errorf("skipped_rate_limited{%s} = %v, want 0", instance, got)
				}
			}
		})
	}
}

func TestAppPool_RateLimitAware_ZeroRemainingIsLowAtAnyThreshold(t *testing.T) {
	const app = "rl-zero"
	pool, quota, callsA, _ := rateLimitPool(t, app, 0, 2, nil)
	quota.Observe(app, "a", "myorg", RateLimitInfo{Resource: "core", Limit: 5000, Remaining: 0, Used: 5000, ResetAt: time.Now().Add(time.Hour).Truncate(time.Second), Complete: true})

	for range 6 {
		if _, err := mintForTarget(pool); err != nil {
			t.Fatal(err)
		}
	}
	if *callsA != 0 {
		t.Errorf("calls a = %d, want 0: an exhausted installation is demoted even with min_remaining_pct 0", *callsA)
	}
}

func TestAppPool_RateLimitAware_RespectsReachabilityFilter(t *testing.T) {
	const app = "rl-reach"
	var callsA, callsB, callsC int32
	srvA := newMockGitHubServer(1, countingHandler(&callsA, succeedHandler("tok-a")))
	defer srvA.Close()
	srvB := newMockGitHubServer(1, countingHandler(&callsB, succeedHandler("tok-b")))
	defer srvB.Close()
	srvC := newMockGitHubServer(1, countingHandler(&callsC, succeedHandler("tok-c")))
	defer srvC.Close()
	reach := &fakeReachability{down: map[string]bool{"c": true}}
	pool := NewAppPool(app, []PoolMember{newMockMember(t, "a", srvA.URL), newMockMember(t, "b", srvB.URL), newMockMember(t, "c", srvC.URL)}, rateLimitAware, 10, 3, reach)
	quota := NewQuotaStore()
	pool.SetQuotaStore(quota)
	quota.Observe(app, "a", "myorg", completeInfo(5000, 100, time.Now().Add(30*time.Minute)))

	for range 9 {
		if _, err := mintForTarget(pool); err != nil {
			t.Fatal(err)
		}
	}
	if atomic.LoadInt32(&callsA) != 0 || atomic.LoadInt32(&callsC) != 0 || atomic.LoadInt32(&callsB) != 9 {
		t.Errorf("calls a=%d b=%d c=%d, want 0, 9, 0: unreachable c dropped, low a demoted", callsA, callsB, callsC)
	}
}
