package github

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/depthmark/github-sts/internal/metrics"
)

// ReachabilityChecker reports whether a specific pool instance is currently
// considered reachable. *ReachabilityProber implements this. AppPool treats
// a nil checker as "assume everyone reachable" — the baseline liveness
// filter degrades to a no-op rather than incorrectly excluding every
// candidate when reachability probing is disabled.
type ReachabilityChecker interface {
	IsReachable(logicalApp, instance string) bool
}

// PoolMember is one physical GitHub App backing a pooled logical app.
// Instance labels it in metrics/audit — an operator-supplied alias, or the
// instance's app_id (stringified) when no alias was configured.
type PoolMember struct {
	Instance string
	Provider *AppTokenProvider
}

// AppPool spreads /sts/exchange token-minting traffic across N physical
// GitHub Apps backing one logical app name, so the effective GitHub primary
// rate-limit ceiling for that logical app scales ~linearly with N, and
// automatically fails over around an exhausted or broken instance instead of
// failing the caller. Callers only ever see the logical app name — instance
// selection is entirely internal.
//
// A pool of exactly one (the normalized shape of a legacy single-instance
// config) degenerates to "try the one member, no retries possible" —
// behaviorally and latency-wise identical to calling the wrapped
// *AppTokenProvider directly. That equivalence is the backbone of backward
// compatibility for every config that predates pooling.
type AppPool struct {
	logicalName string
	members     []PoolMember
	cursor      atomic.Uint64

	// strategy is stored for observability/future use but does not yet
	// change selection behavior in this build: the rate_limit_aware
	// proactive-skip ranking is a follow-up (design doc §10/Phase 4).
	// Every pool currently behaves like round_robin plus the baseline
	// liveness filter below and reactive failover, which already delivers
	// the primary goal (N× ceiling + automatic, correctly-classified
	// failover).
	strategy        string
	minRemainingPct float64
	maxAttempts     int

	// reachability is optional; nil disables the baseline liveness filter.
	reachability ReachabilityChecker
}

// NewAppPool creates a pool for one logical app. members must be
// non-empty. strategy/minRemainingPct/maxAttempts normally come from the
// app's already-defaulted config.RotationConfig. reachability may be nil.
func NewAppPool(logicalName string, members []PoolMember, strategy string, minRemainingPct float64, maxAttempts int, reachability ReachabilityChecker) *AppPool {
	if maxAttempts <= 0 || maxAttempts > len(members) {
		maxAttempts = len(members)
	}
	metrics.AppPoolInstances.WithLabelValues(logicalName).Set(float64(len(members)))
	return &AppPool{
		logicalName:     logicalName,
		members:         members,
		strategy:        strategy,
		minRemainingPct: minRemainingPct,
		maxAttempts:     maxAttempts,
		reachability:    reachability,
	}
}

// GetInstallationToken implements InstallationTokenProvider (and, via the
// identical signature, policy.TokenProvider): it tries pool members in ring
// order starting from an atomically-advanced cursor — advanced once per
// request, not once per failover attempt, so a single request's retries
// walk consecutive members instead of re-randomizing — skipping any member
// the reachability checker currently reports down, and retrying on a
// Retryable TokenMintError (§5.2.1) until max_attempts is exhausted or the
// caller's ctx is no longer live. Returns the instance label of whichever
// member actually served the request ("" on failure — see design doc §5.5
// on why a failed exchange doesn't name one arbitrary tried instance).
func (p *AppPool) GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, string, error) {
	n := len(p.members)
	start := int(p.cursor.Add(1) % uint64(n))

	ring := make([]int, n)
	for i := range ring {
		ring[i] = (start + i) % n
	}

	// Baseline liveness filter (always on, independent of strategy): drop
	// any candidate the reachability checker currently reports down, so a
	// fully-dead instance (revoked key, network partition) doesn't eat a
	// wasted live call on every single request.
	candidates := ring
	if p.reachability != nil {
		filtered := make([]int, 0, n)
		for _, idx := range ring {
			m := p.members[idx]
			if p.reachability.IsReachable(p.logicalName, m.Instance) {
				filtered = append(filtered, idx)
				continue
			}
			metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, m.Instance, "skipped_unreachable").Inc()
		}
		// If every candidate looks unreachable per (possibly stale) local
		// state, don't fail pre-emptively — fall back to the unfiltered
		// ring and make a live attempt anyway. A live failure is
		// authoritative; a locally-cached "probably down" is not.
		if len(filtered) > 0 {
			candidates = filtered
		}
	}

	var lastErr error
	attempts := 0
	for i, idx := range candidates {
		if attempts >= p.maxAttempts {
			break
		}
		attempts++

		m := p.members[idx]
		outcome := "selected"
		if i > 0 {
			outcome = "failover"
		}

		token, err := m.Provider.GetInstallationToken(ctx, scope, permissions, repositories, caller)
		if err == nil {
			metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, m.Instance, outcome).Inc()
			return token, m.Instance, nil
		}
		lastErr = err

		var mintErr *TokenMintError
		retryable := errors.As(err, &mintErr) && mintErr.Retryable
		if !retryable || ctx.Err() != nil {
			// Not worth retrying elsewhere (e.g. 422 — a policy/permissions
			// problem retrying can't fix), or the caller's own context is
			// already done: surface this error immediately rather than
			// treating it as pool exhaustion.
			return "", "", err
		}
		// Retryable and ctx still live — continue to the next candidate.
	}

	metrics.AppPoolExhaustedTotal.WithLabelValues(p.logicalName).Inc()
	return "", "", lastErr
}
