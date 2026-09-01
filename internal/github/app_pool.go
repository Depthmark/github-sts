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

// candidateRing returns this call's ring order, starting from an
// atomically-advanced shared cursor, filtered by the baseline liveness
// check. The cursor is advanced once per call to candidateRing, not once
// per failover attempt, so one call's own retries walk consecutive members
// instead of re-randomizing — but ResolveTarget and GetInstallationToken/
// GetInstallationTokenForTarget each call this independently, so the two
// halves of one exchange request (resolve, then mint) are not guaranteed to
// land on the same instance. That's fine only because every pool member is
// required to have identical permissions/installation access (see the
// config docs' "Operational requirement") — otherwise it would be a bug.
//
// The liveness filter drops any candidate the reachability checker
// currently reports down, so a fully-dead instance (revoked key, network
// partition) doesn't eat a wasted live call on every single request. If
// every candidate looks unreachable per (possibly stale) local state, it
// does not fail pre-emptively — it falls back to the unfiltered ring and
// makes a live attempt anyway. A live failure is authoritative; a
// locally-cached "probably down" is not — and because that fallback means
// every member is actually tried, no "skipped_unreachable" metric is
// emitted in that case: emission is deferred until we know the filtered
// set is the one actually returned, so an instance never gets counted as
// both skipped and selected/failover for the same call.
func (p *AppPool) candidateRing() []int {
	n := len(p.members)
	start := int(p.cursor.Add(1) % uint64(n))

	ring := make([]int, n)
	for i := range ring {
		ring[i] = (start + i) % n
	}

	if p.reachability == nil {
		return ring
	}
	filtered := make([]int, 0, n)
	var skipped []int
	for _, idx := range ring {
		m := p.members[idx]
		if p.reachability.IsReachable(p.logicalName, m.Instance) {
			filtered = append(filtered, idx)
		} else {
			skipped = append(skipped, idx)
		}
	}
	if len(filtered) == 0 {
		return ring
	}
	for _, idx := range skipped {
		m := p.members[idx]
		metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, m.Instance, "skipped_unreachable").Inc()
	}
	return filtered
}

// runOnRing holds the single copy of the ring/failover control flow shared
// by GetInstallationToken, ResolveTarget, and GetInstallationTokenForTarget
// below: try candidates in candidateRing order, retrying on a Retryable
// TokenMintError (§5.2.1) until max_attempts is exhausted or the caller's
// ctx is no longer live, emitting the outcome metric on success and
// AppPoolExhaustedTotal on exhaustion. op is called with ctx already bound
// by the caller's closure — it's not threaded through runOnRing itself,
// only used here for the ctx.Err() liveness check between attempts.
func runOnRing[T any](p *AppPool, ctx context.Context, op func(PoolMember) (T, error)) (T, string, error) {
	candidates := p.candidateRing()

	var zero T
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

		result, err := op(m)
		if err == nil {
			metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, m.Instance, outcome).Inc()
			return result, m.Instance, nil
		}
		lastErr = err

		var mintErr *TokenMintError
		retryable := errors.As(err, &mintErr) && mintErr.Retryable
		if !retryable || ctx.Err() != nil {
			// Not worth retrying elsewhere (e.g. 422 — a policy/permissions
			// problem retrying can't fix), or the caller's own context is
			// already done: surface this error immediately rather than
			// treating it as pool exhaustion.
			return zero, "", err
		}
		// Retryable and ctx still live — continue to the next candidate.
	}

	metrics.AppPoolExhaustedTotal.WithLabelValues(p.logicalName).Inc()
	return zero, "", lastErr
}

// GetInstallationToken implements policy.TokenProvider (used for the
// policy-read mint) and the identical shape ExchangeApp expects. Returns
// the instance label of whichever member actually served the request ("" on
// failure — see design doc §5.5 on why a failed exchange doesn't name one
// arbitrary tried instance).
func (p *AppPool) GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, string, error) {
	return runOnRing(p, ctx, func(m PoolMember) (string, error) {
		return m.Provider.GetInstallationToken(ctx, scope, permissions, repositories, caller)
	})
}

// ResolveTarget implements github.ExchangeApp: same ring/failover mechanics
// as GetInstallationToken, applied to target-identity resolution. A
// structural failure (invalid/non-canonical identity from GitHub) is not a
// *TokenMintError, so it's correctly treated as non-retryable — a different
// credential can't fix bad data, only a different network path or expired
// credential can, and those cases already come back wrapped as retryable.
func (p *AppPool) ResolveTarget(ctx context.Context, scope RepositoryScope) (TargetIdentity, error) {
	identity, _, err := runOnRing(p, ctx, func(m PoolMember) (TargetIdentity, error) {
		return m.Provider.ResolveTarget(ctx, scope)
	})
	return identity, err
}

// GetInstallationTokenForTarget implements github.ExchangeApp: same
// ring/failover mechanics as GetInstallationToken, applied to minting a
// token restricted to an already-resolved immutable target.
func (p *AppPool) GetInstallationTokenForTarget(ctx context.Context, target TargetIdentity, permissions PermissionRequest, caller string) (MintedToken, string, error) {
	return runOnRing(p, ctx, func(m PoolMember) (MintedToken, error) {
		minted, _, err := m.Provider.GetInstallationTokenForTarget(ctx, target, permissions, caller)
		return minted, err
	})
}
