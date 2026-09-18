package github

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	ststracing "github.com/depthmark/github-sts/internal/tracing"
	"go.opentelemetry.io/otel/trace"
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

	// strategy is round_robin or rate_limit_aware. Both rotate, apply the
	// baseline liveness filter and fail over reactively; rate_limit_aware
	// also moves a member whose installation is below minRemainingPct to the
	// back of the attempt order (see candidateRing).
	strategy        string
	minRemainingPct float64
	maxAttempts     int

	// reachability is optional; nil disables the baseline liveness filter.
	reachability ReachabilityChecker

	// quota is optional; without it rate_limit_aware orders like round_robin.
	quota *QuotaStore
	now   func() time.Time
}

// rateLimitAware is the strategy that orders candidates by installation quota.
const rateLimitAware = "rate_limit_aware"

// cursorMode says whether a ring call takes a turn in the rotation or only
// looks at whose turn is next.
type cursorMode bool

const (
	// advanceCursor takes a turn. Only the exchange mint advances: it is the
	// one pool call every successful exchange makes exactly once.
	advanceCursor cursorMode = true
	// peekCursor starts at the member the next mint will use, without taking
	// a turn. Target resolution and policy reads use it.
	peekCursor cursorMode = false
)

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
		now:             time.Now,
	}
}

// SetQuotaStore attaches the process-wide QuotaStore that rate_limit_aware
// reads. Call it before the pool serves requests.
func (p *AppPool) SetQuotaStore(q *QuotaStore) {
	p.quota = q
}

// candidateRing returns this call's attempt order and the index in it where
// quota-demoted members start (len(order) when nothing was demoted).
//
// Rotation. One exchange makes several pool calls: ResolveTarget, zero to
// two policy-read GetInstallationToken calls, then exactly one
// GetInstallationTokenForTarget. When every call advanced the shared cursor,
// an even number of calls per exchange pinned the mint to the same member of
// a 2-member pool (1296 against 262 exchange mints over 7 days in
// github-sts-dev). Now only the mint advances (advanceCursor); the other
// calls peek at the member the next mint will use, so a whole exchange lands
// on one member and mints rotate evenly for any pool size. The price is that
// pool calls with no mint behind them (for example exchanges the policy
// denies) keep starting on the same member until a mint moves the cursor;
// failover, the liveness filter and rate_limit_aware still move them. Every
// pool member is required to have identical permissions and installation
// access (see the config docs' "Operational requirement"), so where each
// half of an exchange runs is a load question, not a correctness one. One
// call's own retries walk consecutive members from its start.
//
// Liveness filter. Any candidate the reachability checker reports down is
// dropped, so a fully-dead instance (revoked key, network partition) doesn't
// eat a wasted live call on every request. If every candidate looks
// unreachable per (possibly stale) local state, the unfiltered ring is used
// and a live attempt made anyway: a live failure is authoritative, a cached
// "probably down" is not. skipped_unreachable is only emitted when the
// filtered set is the one returned, so an instance is never counted as both
// skipped and selected/failover for the same call.
//
// Quota ordering (rate_limit_aware only). A reachable member whose
// installation for account is known to be below minRemainingPct (or at zero)
// in a window that has not reset yet moves to the back of the order, keeping
// ring order within each group. It is demoted, not dropped: low is not empty,
// and failover can still reach it when every healthier member fails. When
// every member is low, or none is, the order is the plain ring. See
// quotaIsLow for what counts as known.
func (p *AppPool) candidateRing(mode cursorMode, account string) (order []int, demotedFrom int) {
	n := len(p.members)
	var turn uint64
	if mode == advanceCursor {
		turn = p.cursor.Add(1)
	} else {
		turn = p.cursor.Load() + 1
	}
	start := int(turn % uint64(n))

	ring := make([]int, n)
	for i := range ring {
		ring[i] = (start + i) % n
	}

	if p.reachability != nil {
		filtered := make([]int, 0, n)
		var skipped []int
		for _, idx := range ring {
			if p.reachability.IsReachable(p.logicalName, p.members[idx].Instance) {
				filtered = append(filtered, idx)
			} else {
				skipped = append(skipped, idx)
			}
		}
		if len(filtered) > 0 {
			for _, idx := range skipped {
				metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, p.members[idx].Instance, "skipped_unreachable").Inc()
			}
			ring = filtered
		}
	}

	if p.strategy != rateLimitAware || p.quota == nil {
		return ring, len(ring)
	}
	healthy := make([]int, 0, len(ring))
	var low []int
	for _, idx := range ring {
		if p.quotaIsLow(p.members[idx].Instance, account) {
			low = append(low, idx)
		} else {
			healthy = append(healthy, idx)
		}
	}
	if len(healthy) == 0 || len(low) == 0 {
		return ring, len(ring)
	}
	return append(healthy, low...), len(healthy)
}

// quotaIsLow reports whether instance's installation for account is known to
// be low. Known means a reading that counted requests (Used > 0) in a window
// that has not reset. Such a reading can only overstate what is left, since
// GitHub never refunds a request inside a window, so it never demotes a member
// that has recovered. A missing reading, an uncounted one, or one whose window
// has reset is not low: when in doubt, rotate normally.
func (p *AppPool) quotaIsLow(instance, account string) bool {
	q, ok := p.quota.Installation(p.logicalName, instance, account, "core")
	if !ok || q.Used == 0 || !p.now().Before(q.ResetAt) {
		return false
	}
	return q.Remaining == 0 || q.RemainingPct() < p.minRemainingPct
}

// runOnRing holds the single copy of the ring/failover control flow shared
// by GetInstallationToken, ResolveTarget, and GetInstallationTokenForTarget
// below: try candidates in candidateRing order, retrying on a Retryable
// TokenMintError (§5.2.1) until max_attempts is exhausted or the caller's
// ctx is no longer live, emitting the outcome metric on success and
// AppPoolExhaustedTotal on exhaustion. op is called with ctx already bound
// by the caller's closure — it's not threaded through runOnRing itself,
// only used here for the ctx.Err() liveness check between attempts.
//
// skipped_rate_limited is emitted for each quota-demoted member the call never
// attempted, once the call has succeeded or exhausted its attempts. A call that
// stops on a non-retryable error or a finished context skipped nobody for
// quota reasons, so it emits nothing.
func runOnRing[T any](p *AppPool, ctx context.Context, mode cursorMode, account, operation, tokenPurpose string, op func(context.Context, PoolMember) (T, error)) (T, string, error) {
	candidates, demotedFrom := p.candidateRing(mode, account)

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

		attemptCtx, attemptSpan := ststracing.Tracer().Start(ctx, "github.app_pool.attempt",
			trace.WithAttributes(ststracing.AppPoolAttemptAttributes(
				p.logicalName, m.Instance, operation, tokenPurpose, attempts,
			)...),
		)
		result, err := op(attemptCtx, m)
		if err == nil {
			attemptSpan.SetAttributes(
				ststracing.AttrGitHubPoolOutcome.String(outcome),
				ststracing.StageResult("success"),
			)
			attemptSpan.End()
			metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, m.Instance, outcome).Inc()
			p.recordQuotaSkips(candidates[max(demotedFrom, attempts):])
			return result, m.Instance, nil
		}
		ststracing.MarkError(attemptSpan, tokenMintErrorType(err))
		attemptSpan.SetAttributes(ststracing.AttrGitHubPoolOutcome.String("failed"))
		attemptSpan.End()
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

	p.recordQuotaSkips(candidates[max(demotedFrom, attempts):])
	metrics.AppPoolExhaustedTotal.WithLabelValues(p.logicalName).Inc()
	return zero, "", lastErr
}

func (p *AppPool) recordQuotaSkips(skipped []int) {
	for _, idx := range skipped {
		metrics.AppPoolSelectionTotal.WithLabelValues(p.logicalName, p.members[idx].Instance, "skipped_rate_limited").Inc()
	}
}

// GetInstallationToken implements policy.TokenProvider (used for the
// policy-read mint) and the identical shape ExchangeApp expects. Returns
// the instance label of whichever member actually served the request ("" on
// failure — see design doc §5.5 on why a failed exchange doesn't name one
// arbitrary tried instance). It peeks at the rotation rather than taking a
// turn; see candidateRing.
func (p *AppPool) GetInstallationToken(ctx context.Context, scope string, permissions map[string]string, repositories []string, caller string) (string, string, error) {
	return runOnRing(p, ctx, peekCursor, extractOrg(scope), "create_token", tokenPurpose(caller), func(attemptCtx context.Context, m PoolMember) (string, error) {
		return m.Provider.GetInstallationToken(attemptCtx, scope, permissions, repositories, caller)
	})
}

// ResolveTarget implements github.ExchangeApp: same ring/failover mechanics
// as GetInstallationToken, applied to target-identity resolution. A
// structural failure (invalid/non-canonical identity from GitHub) is not a
// *TokenMintError, so it's correctly treated as non-retryable — a different
// credential can't fix bad data, only a different network path or expired
// credential can, and those cases already come back wrapped as retryable.
// It peeks at the rotation rather than taking a turn; see candidateRing.
func (p *AppPool) ResolveTarget(ctx context.Context, scope RepositoryScope) (TargetIdentity, error) {
	identity, _, err := runOnRing(p, ctx, peekCursor, scope.Owner, "resolve_target", "", func(attemptCtx context.Context, m PoolMember) (TargetIdentity, error) {
		return m.Provider.ResolveTarget(attemptCtx, scope)
	})
	return identity, err
}

// GetInstallationTokenForTarget implements github.ExchangeApp: same
// ring/failover mechanics as GetInstallationToken, applied to minting a
// token restricted to an already-resolved immutable target. It is the only
// pool call that takes a turn in the rotation; see candidateRing.
func (p *AppPool) GetInstallationTokenForTarget(ctx context.Context, target TargetIdentity, permissions PermissionRequest, caller string) (MintedToken, string, error) {
	return runOnRing(p, ctx, advanceCursor, target.Owner, "create_token", "exchange", func(attemptCtx context.Context, m PoolMember) (MintedToken, error) {
		minted, _, err := m.Provider.GetInstallationTokenForTarget(attemptCtx, target, permissions, caller)
		return minted, err
	})
}
