package github

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
)

// RateLimitInfo is one parsed set of GitHub X-RateLimit-* response headers.
// Parsing is separate from recording so the Prometheus gauges and the
// in-memory QuotaStore consume the same values (design doc §5.3).
type RateLimitInfo struct {
	Resource  string
	Limit     int64
	Remaining int64
	Used      int64
	ResetAt   time.Time

	// Complete is true only when Limit, Remaining and Reset were all present
	// and parsed. An incomplete set must never be recorded: a missing
	// Remaining header is not the same as zero remaining.
	Complete bool

	// PrimaryExceeded and SecondaryLimited follow isRetryableTokenMintStatus:
	// a 403/429 with X-RateLimit-Remaining: 0, or with Retry-After.
	PrimaryExceeded  bool
	SecondaryLimited bool
	RetryAfter       time.Duration
}

// RateLimited reports whether the response carried either rate-limit signal.
func (i RateLimitInfo) RateLimited() bool {
	return i.PrimaryExceeded || i.SecondaryLimited
}

// ParseRateLimitHeaders reads the rate-limit headers from resp. It has no
// side effects.
func ParseRateLimitHeaders(resp *http.Response) RateLimitInfo {
	info := RateLimitInfo{Resource: resp.Header.Get("X-RateLimit-Resource")}
	if info.Resource == "" {
		info.Resource = "core"
	}

	limit, hasLimit := parseHeaderInt(resp.Header, "X-RateLimit-Limit")
	remaining, hasRemaining := parseHeaderInt(resp.Header, "X-RateLimit-Remaining")
	reset, hasReset := parseHeaderInt(resp.Header, "X-RateLimit-Reset")
	info.Limit, info.Remaining = limit, remaining
	if used, ok := parseHeaderInt(resp.Header, "X-RateLimit-Used"); ok {
		info.Used = used
	} else if hasLimit && hasRemaining {
		info.Used = limit - remaining
	}
	if hasReset {
		info.ResetAt = time.Unix(reset, 0)
	}
	info.Complete = hasLimit && hasRemaining && hasReset && limit > 0

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			info.SecondaryLimited = true
			if n, err := strconv.ParseInt(retryAfter, 10, 64); err == nil {
				info.RetryAfter = time.Duration(n) * time.Second
			}
		} else if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			info.PrimaryExceeded = true
		}
	}
	return info
}

func parseHeaderInt(h http.Header, name string) (int64, bool) {
	v := h.Get(name)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Quota is the last accepted observation of one installation's bucket.
type Quota struct {
	Account    string
	Limit      int64
	Remaining  int64
	Used       int64
	ResetAt    time.Time
	ObservedAt time.Time
}

// RemainingPct returns Remaining as a percentage of Limit.
func (q Quota) RemainingPct() float64 {
	if q.Limit <= 0 {
		return 0
	}
	return float64(q.Remaining) / float64(q.Limit) * 100
}

type quotaKey struct {
	logicalApp string
	instance   string
	account    string
	resource   string
}

// QuotaStore keeps the latest rate-limit observation for every installation
// of every pool instance, in process. It is the single writer of the
// githubsts_github_rate_limit_* gauges and the state rate-limit-aware
// selection reads.
//
// Only observations of an installation bucket belong here: the rate-limit
// poller's own probe and STS's own installation-token calls. App JWT calls
// spend a different bucket, and a token minted for a client is never kept
// or probed, so a bucket that only client tokens spend stays invisible.
type QuotaStore struct {
	mu      sync.RWMutex
	entries map[quotaKey]Quota
	now     func() time.Time

	probes chan poolInstanceKey
}

// probeRequestBuffer bounds pending probe requests. RequestProbe drops a
// request when the buffer is full; a burst of rate-limit signals only needs
// one refresh per instance, and the poller's own interval is the backstop.
const probeRequestBuffer = 64

// NewQuotaStore returns an empty store.
func NewQuotaStore() *QuotaStore {
	return &QuotaStore{
		entries: make(map[quotaKey]Quota),
		now:     time.Now,
		probes:  make(chan poolInstanceKey, probeRequestBuffer),
	}
}

// Observe records info for one installation (account) of one pool instance
// and refreshes that instance's gauges. It reports whether the observation
// was accepted.
//
// Responses can land out of order, so an observation only replaces the
// stored one when it describes a later window (a later reset), or the same
// window with at least as many requests used. GitHub never refunds requests
// inside a window, so a lower used count for the same reset is a stale
// response and is dropped.
func (s *QuotaStore) Observe(logicalApp, instance, account string, info RateLimitInfo) bool {
	if s == nil || !info.Complete {
		return false
	}
	key := quotaKey{
		logicalApp: logicalApp,
		instance:   instance,
		account:    strings.ToLower(account),
		resource:   info.Resource,
	}
	next := Quota{
		Account:    key.account,
		Limit:      info.Limit,
		Remaining:  info.Remaining,
		Used:       info.Used,
		ResetAt:    info.ResetAt,
		ObservedAt: s.now(),
	}

	s.mu.Lock()
	if cur, ok := s.entries[key]; ok {
		if next.ResetAt.Before(cur.ResetAt) || (next.ResetAt.Equal(cur.ResetAt) && next.Used < cur.Used) {
			s.mu.Unlock()
			return false
		}
	}
	s.entries[key] = next
	lowest, _ := s.lowestLocked(logicalApp, instance, info.Resource)
	s.mu.Unlock()

	renderQuotaGauges(logicalApp, instance, info.Resource, lowest)
	return true
}

// Lowest returns the installation with the least remaining for one pool
// instance and resource. Installations whose window has already reset are
// skipped unless every installation has reset, because their stored
// remaining is known to be out of date.
func (s *QuotaStore) Lowest(logicalApp, instance, resource string) (Quota, bool) {
	if s == nil {
		return Quota{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lowestLocked(logicalApp, instance, resource)
}

func (s *QuotaStore) lowestLocked(logicalApp, instance, resource string) (Quota, bool) {
	now := s.now()
	var best, bestExpired Quota
	var found, foundExpired bool
	for key, q := range s.entries {
		if key.logicalApp != logicalApp || key.instance != instance || key.resource != resource {
			continue
		}
		if !now.Before(q.ResetAt) {
			if !foundExpired || q.Remaining < bestExpired.Remaining {
				bestExpired, foundExpired = q, true
			}
			continue
		}
		if !found || q.Remaining < best.Remaining {
			best, found = q, true
		}
	}
	if found {
		return best, true
	}
	return bestExpired, foundExpired
}

// RequestProbe asks the rate-limit poller to refresh one instance soon, for
// example after a call on it was rate limited. It never blocks.
func (s *QuotaStore) RequestProbe(logicalApp, instance string) {
	if s == nil {
		return
	}
	select {
	case s.probes <- poolInstanceKey{logicalApp: logicalApp, instance: instance}:
	default:
	}
}

func (s *QuotaStore) probeRequests() <-chan poolInstanceKey {
	return s.probes
}

func renderQuotaGauges(logicalApp, instance, resource string, q Quota) {
	metrics.GitHubRateLimitLimit.WithLabelValues(logicalApp, instance, resource).Set(float64(q.Limit))
	metrics.GitHubRateLimitRemaining.WithLabelValues(logicalApp, instance, resource).Set(float64(q.Remaining))
	metrics.GitHubRateLimitUsed.WithLabelValues(logicalApp, instance, resource).Set(float64(q.Used))
	metrics.GitHubRateLimitResetTimestamp.WithLabelValues(logicalApp, instance, resource).Set(float64(q.ResetAt.Unix()))
	metrics.GitHubRateLimitRemainingPercent.WithLabelValues(logicalApp, instance, resource).Set(q.RemainingPct())
	metrics.GitHubRateLimitObservedTimestamp.WithLabelValues(logicalApp, instance, resource).Set(float64(q.ObservedAt.Unix()))
}
