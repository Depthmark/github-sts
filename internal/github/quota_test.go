package github

import (
	"math"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func rateLimitResponse(status int, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h}
}

func completeInfo(limit, remaining int64, reset time.Time) RateLimitInfo {
	return RateLimitInfo{
		Resource:  "core",
		Limit:     limit,
		Remaining: remaining,
		Used:      limit - remaining,
		ResetAt:   reset.Truncate(time.Second),
		Complete:  true,
	}
}

func TestParseRateLimitHeaders(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		want    RateLimitInfo
	}{
		{
			name:   "complete",
			status: http.StatusOK,
			headers: map[string]string{
				"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "4990",
				"X-RateLimit-Used": "10", "X-RateLimit-Reset": "1789327756", "X-RateLimit-Resource": "core",
			},
			want: RateLimitInfo{Resource: "core", Limit: 5000, Remaining: 4990, Used: 10, ResetAt: time.Unix(1789327756, 0), Complete: true},
		},
		{
			name:   "used derived when header absent",
			status: http.StatusNotModified,
			headers: map[string]string{
				"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "4000", "X-RateLimit-Reset": "1789327756",
			},
			want: RateLimitInfo{Resource: "core", Limit: 5000, Remaining: 4000, Used: 1000, ResetAt: time.Unix(1789327756, 0), Complete: true},
		},
		{
			name:    "missing remaining is incomplete, not zero",
			status:  http.StatusOK,
			headers: map[string]string{"X-RateLimit-Limit": "5000", "X-RateLimit-Reset": "1789327756"},
			want:    RateLimitInfo{Resource: "core", Limit: 5000, ResetAt: time.Unix(1789327756, 0)},
		},
		{
			name:    "no headers",
			status:  http.StatusOK,
			headers: nil,
			want:    RateLimitInfo{Resource: "core"},
		},
		{
			name:   "primary limit exceeded",
			status: http.StatusForbidden,
			headers: map[string]string{
				"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1789327756",
			},
			want: RateLimitInfo{Resource: "core", Limit: 5000, Remaining: 0, Used: 5000, ResetAt: time.Unix(1789327756, 0), Complete: true, PrimaryExceeded: true},
		},
		{
			name:    "secondary limit",
			status:  http.StatusTooManyRequests,
			headers: map[string]string{"Retry-After": "60"},
			want:    RateLimitInfo{Resource: "core", SecondaryLimited: true, RetryAfter: time.Minute},
		},
		{
			name:    "remaining zero on 200 is not a signal",
			status:  http.StatusOK,
			headers: map[string]string{"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1789327756"},
			want:    RateLimitInfo{Resource: "core", Limit: 5000, Used: 5000, ResetAt: time.Unix(1789327756, 0), Complete: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRateLimitHeaders(rateLimitResponse(tt.status, tt.headers))
			if got != tt.want {
				t.Errorf("ParseRateLimitHeaders() =\n  %+v\nwant\n  %+v", got, tt.want)
			}
		})
	}
}

func TestQuotaStore_ObserveRejectsIncomplete(t *testing.T) {
	s := NewQuotaStore()
	if s.Observe("quota-incomplete", "i1", "org", RateLimitInfo{Resource: "core", Limit: 5000}) {
		t.Fatal("incomplete observation was accepted")
	}
	if _, ok := s.Lowest("quota-incomplete", "i1", "core"); ok {
		t.Fatal("incomplete observation was stored")
	}
}

func TestQuotaStore_ObserveOrdering(t *testing.T) {
	now := time.Now()
	window := now.Add(30 * time.Minute)
	// uncounted is what GET /rate_limit or a 304 returns for an installation
	// token: used=0 and a reset about an hour out (V1b).
	uncounted := func(reset time.Time) RateLimitInfo { return completeInfo(5000, 5000, reset) }

	tests := []struct {
		name         string
		first        RateLimitInfo
		firstAt      time.Time // when first was observed; zero means now
		second       RateLimitInfo
		wantAccepted bool
		wantRemain   int64
	}{
		{name: "same window, more used", first: completeInfo(5000, 4950, window), second: completeInfo(5000, 4900, window), wantAccepted: true, wantRemain: 4900},
		{name: "same window, same used refreshes", first: completeInfo(5000, 4950, window), second: completeInfo(5000, 4950, window), wantAccepted: true, wantRemain: 4950},
		{name: "same window, fewer used is stale", first: completeInfo(5000, 4950, window), second: completeInfo(5000, 4990, window), wantAccepted: false, wantRemain: 4950},
		{name: "open window cannot move to a later reset", first: completeInfo(5000, 4950, window), second: completeInfo(5000, 4999, window.Add(time.Hour)), wantAccepted: false, wantRemain: 4950},
		{name: "open window cannot move to an earlier reset", first: completeInfo(5000, 4950, window), second: completeInfo(5000, 4000, window.Add(-10*time.Minute)), wantAccepted: false, wantRemain: 4950},
		{name: "uncounted reading never overwrites a counted open window (V1b)", first: completeInfo(5000, 4997, window), second: uncounted(now.Add(time.Hour)), wantAccepted: false, wantRemain: 4997},
		{name: "counted reading replaces an uncounted one, even with an earlier reset", first: uncounted(now.Add(time.Hour)), second: completeInfo(5000, 4997, window), wantAccepted: true, wantRemain: 4997},
		{name: "uncounted reading replaces an uncounted one with a later reset", first: uncounted(window), second: uncounted(window.Add(time.Minute)), wantAccepted: true, wantRemain: 5000},
		{name: "after reset, the next window replaces", first: completeInfo(5000, 10, now.Add(-time.Second)), firstAt: now.Add(-time.Hour), second: completeInfo(5000, 4999, now.Add(time.Hour)), wantAccepted: true, wantRemain: 4999},
		{name: "after reset, a stale response for the old window is dropped", first: completeInfo(5000, 10, now.Add(-time.Second)), firstAt: now.Add(-time.Hour), second: completeInfo(5000, 20, now.Add(-time.Second)), wantAccepted: false, wantRemain: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewQuotaStore()
			if !tt.firstAt.IsZero() {
				s.now = func() time.Time { return tt.firstAt }
			}
			if !s.Observe("quota-order", "i1", "org", tt.first) {
				t.Fatal("first observation rejected")
			}
			s.now = func() time.Time { return now }
			if got := s.Observe("quota-order", "i1", "org", tt.second); got != tt.wantAccepted {
				t.Fatalf("accepted = %v, want %v", got, tt.wantAccepted)
			}
			s.mu.RLock()
			q := s.entries[quotaKey{logicalApp: "quota-order", instance: "i1", account: "org", resource: "core"}]
			s.mu.RUnlock()
			if q.Remaining != tt.wantRemain {
				t.Errorf("remaining = %d, want %d", q.Remaining, tt.wantRemain)
			}
		})
	}
}

func TestQuotaStore_AccountIsCaseInsensitive(t *testing.T) {
	s := NewQuotaStore()
	window := time.Now().Add(time.Hour)
	s.Observe("quota-case", "i1", "Depthmark-Lab", completeInfo(5000, 4000, window))
	// The same installation seen through a target scope with other casing
	// must land on the same entry, so a stale lower count is rejected.
	if s.Observe("quota-case", "i1", "depthmark-lab", completeInfo(5000, 4500, window)) {
		t.Fatal("same installation under different casing was treated as a separate entry")
	}
}

func TestQuotaStore_LowestAcrossInstallations(t *testing.T) {
	s := NewQuotaStore()
	future := time.Now().Add(time.Hour)
	s.Observe("quota-lowest", "i1", "org-a", completeInfo(5000, 4000, future))
	s.Observe("quota-lowest", "i1", "org-b", completeInfo(12500, 900, future))
	s.Observe("quota-lowest", "i2", "org-a", completeInfo(5000, 10, future))

	q, ok := s.Lowest("quota-lowest", "i1", "core")
	if !ok || q.Account != "org-b" || q.Remaining != 900 {
		t.Fatalf("Lowest(i1) = %+v, %v; want org-b with 900", q, ok)
	}

	labels := []string{"quota-lowest", "i1", "core"}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitRemaining.WithLabelValues(labels...)); got != 900 {
		t.Errorf("remaining gauge = %v, want 900 (lowest installation, not last written)", got)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitLimit.WithLabelValues(labels...)); got != 12500 {
		t.Errorf("limit gauge = %v, want 12500", got)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitRemainingPercent.WithLabelValues(labels...)); math.Abs(got-7.2) > 1e-9 {
		t.Errorf("remaining percent gauge = %v, want 7.2", got)
	}
	if got := testutil.ToFloat64(metrics.GitHubRateLimitObservedTimestamp.WithLabelValues(labels...)); got < float64(time.Now().Add(-time.Minute).Unix()) {
		t.Errorf("observed timestamp gauge = %v, want about now", got)
	}
}

func TestQuotaStore_LowestSkipsResetInstallations(t *testing.T) {
	s := NewQuotaStore()
	now := time.Now()
	s.now = func() time.Time { return now.Add(-2 * time.Hour) }
	s.Observe("quota-reset", "i1", "org-a", completeInfo(5000, 5, now.Add(-time.Hour)))
	s.now = func() time.Time { return now }
	s.Observe("quota-reset", "i1", "org-b", completeInfo(5000, 3000, now.Add(time.Hour)))

	q, ok := s.Lowest("quota-reset", "i1", "core")
	if !ok || q.Account != "org-b" {
		t.Fatalf("Lowest = %+v, %v; want org-b, whose window is still open", q, ok)
	}

	only := NewQuotaStore()
	only.now = func() time.Time { return now.Add(-2 * time.Hour) }
	only.Observe("quota-reset-only", "i1", "org-a", completeInfo(5000, 5, now.Add(-time.Hour)))
	only.now = func() time.Time { return now }
	if q, ok := only.Lowest("quota-reset-only", "i1", "core"); !ok || q.Remaining != 5 {
		t.Fatalf("Lowest with only reset installations = %+v, %v; want the stale reading rather than nothing", q, ok)
	}
}

func TestQuotaStore_RequestProbeNeverBlocks(t *testing.T) {
	s := NewQuotaStore()
	done := make(chan struct{})
	go func() {
		for i := range probeRequestBuffer * 3 {
			s.RequestProbe("quota-probe", "i"+strconv.Itoa(i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestProbe blocked with a full buffer")
	}
	if got := len(s.probeRequests()); got != probeRequestBuffer {
		t.Errorf("buffered probe requests = %d, want %d", got, probeRequestBuffer)
	}
}

func TestQuotaStore_NilIsSafe(t *testing.T) {
	var s *QuotaStore
	if s.Observe("quota-nil", "i1", "org", completeInfo(5000, 1, time.Now().Add(time.Hour))) {
		t.Fatal("nil store accepted an observation")
	}
	s.RequestProbe("quota-nil", "i1")
	if _, ok := s.Lowest("quota-nil", "i1", "core"); ok {
		t.Fatal("nil store returned a quota")
	}
}
