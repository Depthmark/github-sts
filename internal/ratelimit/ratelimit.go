// Package ratelimit provides per-IP rate limiting with CIDR-based exemptions.
package ratelimit

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter enforces per-IP token-bucket rate limits. IPs matching
// any exempt CIDR bypass rate limiting entirely.
type IPRateLimiter struct {
	rate        rate.Limit
	burst       int
	exemptNets  []*net.IPNet
	limiters    map[string]*entry
	mu          sync.Mutex
	stopCleanup chan struct{}
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New creates an IPRateLimiter. exemptCIDRs should already be validated.
func New(rps float64, burst int, exemptCIDRs []string) (*IPRateLimiter, error) {
	var nets []*net.IPNet
	for _, cidr := range exemptCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}

	l := &IPRateLimiter{
		rate:        rate.Limit(rps),
		burst:       burst,
		exemptNets:  nets,
		limiters:    make(map[string]*entry),
		stopCleanup: make(chan struct{}),
	}

	go l.cleanupLoop()
	return l, nil
}

// Allow reports whether a request from the given IP should be permitted.
func (l *IPRateLimiter) Allow(ip string) bool {
	if l.isExempt(ip) {
		return true
	}

	l.mu.Lock()
	e, ok := l.limiters[ip]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	l.mu.Unlock()

	return e.limiter.Allow()
}

// Stop halts the background cleanup goroutine.
func (l *IPRateLimiter) Stop() {
	close(l.stopCleanup)
}

func (l *IPRateLimiter) isExempt(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range l.exemptNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// cleanupLoop evicts stale limiter entries every 5 minutes.
func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCleanup:
			return
		case <-ticker.C:
			l.evictStale()
		}
	}
}

func (l *IPRateLimiter) evictStale() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, e := range l.limiters {
		if e.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}
