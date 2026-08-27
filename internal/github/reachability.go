package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
)

// ReachabilityProber periodically probes GitHub API endpoints to verify
// connectivity, per instance. Results are exported as Prometheus gauges and
// kept in an in-memory map so AppPool can cheaply skip a known-unreachable
// candidate as part of its baseline liveness filter, without an extra live
// call per request.
type ReachabilityProber struct {
	instances  []PoolInstanceConfig
	apiURL     string
	interval   time.Duration
	httpClient *http.Client
	cancel     context.CancelFunc

	mu    sync.RWMutex
	state map[poolInstanceKey]bool
}

// NewReachabilityProber creates a reachability prober over the given flat
// list of pool instances (one entry per physical GitHub App, across every
// configured logical app).
func NewReachabilityProber(instances []PoolInstanceConfig, apiURL string, interval time.Duration) *ReachabilityProber {
	return &ReachabilityProber{
		instances:  instances,
		apiURL:     apiURL,
		interval:   interval,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		state:      make(map[poolInstanceKey]bool),
	}
}

// IsReachable reports whether the most recent probe for this instance found
// it reachable. Defaults to true (assume reachable) when no probe result
// exists yet for logicalApp/instance — e.g. before the first probe
// completes, or when reachability probing is disabled entirely (server.go
// then never constructs a ReachabilityProber at all, and AppPool's baseline
// filter degrades to a no-op rather than incorrectly excluding every
// candidate on missing data).
func (p *ReachabilityProber) IsReachable(logicalApp, instance string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	reachable, ok := p.state[poolInstanceKey{logicalApp: logicalApp, instance: instance}]
	if !ok {
		return true
	}
	return reachable
}

// Start begins the probing loop in a background goroutine.
func (p *ReachabilityProber) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.probeLoop(ctx)
}

// Stop halts the probing loop.
func (p *ReachabilityProber) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *ReachabilityProber) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Run immediately on start.
	p.probeAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll(ctx)
		}
	}
}

func (p *ReachabilityProber) probeAll(ctx context.Context) {
	for _, pi := range p.instances {
		p.probeInstance(ctx, pi)
	}
}

// setReachable records the outcome of a probe both to the Prometheus gauge
// (for dashboards/alerting) and to the in-memory state map (for AppPool's
// baseline liveness filter, which needs a cheap, no-network-call answer).
func (p *ReachabilityProber) setReachable(logicalApp, instance string, reachable bool) {
	v := 0.0
	if reachable {
		v = 1
	}
	metrics.GitHubReachable.WithLabelValues(logicalApp, instance).Set(v)

	p.mu.Lock()
	p.state[poolInstanceKey{logicalApp: logicalApp, instance: instance}] = reachable
	p.mu.Unlock()
}

func (p *ReachabilityProber) probeInstance(ctx context.Context, pi PoolInstanceConfig) {
	appName, instance, cfg := pi.LogicalApp, pi.Instance, pi.AppConfig
	start := time.Now()

	// Generate App JWT for the probe.
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": formatAppID(cfg.AppID),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	appJWT, err := tok.SignedString(cfg.PrivateKey)
	if err != nil {
		p.setReachable(appName, instance, false)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, instance, "jwt_error").Inc()
		slog.Error("reachability probe: JWT signing failed", "app", appName, "instance", instance, "error", err)
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := p.apiURL + "/rate_limit"
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	duration := time.Since(start).Seconds()
	metrics.GitHubReachabilityCheckDuration.WithLabelValues(appName, instance).Observe(duration)

	if err != nil {
		p.setReachable(appName, instance, false)
		reason := classifyNetError(err)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, instance, reason).Inc()
		slog.Warn("reachability probe failed", "app", appName, "instance", instance, "reason", reason, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNotModified, http.StatusForbidden:
		// Reachable.
		p.setReachable(appName, instance, true)
	case http.StatusUnauthorized:
		// Reachable but auth error (e.g., bad JWT).
		p.setReachable(appName, instance, true)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, instance, "auth_error").Inc()
	default:
		// 5xx or other — unreachable.
		p.setReachable(appName, instance, false)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, instance, "http_error").Inc()
		slog.Warn("reachability probe: unexpected status", "app", appName, "instance", instance, "status", resp.StatusCode)
	}
}

func classifyNetError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connection_error"
}

func formatAppID(id int64) string {
	return fmt.Sprintf("%d", id)
}
