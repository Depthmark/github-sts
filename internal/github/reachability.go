package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
)

// ReachabilityProber periodically probes GitHub API endpoints to verify
// connectivity. Results are exported as Prometheus gauges.
type ReachabilityProber struct {
	apps       map[string]AppConfig
	apiURL     string
	interval   time.Duration
	httpClient *http.Client
	cancel     context.CancelFunc
}

// NewReachabilityProber creates a reachability prober.
func NewReachabilityProber(apps map[string]AppConfig, apiURL string, interval time.Duration) *ReachabilityProber {
	return &ReachabilityProber{
		apps:       apps,
		apiURL:     apiURL,
		interval:   interval,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
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
	for appName, cfg := range p.apps {
		p.probeApp(ctx, appName, cfg)
	}
}

func (p *ReachabilityProber) probeApp(ctx context.Context, appName string, cfg AppConfig) {
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
		metrics.GitHubReachable.WithLabelValues(appName).Set(0)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, "jwt_error").Inc()
		slog.Error("reachability probe: JWT signing failed", "app", appName, "error", err)
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
	metrics.GitHubReachabilityCheckDuration.WithLabelValues(appName).Observe(duration)

	if err != nil {
		metrics.GitHubReachable.WithLabelValues(appName).Set(0)
		reason := classifyNetError(err)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, reason).Inc()
		slog.Warn("reachability probe failed", "app", appName, "reason", reason, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNotModified, http.StatusForbidden:
		// Reachable.
		metrics.GitHubReachable.WithLabelValues(appName).Set(1)
	case http.StatusUnauthorized:
		// Reachable but auth error (e.g., bad JWT).
		metrics.GitHubReachable.WithLabelValues(appName).Set(1)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, "auth_error").Inc()
	default:
		// 5xx or other — unreachable.
		metrics.GitHubReachable.WithLabelValues(appName).Set(0)
		metrics.GitHubReachabilityFailuresTotal.WithLabelValues(appName, "http_error").Inc()
		slog.Warn("reachability probe: unexpected status", "app", appName, "status", resp.StatusCode)
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

