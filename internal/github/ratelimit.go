package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppConfig holds the configuration for a GitHub App.
type AppConfig struct {
	AppID         int64
	PrivateKey    *rsa.PrivateKey
	OrgPolicyRepo string
}

// PoolInstanceConfig identifies one physical GitHub App instance for the
// background pollers (RateLimitPoller, ReachabilityProber), which sweep
// every instance of every configured app on a fixed interval rather than
// going through AppPool/AppTokenProvider — each poller manages its own JWT
// signing and token cache, isolated from the exchange-path request flow.
// For a non-pooled app, this is that app's single normalized instance.
type PoolInstanceConfig struct {
	LogicalApp string // the app name callers pass as ?app=
	Instance   string // this instance's label within its pool
	AppConfig
}

// poolInstanceKey uniquely identifies one instance across every pool.
// Keying by LogicalApp+Instance together (not Instance alone) matters
// because an instance's label defaults to its app_id, and the same app_id
// may legitimately be reused across two different logical apps' pools (see
// config.Settings.DuplicateAppIDWarnings) — Instance alone could collide in
// that case.
type poolInstanceKey struct {
	logicalApp string
	instance   string
}

// RateLimitPoller periodically polls GitHub rate limit endpoints for every
// configured instance's installations. Self-contained — manages its own JWT
// signing and token cache, isolated from the exchange-path AppTokenProvider.
type RateLimitPoller struct {
	instances         []PoolInstanceConfig
	apiURL            string
	interval          time.Duration
	installationCache map[poolInstanceKey][]installationEntry
	installationTTL   time.Duration
	tokenCache        map[tokenCacheKey]tokenEntry
	httpClient        *http.Client
	mu                sync.Mutex
	cancel            context.CancelFunc
}

type installationEntry struct {
	id        int64
	account   string
	fetchedAt time.Time
}

type tokenEntry struct {
	token     string
	expiresAt time.Time
}

// tokenCacheKey additionally scopes a token cache entry by installation ID:
// one instance can be installed on multiple orgs, each with its own token.
type tokenCacheKey struct {
	poolInstanceKey
	installationID int64
}

// NewRateLimitPoller creates a rate limit poller over the given flat list of
// pool instances (one entry per physical GitHub App, across every
// configured logical app).
func NewRateLimitPoller(instances []PoolInstanceConfig, apiURL string, interval time.Duration) *RateLimitPoller {
	return &RateLimitPoller{
		instances:         instances,
		apiURL:            apiURL,
		interval:          interval,
		installationCache: make(map[poolInstanceKey][]installationEntry),
		installationTTL:   10 * time.Minute,
		tokenCache:        make(map[tokenCacheKey]tokenEntry),
		httpClient:        &http.Client{Timeout: 15 * time.Second},
	}
}

// Start begins the polling loop in a background goroutine.
func (p *RateLimitPoller) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.pollLoop(ctx)
}

// Stop halts the polling loop.
func (p *RateLimitPoller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *RateLimitPoller) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Run immediately on start.
	p.pollAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

func (p *RateLimitPoller) pollAll(ctx context.Context) {
	for _, pi := range p.instances {
		key := poolInstanceKey{logicalApp: pi.LogicalApp, instance: pi.Instance}
		installations, err := p.getInstallations(ctx, key, pi.AppConfig)
		if err != nil {
			slog.Error("rate limit poller: failed to get installations", "app", pi.LogicalApp, "instance", pi.Instance, "error", err)
			continue
		}

		for _, inst := range installations {
			token, err := p.getOrCreateToken(ctx, key, pi.AppConfig, inst.id)
			if err != nil {
				slog.Error("rate limit poller: failed to get token", "app", pi.LogicalApp, "instance", pi.Instance, "installation", inst.id, "error", err)
				continue
			}

			p.pollRateLimit(ctx, pi.LogicalApp, pi.Instance, token, inst.account)
		}
	}
}

func (p *RateLimitPoller) getInstallations(ctx context.Context, key poolInstanceKey, cfg AppConfig) ([]installationEntry, error) {
	p.mu.Lock()
	cached, ok := p.installationCache[key]
	if ok && len(cached) > 0 && time.Since(cached[0].fetchedAt) < p.installationTTL {
		p.mu.Unlock()
		return cached, nil
	}
	p.mu.Unlock()

	appJWT, err := p.signJWT(cfg)
	if err != nil {
		return nil, err
	}

	var installations []installationEntry
	nextURL := fmt.Sprintf("%s/app/installations?per_page=100", p.apiURL)

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+appJWT)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := p.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("GET installations returned %d", resp.StatusCode)
		}

		var page []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		_ = resp.Body.Close()

		now := time.Now()
		for _, inst := range page {
			installations = append(installations, installationEntry{
				id:        inst.ID,
				account:   inst.Account.Login,
				fetchedAt: now,
			})
		}

		nextURL = parseLinkNext(resp.Header.Get("Link"))
	}

	p.mu.Lock()
	p.installationCache[key] = installations
	p.mu.Unlock()

	return installations, nil
}

func (p *RateLimitPoller) getOrCreateToken(ctx context.Context, key poolInstanceKey, cfg AppConfig, installationID int64) (string, error) {
	cacheKey := tokenCacheKey{poolInstanceKey: key, installationID: installationID}

	p.mu.Lock()
	if entry, ok := p.tokenCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		p.mu.Unlock()
		return entry.token, nil
	}
	p.mu.Unlock()

	appJWT, err := p.signJWT(cfg)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST access_tokens returned %d", resp.StatusCode)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	// Cache with 5-minute buffer before actual expiry.
	p.mu.Lock()
	p.tokenCache[cacheKey] = tokenEntry{
		token:     result.Token,
		expiresAt: result.ExpiresAt.Add(-5 * time.Minute),
	}
	p.mu.Unlock()

	return result.Token, nil
}

func (p *RateLimitPoller) pollRateLimit(ctx context.Context, appName, instance, token, account string) {
	url := fmt.Sprintf("%s/rate_limit", p.apiURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		slog.Error("rate limit poll failed", "app", appName, "instance", instance, "account", account, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	ExtractRateLimitHeaders(resp, appName, instance, "rate_limit_poller")
}

func (p *RateLimitPoller) signJWT(cfg AppConfig) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": fmt.Sprintf("%d", cfg.AppID),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(cfg.PrivateKey)
}

// parseLinkNext extracts the "next" URL from a GitHub Link header.
func parseLinkNext(link string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				return part[start+1 : end]
			}
		}
	}
	return ""
}
