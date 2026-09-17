package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
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

// rateLimitProbePath is the endpoint the poller reads installation buckets
// from.
//
// GET /rate_limit cannot be used: it reports a fresh bucket (used=0, reset
// about an hour out) that does not match the bucket real API calls spend,
// in its headers and its body alike. The probe is a conditional GET of a
// static resource instead. Its first response per token is a counted 200
// that carries the installation bucket. Later responses are 304 Not
// Modified and spend nothing, but for installation tokens they carry the
// same unused bucket as /rate_limit (V1b, observed in github-sts-dev on
// 2026-09-13), so QuotaStore drops their readings while it holds a counted
// one; see replacesQuota.
//
// Left alone, that means only the very first probe per cached token is ever
// trustworthy: every 304 after it is free but worthless, so a bucket drained
// by traffic github-sts never sees (client tokens, or a probe reading it
// directly) stays invisible for as long as the token is cached — up to
// tokenEntry's ~55-minute TTL. forceCountedInterval bounds that: once a
// cached etag is older than it, the probe skips If-None-Match and pays for
// another counted 200, trading a small amount of bucket headroom for a
// bounded staleness ceiling instead of an unbounded one. See
// .agent-tasks/github-rate-limit-telemetry-drain-visibility.md.
const rateLimitProbePath = "/emojis"

// probeTokenPermissions narrows the poller's own installation token. The
// probe needs no permission at all, and metadata:read is implicit on every
// installation, so this is the least a token can hold. An empty request
// body would inherit every permission the installation has, for a token
// that sits in memory for most of an hour.
var probeTokenPermissions = map[string]string{"metadata": "read"}

const (
	// defaultMinEventProbeSpacing bounds probes triggered by rate-limit
	// signals, so a burst of 403s cannot turn into a burst of probes (which
	// would count toward GitHub's secondary rate limits even when they are
	// 304s).
	defaultMinEventProbeSpacing = 5 * time.Second

	// maxProbeBodyBytes caps how much of a 200 probe body is read before it
	// is discarded. Draining lets the connection be reused.
	maxProbeBodyBytes = 1 << 20
)

// RateLimitPoller keeps the QuotaStore fresh for every configured instance's
// installations, without waiting for exchange traffic to reveal a change. It
// probes each installation on a fixed interval, once more just after a
// drained bucket resets, and on demand when a call on that instance was rate
// limited (QuotaStore.RequestProbe).
//
// The poller only ever uses installation tokens it minted for itself,
// narrowed to probeTokenPermissions and never handed to anyone. It never
// sees, keeps or probes a token minted for a client, so a bucket that only
// client tokens spend is out of its reach by design.
type RateLimitPoller struct {
	instances         []PoolInstanceConfig
	byKey             map[poolInstanceKey]PoolInstanceConfig
	apiURL            string
	interval          time.Duration
	quota             *QuotaStore
	installationCache map[poolInstanceKey][]installationEntry
	installationTTL   time.Duration
	tokenCache        map[tokenCacheKey]tokenEntry
	httpClient        *http.Client
	mu                sync.Mutex
	cancel            context.CancelFunc
	now               func() time.Time

	// forceCountedInterval bounds how long a cached etag can keep a probe
	// conditional. Once it has held since the last counted 200 for longer
	// than this, the probe drops If-None-Match and pays for a fresh one, so
	// a drain this poller's own calls never observed is never invisible for
	// longer than forceCountedInterval — see rateLimitProbePath. <= 0 forces
	// every probe to be counted.
	forceCountedInterval time.Duration

	// lastProbe is only touched by the poll loop goroutine.
	lastProbe            map[poolInstanceKey]time.Time
	minEventProbeSpacing time.Duration

	// resetTimers holds at most one pending post-reset probe per instance,
	// guarded by mu. Timers hand their key to the loop through resetDue.
	resetTimers map[poolInstanceKey]*resetTimer
	resetDue    chan poolInstanceKey
	resetDelay  func() time.Duration
}

type resetTimer struct {
	at    time.Time
	timer *time.Timer
}

type installationEntry struct {
	id        int64
	account   string
	fetchedAt time.Time
}

type tokenEntry struct {
	token     string
	expiresAt time.Time
	// etag is the ETag of this token's last counted (200) probe response. It
	// is cached per token because GitHub varies the probe response on
	// Authorization.
	etag string
	// etagSetAt is when etag was captured. A probe only sends If-None-Match
	// while etag is younger than forceCountedInterval; see rateLimitProbePath.
	etagSetAt time.Time
}

// tokenCacheKey additionally scopes a token cache entry by installation ID:
// one instance can be installed on multiple orgs, each with its own token.
type tokenCacheKey struct {
	poolInstanceKey
	installationID int64
}

// NewRateLimitPoller creates a rate limit poller over the given flat list of
// pool instances (one entry per physical GitHub App, across every
// configured logical app). Observations go to quota; a nil quota gets a
// private store, so the gauges are still rendered. forceCountedInterval
// bounds how long a cached etag can keep probes conditional (and therefore
// untrustworthy for installation tokens) between counted reads; see
// rateLimitProbePath.
func NewRateLimitPoller(instances []PoolInstanceConfig, apiURL string, interval time.Duration, quota *QuotaStore, forceCountedInterval time.Duration) *RateLimitPoller {
	if quota == nil {
		quota = NewQuotaStore()
	}
	byKey := make(map[poolInstanceKey]PoolInstanceConfig, len(instances))
	for _, pi := range instances {
		byKey[poolInstanceKey{logicalApp: pi.LogicalApp, instance: pi.Instance}] = pi
	}
	return &RateLimitPoller{
		instances:            instances,
		byKey:                byKey,
		apiURL:               apiURL,
		interval:             interval,
		quota:                quota,
		installationCache:    make(map[poolInstanceKey][]installationEntry),
		installationTTL:      10 * time.Minute,
		tokenCache:           make(map[tokenCacheKey]tokenEntry),
		httpClient:           &http.Client{Timeout: 15 * time.Second},
		now:                  time.Now,
		forceCountedInterval: forceCountedInterval,
		lastProbe:            make(map[poolInstanceKey]time.Time),
		minEventProbeSpacing: defaultMinEventProbeSpacing,
		resetTimers:          make(map[poolInstanceKey]*resetTimer),
		resetDue:             make(chan poolInstanceKey, probeRequestBuffer),
		resetDelay:           defaultResetDelay,
	}
}

// defaultResetDelay waits 1 to 3 seconds past the reported reset, so a
// small clock difference with GitHub does not probe the old window, and
// replicas do not all probe in the same second.
func defaultResetDelay() time.Duration {
	return time.Second + rand.N(2*time.Second)
}

// Start begins the polling loop in a background goroutine.
func (p *RateLimitPoller) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.pollLoop(ctx)
}

// Stop halts the polling loop and any pending post-reset probe.
func (p *RateLimitPoller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, rt := range p.resetTimers {
		rt.timer.Stop()
		delete(p.resetTimers, key)
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
		case key := <-p.resetDue:
			p.pollKey(ctx, key)
		case key := <-p.quota.probeRequests():
			if time.Since(p.lastProbe[key]) < p.minEventProbeSpacing {
				continue
			}
			p.pollKey(ctx, key)
		}
	}
}

func (p *RateLimitPoller) pollAll(ctx context.Context) {
	for _, pi := range p.instances {
		p.pollInstance(ctx, pi)
	}
}

func (p *RateLimitPoller) pollKey(ctx context.Context, key poolInstanceKey) {
	if pi, ok := p.byKey[key]; ok {
		p.pollInstance(ctx, pi)
	}
}

func (p *RateLimitPoller) pollInstance(ctx context.Context, pi PoolInstanceConfig) {
	key := poolInstanceKey{logicalApp: pi.LogicalApp, instance: pi.Instance}
	p.lastProbe[key] = time.Now()

	installations, err := p.getInstallations(ctx, key, pi.AppConfig)
	if err != nil {
		slog.Error("rate limit poller: failed to get installations", "app", pi.LogicalApp, "instance", pi.Instance, "error", err)
		return
	}
	for _, inst := range installations {
		p.probeInstallation(ctx, pi, inst)
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

func (p *RateLimitPoller) getOrCreateToken(ctx context.Context, cacheKey tokenCacheKey, cfg AppConfig) (tokenEntry, error) {
	p.mu.Lock()
	if entry, ok := p.tokenCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		p.mu.Unlock()
		return entry, nil
	}
	p.mu.Unlock()

	appJWT, err := p.signJWT(cfg)
	if err != nil {
		return tokenEntry{}, err
	}

	body, err := json.Marshal(map[string]any{"permissions": probeTokenPermissions})
	if err != nil {
		return tokenEntry{}, err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiURL, cacheKey.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return tokenEntry{}, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return tokenEntry{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return tokenEntry{}, fmt.Errorf("POST access_tokens returned %d", resp.StatusCode)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	// Cache with 5-minute buffer before actual expiry.
	entry := tokenEntry{
		token:     result.Token,
		expiresAt: result.ExpiresAt.Add(-5 * time.Minute),
	}
	p.mu.Lock()
	p.tokenCache[cacheKey] = entry
	p.mu.Unlock()

	return entry, nil
}

// probeInstallation reads one installation's bucket with a conditional
// request and records it. Only a response that is authoritative for the
// bucket is recorded: a 200 or 304, or a 403/429 that is itself a rate-limit
// signal, carrying a complete set of headers. A 401 means the poller's token
// is no longer valid, which says nothing about the bucket.
func (p *RateLimitPoller) probeInstallation(ctx context.Context, pi PoolInstanceConfig, inst installationEntry) {
	key := poolInstanceKey{logicalApp: pi.LogicalApp, instance: pi.Instance}
	cacheKey := tokenCacheKey{poolInstanceKey: key, installationID: inst.id}
	record := func(result string) {
		metrics.GitHubRateLimitProbeTotal.WithLabelValues(pi.LogicalApp, pi.Instance, result).Inc()
	}

	entry, err := p.getOrCreateToken(ctx, cacheKey, pi.AppConfig)
	if err != nil {
		record("error")
		slog.Error("rate limit poller: failed to get token", "app", pi.LogicalApp, "instance", pi.Instance, "installation", inst.id, "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+rateLimitProbePath, nil)
	if err != nil {
		record("error")
		return
	}
	req.Header.Set("Authorization", "Bearer "+entry.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if entry.etag != "" && p.forceCountedInterval > 0 && p.now().Sub(entry.etagSetAt) < p.forceCountedInterval {
		req.Header.Set("If-None-Match", entry.etag)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		record("error")
		slog.Error("rate limit probe failed", "app", pi.LogicalApp, "instance", pi.Instance, "account", inst.account, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))

	info := ExtractRateLimitHeaders(resp, pi.LogicalApp, pi.Instance, "rate_limit_poller")

	var result string
	switch {
	case resp.StatusCode == http.StatusNotModified:
		result = "not_modified"
	case resp.StatusCode == http.StatusOK:
		result = "ok"
		p.recordCountedProbe(cacheKey, entry.token, resp.Header.Get("ETag"))
	case resp.StatusCode == http.StatusUnauthorized:
		p.dropToken(cacheKey, entry.token)
		record("unauthorized")
		slog.Warn("rate limit probe: poller token rejected, minting a new one next probe", "app", pi.LogicalApp, "instance", pi.Instance, "account", inst.account)
		return
	case info.RateLimited():
		result = "rate_limited"
	default:
		record("error")
		slog.Warn("rate limit probe: unexpected status", "app", pi.LogicalApp, "instance", pi.Instance, "account", inst.account, "status", resp.StatusCode)
		return
	}

	if !info.Complete {
		record("incomplete_headers")
		slog.Warn("rate limit probe: response lacks rate-limit headers", "app", pi.LogicalApp, "instance", pi.Instance, "account", inst.account, "status", resp.StatusCode)
		return
	}
	record(result)

	if p.quota.Observe(pi.LogicalApp, pi.Instance, inst.account, info) && info.Remaining < info.Limit {
		p.armResetProbe(key, info.ResetAt)
	}
}

// recordCountedProbe stores the etag (if any) and the counted-read timestamp
// for the token a counted 200 was served to, unless the token was replaced in
// the meantime. Recording the timestamp even for an empty etag is
// deliberate: a probe with nothing to cache stays uncached (see its use in
// probeInstallation), so no explicit staleness check is skipped.
func (p *RateLimitPoller) recordCountedProbe(cacheKey tokenCacheKey, token, etag string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.tokenCache[cacheKey]; ok && entry.token == token {
		entry.etag = etag
		entry.etagSetAt = p.now()
		p.tokenCache[cacheKey] = entry
	}
}

func (p *RateLimitPoller) dropToken(cacheKey tokenCacheKey, token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.tokenCache[cacheKey]; ok && entry.token == token {
		delete(p.tokenCache, cacheKey)
	}
}

// armResetProbe schedules one probe of key just after resetAt, so a drained
// bucket reads as recovered as soon as GitHub resets it, instead of after
// the next tick or the next exchange. An instance keeps a single pending
// timer, for its earliest known future reset.
func (p *RateLimitPoller) armResetProbe(key poolInstanceKey, resetAt time.Time) {
	now := time.Now()
	if !resetAt.After(now) {
		return
	}
	at := resetAt.Add(p.resetDelay())

	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.resetTimers[key]; ok {
		if cur.at.After(now) && !cur.at.After(at) {
			return
		}
		cur.timer.Stop()
	}
	rt := &resetTimer{at: at}
	rt.timer = time.AfterFunc(at.Sub(now), func() {
		p.mu.Lock()
		if p.resetTimers[key] == rt {
			delete(p.resetTimers, key)
		}
		p.mu.Unlock()
		select {
		case p.resetDue <- key:
		default:
		}
	})
	p.resetTimers[key] = rt
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
