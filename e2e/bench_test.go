//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/handler"
	"github.com/depthmark/github-sts/internal/jti"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

// ---------------------------------------------------------------------------
// Realistic benchmark configuration
// ---------------------------------------------------------------------------

const (
	// GitHub App rate limit: 15,000 API calls/hour per app.
	githubRateLimitPerHour = 15_000
	githubRateLimitPerMin  = githubRateLimitPerHour / 60 // 250/min

	// Simulated GitHub API response latency (real-world: 50-300ms).
	githubAPILatencyMin = 80 * time.Millisecond
	githubAPILatencyMax = 200 * time.Millisecond
)

// ---------------------------------------------------------------------------
// JSON report structures
// ---------------------------------------------------------------------------

type BenchmarkReport struct {
	Timestamp       string              `json:"timestamp"`
	GoVersion       string              `json:"go_version"`
	RateLimitPerApp int                 `json:"rate_limit_per_app_per_hour"`
	SimulatedLatency string             `json:"simulated_github_api_latency"`
	Scenarios       []ScenarioResult    `json:"scenarios"`
	Scaling         []ScalingResult     `json:"scaling"`
	Projection      []ProjectionResult  `json:"projection"`
	Internal        InternalCeiling     `json:"internal_ceiling"`
}

type ScenarioResult struct {
	Name        string  `json:"name"`
	Apps        int     `json:"apps"`
	Requests    int64   `json:"requests"`
	Successes   int64   `json:"successes"`
	Errors      int64   `json:"errors"`
	RateLimited int64   `json:"rate_limited"`
	ReqPerMin   float64 `json:"req_per_min"`
	ReqPerHour  float64 `json:"req_per_hour"`
	SuccessRate float64 `json:"success_rate_pct"`
	LatencyP50  float64 `json:"latency_p50_ms"`
	LatencyP95  float64 `json:"latency_p95_ms"`
	LatencyP99  float64 `json:"latency_p99_ms"`
	LatencyMax  float64 `json:"latency_max_ms"`
	Concurrency int     `json:"concurrency"`
	DurationSec float64 `json:"duration_sec"`
}

type ScalingResult struct {
	Apps            int     `json:"apps"`
	TheoreticalMax  float64 `json:"theoretical_max_per_hour"`
	MeasuredPerMin  float64 `json:"measured_per_min"`
	MeasuredPerHour float64 `json:"measured_per_hour"`
	Efficiency      float64 `json:"efficiency_pct"`
	SuccessRate     float64 `json:"success_rate_pct"`
	LatencyP99      float64 `json:"latency_p99_ms"`
}

type ProjectionResult struct {
	TargetPerHour   int     `json:"target_per_hour"`
	AppsNeeded      int     `json:"apps_needed"`
	EffectivePerMin float64 `json:"effective_per_min"`
}

type InternalCeiling struct {
	ReqPerMin  float64 `json:"req_per_min_no_ratelimit"`
	LatencyP50 float64 `json:"latency_p50_ms"`
	LatencyP99 float64 `json:"latency_p99_ms"`
	Note       string  `json:"note"`
}

// ---------------------------------------------------------------------------
// Realistic test environment: rate-limited, latency-simulated mock GitHub
// ---------------------------------------------------------------------------

type realisticEnv struct {
	oidcKey      *rsa.PrivateKey
	oidcServer   *httptest.Server
	githubServer *httptest.Server

	// Per-app rate limit tracking (token creation is the bottleneck).
	rateLimitMu   sync.Mutex
	appTokenCount map[string]*atomic.Int64

	// Counters.
	installationCalls atomic.Int64
	tokenCalls        atomic.Int64
	rateLimitHits     atomic.Int64

	handler *handler.ExchangeHandler
	jtiC    *jti.InMemoryCache
	apps    []string
}

func newRealisticEnv(t *testing.T, apps []string, simulateLatency bool, rateLimitPerMin int) *realisticEnv {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	env := &realisticEnv{
		oidcKey:       key,
		appTokenCount: make(map[string]*atomic.Int64, len(apps)),
		apps:          apps,
	}
	for _, name := range apps {
		env.appTokenCount[name] = &atomic.Int64{}
	}

	// Track when the rate limit window started.
	var windowStart sync.Map // app → time.Time

	// --- Mock OIDC issuer ---
	env.oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   env.oidcServer.URL,
				"jwks_uri": env.oidcServer.URL + "/jwks",
			})
		case r.URL.Path == "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{{
					"kty": "RSA",
					"kid": "test-key-1",
					"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// Per-app rate limit counters: appID (from JWT iss claim) → counter.
	rateLimitCounters := &sync.Map{}       // appID → *atomic.Int64
	rateLimitWindowStart := &sync.Map{}    // appID → time.Time

	// --- Rate-limited mock GitHub API ---
	// Each app gets a unique installation ID (1000+i) so rate limits are per-app.
	env.githubServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate real GitHub API latency.
		if simulateLatency {
			jitter := time.Duration(fastRand()%uint32((githubAPILatencyMax-githubAPILatencyMin).Milliseconds())) * time.Millisecond
			time.Sleep(githubAPILatencyMin + jitter)
		}

		// Extract app ID from the JWT Authorization header for per-app rate limiting.
		appID := extractAppIDFromAuth(r)

		switch {
		case strings.Contains(r.URL.Path, "/orgs/") && strings.HasSuffix(r.URL.Path, "/installation"):
			env.installationCalls.Add(1)
			// Each app gets a unique installation ID based on its app_id.
			instID := int64(12345)
			if id, err := fmt.Sscanf(appID, "%d", &instID); id > 0 && err == nil {
				instID = instID + 90000 // offset to make unique
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": instID})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			env.tokenCalls.Add(1)

			// Per-app rate limiting keyed by the app ID from the JWT.
			if rateLimitPerMin > 0 && appID != "" {
				now := time.Now()
				startVal, _ := rateLimitWindowStart.LoadOrStore(appID, now)
				start := startVal.(time.Time)

				// Reset window every minute.
				if now.Sub(start) > time.Minute {
					rateLimitWindowStart.Store(appID, now)
					if c, ok := rateLimitCounters.Load(appID); ok {
						c.(*atomic.Int64).Store(0)
					}
				}

				counterVal, _ := rateLimitCounters.LoadOrStore(appID, &atomic.Int64{})
				counter := counterVal.(*atomic.Int64)

				count := counter.Add(1)
				if count > int64(rateLimitPerMin) {
					env.rateLimitHits.Add(1)
					w.Header().Set("Retry-After", "60")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
					return
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token": fmt.Sprintf("ghs_mock_%d", env.tokenCalls.Load()),
			})

		case strings.Contains(r.URL.Path, "/contents/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`issuer: %s
subject_pattern: "repo:testorg/testrepo:.*"
permissions:
  contents: read
`, env.oidcServer.URL)))

		default:
			http.NotFound(w, r)
		}
	}))

	// --- Build the handler ---
	env.jtiC = jti.NewInMemoryCache(1 * time.Hour)

	appProviders := make(map[string]*github.AppTokenProvider, len(apps))
	policyTPs := make(map[string]policy.TokenProvider, len(apps))
	for i, name := range apps {
		p := github.NewAppTokenProvider(name, int64(1000+i), key, env.githubServer.URL, nil)
		appProviders[name] = p
		policyTPs[name] = p
	}

	slogger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError}))

	policyLoader := policy.NewGitHubLoader(
		policyTPs, nil, env.githubServer.URL,
		".github/sts", 60*time.Second, slogger, nil,
	)

	env.handler = handler.NewExchangeHandler(
		env.jtiC, policyLoader, appProviders,
		[]string{env.oidcServer.URL},
		audit.NopLogger{}, slogger, false,
	)

	return env
}

func (e *realisticEnv) close() {
	e.oidcServer.Close()
	e.githubServer.Close()
	e.jtiC.Stop()
}

func (e *realisticEnv) signOIDCToken(t *testing.T, sub, jtiVal string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": e.oidcServer.URL,
		"sub": sub,
		"aud": "github-sts",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": jtiVal,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key-1"
	signed, err := tok.SignedString(e.oidcKey)
	if err != nil {
		t.Fatalf("signing OIDC token: %v", err)
	}
	return signed
}

func (e *realisticEnv) resetCounters() {
	e.installationCalls.Store(0)
	e.tokenCalls.Store(0)
	e.rateLimitHits.Store(0)
	for _, c := range e.appTokenCount {
		c.Store(0)
	}
}

// Simple fast PRNG for jitter (not crypto — just latency simulation).
var fastRandCounter atomic.Uint32

func fastRand() uint32 {
	return fastRandCounter.Add(7919) // prime increment
}

// ---------------------------------------------------------------------------
// Run a scenario against the realistic env
// ---------------------------------------------------------------------------

func runRealisticScenario(t *testing.T, env *realisticEnv, name string, concurrency int, duration time.Duration) ScenarioResult {
	t.Helper()
	env.resetCounters()

	var (
		total       atomic.Int64
		successes   atomic.Int64
		errors      atomic.Int64
		rateLimited atomic.Int64
		latencies   []time.Duration
		latenciesMu sync.Mutex
		jtiCounter  atomic.Int64
	)

	start := time.Now()
	deadline := start.Add(duration)
	numApps := len(env.apps)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// Each worker round-robins across apps.
			appIdx := workerID % numApps
			for time.Now().Before(deadline) {
				id := jtiCounter.Add(1)
				app := env.apps[appIdx]
				appIdx = (appIdx + 1) % numApps

				bearer := env.signOIDCToken(t,
					"repo:testorg/testrepo:ref:refs/heads/main",
					fmt.Sprintf("bench-%s-%d", name, id),
				)
				code, lat := doExchange(env.handler, bearer, "testorg/testrepo", "ci", app)
				total.Add(1)
				switch {
				case code == http.StatusOK:
					successes.Add(1)
				case code == http.StatusBadGateway:
					// Upstream rate limit hit.
					rateLimited.Add(1)
				default:
					errors.Add(1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, lat)
				latenciesMu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(start)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	result := ScenarioResult{
		Name:        name,
		Apps:        numApps,
		Requests:    total.Load(),
		Successes:   successes.Load(),
		Errors:      errors.Load(),
		RateLimited: rateLimited.Load(),
		Concurrency: concurrency,
		DurationSec: elapsed.Seconds(),
	}

	if result.Requests > 0 {
		result.ReqPerMin = float64(result.Successes) / elapsed.Seconds() * 60
		result.ReqPerHour = result.ReqPerMin * 60
		result.SuccessRate = float64(result.Successes) / float64(result.Requests) * 100
	}

	n := len(latencies)
	if n > 0 {
		result.LatencyP50 = float64(latencies[n*50/100].Microseconds()) / 1000
		result.LatencyP95 = float64(latencies[n*95/100].Microseconds()) / 1000
		result.LatencyP99 = float64(latencies[n*99/100].Microseconds()) / 1000
		result.LatencyMax = float64(latencies[n-1].Microseconds()) / 1000
	}

	return result
}

// ---------------------------------------------------------------------------
// Main benchmark test
// ---------------------------------------------------------------------------

func TestBenchmark_GenerateReport(t *testing.T) {
	report := BenchmarkReport{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		GoVersion:        "go1.26",
		RateLimitPerApp:  githubRateLimitPerHour,
		SimulatedLatency: fmt.Sprintf("%v-%v", githubAPILatencyMin, githubAPILatencyMax),
	}

	// ── Part 1: Internal ceiling (no rate limit, no latency) ──
	t.Log("=== Internal ceiling (no rate limit, no simulated latency) ===")
	{
		env := newTestEnv(t, []string{"default"})
		defer env.close()

		result := runBenchScenario(t, env, "internal-ceiling", 100, 5*time.Second)
		report.Internal = InternalCeiling{
			ReqPerMin:  result.ReqPerMin,
			LatencyP50: result.LatencyP50,
			LatencyP99: result.LatencyP99,
			Note:       "Mock backends with zero latency — the STS server's own processing ceiling",
		}
		t.Logf("  Internal ceiling: %.0f req/min, p50=%.1fms, p99=%.1fms",
			result.ReqPerMin, result.LatencyP50, result.LatencyP99)
	}

	// ── Part 2: Realistic with latency, no rate limit ──
	// Shows what throughput looks like with real-world GitHub API latency.
	t.Log("=== Realistic latency, no rate limit ===")
	{
		apps := []string{"app-1"}
		env := newRealisticEnv(t, apps, true, 0) // latency=yes, ratelimit=no
		defer env.close()

		result := runRealisticScenario(t, env, "latency-only-1app", 50, 10*time.Second)
		report.Scenarios = append(report.Scenarios, result)
		t.Logf("  1 app, latency only: %.0f req/min (%.0f/hr), p50=%.0fms, p99=%.0fms, %.1f%% success",
			result.ReqPerMin, result.ReqPerHour, result.LatencyP50, result.LatencyP99, result.SuccessRate)
	}

	// ── Part 3: Multi-app scaling with rate limits ──
	// This is the realistic scenario: GitHub rate limit enforced, latency simulated.
	t.Log("=== Multi-app scaling with rate limits (15K/hr per app) ===")

	appCounts := []int{1, 3, 5, 7, 10}
	for _, numApps := range appCounts {
		apps := make([]string, numApps)
		for i := range apps {
			apps[i] = fmt.Sprintf("app-%d", i+1)
		}

		env := newRealisticEnv(t, apps, true, githubRateLimitPerMin)
		result := runRealisticScenario(t, env, fmt.Sprintf("%d-apps", numApps), numApps*10, 15*time.Second)
		report.Scenarios = append(report.Scenarios, result)

		theoretical := float64(numApps * githubRateLimitPerHour)
		efficiency := float64(0)
		if theoretical > 0 {
			efficiency = result.ReqPerHour / theoretical * 100
		}
		if efficiency > 100 {
			efficiency = 100
		}

		report.Scaling = append(report.Scaling, ScalingResult{
			Apps:            numApps,
			TheoreticalMax:  theoretical,
			MeasuredPerMin:  result.ReqPerMin,
			MeasuredPerHour: result.ReqPerHour,
			Efficiency:      efficiency,
			SuccessRate:     result.SuccessRate,
			LatencyP99:      result.LatencyP99,
		})

		t.Logf("  %d apps: %.0f req/min (%.0f/hr), theoretical max %.0f/hr, efficiency %.0f%%, rate_limited=%d, success=%.1f%%",
			numApps, result.ReqPerMin, result.ReqPerHour, theoretical, efficiency,
			result.RateLimited, result.SuccessRate)

		env.close()
	}

	// ── Part 4: Capacity projections ──
	// Calculate how many apps needed for common targets.
	t.Log("=== Capacity projections ===")

	// Use measured efficiency from the 10-app scenario (most reliable).
	measuredEfficiency := float64(0.90) // conservative default
	for _, s := range report.Scaling {
		if s.Apps == 10 && s.Efficiency > 0 {
			measuredEfficiency = s.Efficiency / 100
		}
	}

	targets := []int{15_000, 50_000, 100_000, 250_000, 500_000}
	for _, target := range targets {
		// Each app provides: rate_limit * efficiency tokens/hr
		effectivePerApp := float64(githubRateLimitPerHour) * measuredEfficiency
		appsNeeded := int(float64(target)/effectivePerApp) + 1

		report.Projection = append(report.Projection, ProjectionResult{
			TargetPerHour:   target,
			AppsNeeded:      appsNeeded,
			EffectivePerMin: float64(target) / 60,
		})

		t.Logf("  %6dK/hr → %d apps needed (%.0f effective/app/hr at %.0f%% efficiency)",
			target/1000, appsNeeded, effectivePerApp, measuredEfficiency*100)
	}

	// ── Write report ──
	outPath := os.Getenv("BENCH_OUTPUT")
	if outPath == "" {
		outPath = "bench-results.json"
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshalling report: %v", err)
	}

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		t.Fatalf("writing report to %s: %v", outPath, err)
	}

	t.Logf("Report written to %s", outPath)
}

// runBenchScenario for the internal ceiling test (uses the original mock env).
func runBenchScenario(t *testing.T, env *testEnv, name string, concurrency int, duration time.Duration) ScenarioResult {
	t.Helper()
	env.installationCalls.Store(0)
	env.tokenCalls.Store(0)

	var (
		total       atomic.Int64
		successes   atomic.Int64
		latencies   []time.Duration
		latenciesMu sync.Mutex
		jtiCounter  atomic.Int64
	)

	start := time.Now()
	deadline := start.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				id := jtiCounter.Add(1)
				bearer := env.signOIDCToken(t,
					"repo:testorg/testrepo:ref:refs/heads/main",
					fmt.Sprintf("bench-%s-%d", name, id),
				)
				code, lat := doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
				total.Add(1)
				if code == http.StatusOK {
					successes.Add(1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, lat)
				latenciesMu.Unlock()
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	result := ScenarioResult{
		Name:        name,
		Apps:        1,
		Requests:    total.Load(),
		Successes:   successes.Load(),
		Concurrency: concurrency,
		DurationSec: elapsed.Seconds(),
	}
	if result.Requests > 0 {
		result.ReqPerMin = float64(result.Successes) / elapsed.Seconds() * 60
		result.ReqPerHour = result.ReqPerMin * 60
		result.SuccessRate = float64(result.Successes) / float64(result.Requests) * 100
	}
	n := len(latencies)
	if n > 0 {
		result.LatencyP50 = float64(latencies[n*50/100].Microseconds()) / 1000
		result.LatencyP95 = float64(latencies[n*95/100].Microseconds()) / 1000
		result.LatencyP99 = float64(latencies[n*99/100].Microseconds()) / 1000
		result.LatencyMax = float64(latencies[n-1].Microseconds()) / 1000
	}
	return result
}

// extractAppIDFromAuth extracts the app ID (iss claim) from the JWT in the
// Authorization header. Used by the mock to enforce per-app rate limits.
func extractAppIDFromAuth(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	// Quick and dirty: split JWT and decode the payload (base64url).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	// Add padding for base64url.
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var claims struct {
		ISS string `json:"iss"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.ISS
}
