//go:build e2e

// Package e2e contains end-to-end load tests for github-sts.
//
// These tests spin up the real server with mock GitHub and OIDC backends,
// then drive concurrent traffic to validate throughput, latency, cache
// efficiency, and correctness under load.
//
// Run with: go test -tags e2e -v -count=1 ./e2e/
package e2e

import (
	"bytes"
	"context"
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
)

// ---------------------------------------------------------------------------
// Test infrastructure: mock OIDC issuer + mock GitHub API
// ---------------------------------------------------------------------------

// testEnv holds all mock servers and keys needed for an e2e test run.
type testEnv struct {
	// RSA key pair used by both the mock OIDC issuer (public) and
	// for signing OIDC tokens in the test (private).
	oidcKey *rsa.PrivateKey

	// Mock servers.
	oidcServer   *httptest.Server // OIDC discovery + JWKS
	githubServer *httptest.Server // GitHub App API

	// Counters to track how many GitHub API calls were made.
	installationCalls atomic.Int64
	tokenCalls        atomic.Int64

	// The exchange handler wired to the mocks.
	handler *handler.ExchangeHandler
	jtiC    *jti.InMemoryCache
}

func newTestEnv(t *testing.T, apps []string) *testEnv {
	t.Helper()

	// Generate RSA key pair for OIDC signing.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	env := &testEnv{oidcKey: key}

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
				"keys": []map[string]string{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// --- Mock GitHub API ---
	env.githubServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/orgs/") && strings.HasSuffix(r.URL.Path, "/installation"):
			env.installationCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 12345})

		case strings.Contains(r.URL.Path, "/access_tokens"):
			env.tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token": fmt.Sprintf("ghs_mock_%d", env.tokenCalls.Load()),
			})

		case strings.Contains(r.URL.Path, "/contents/"):
			// Policy file response.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return a valid policy YAML that matches our test OIDC tokens.
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
		policyTPs,
		nil, // no org policy repos — all repo-level
		env.githubServer.URL,
		".github/sts",
		60*time.Second,
		slogger,
		nil,
	)

	env.handler = handler.NewExchangeHandler(
		env.jtiC,
		policyLoader,
		appProviders,
		[]string{env.oidcServer.URL},
		audit.NopLogger{},
		slogger,
		false,
	)

	return env
}

func (e *testEnv) close() {
	e.oidcServer.Close()
	e.githubServer.Close()
	e.jtiC.Stop()
}

// signOIDCToken creates a signed OIDC JWT that the mock issuer's JWKS will verify.
func (e *testEnv) signOIDCToken(t *testing.T, sub, jtiVal string) string {
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

// doExchange performs a single token exchange request and returns the status code and latency.
func doExchange(h http.Handler, bearer, scope, identity, app string) (int, time.Duration) {
	url := fmt.Sprintf("/sts/exchange?scope=%s&identity=%s", scope, identity)
	if app != "" {
		url += "&app=" + app
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	// Add trace ID context so the handler doesn't log warnings.
	ctx := context.WithValue(req.Context(), handler.TraceIDKey, "load-test")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(w, req)
	return w.Code, time.Since(start)
}

// ---------------------------------------------------------------------------
// Test: Sustained throughput
// ---------------------------------------------------------------------------

func TestLoad_SustainedThroughput(t *testing.T) {
	env := newTestEnv(t, []string{"default"})
	defer env.close()

	const (
		duration    = 10 * time.Second
		concurrency = 50
	)

	var (
		total      atomic.Int64
		successes  atomic.Int64
		errors     atomic.Int64
		latencies  []time.Duration
		latenciesMu sync.Mutex
		jtiCounter atomic.Int64
	)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				id := jtiCounter.Add(1)
				bearer := env.signOIDCToken(t, "repo:testorg/testrepo:ref:refs/heads/main", fmt.Sprintf("jti-%d", id))
				code, lat := doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
				total.Add(1)
				if code == http.StatusOK {
					successes.Add(1)
				} else {
					errors.Add(1)
				}
				latenciesMu.Lock()
				latencies = append(latencies, lat)
				latenciesMu.Unlock()
			}
		}()
	}

	wg.Wait()

	// --- Assertions ---
	totalReqs := total.Load()
	successReqs := successes.Load()
	errorReqs := errors.Load()
	reqPerMin := float64(totalReqs) / duration.Seconds() * 60

	t.Logf("Total requests:    %d", totalReqs)
	t.Logf("Successes:         %d", successReqs)
	t.Logf("Errors:            %d", errorReqs)
	t.Logf("Throughput:         %.0f req/min", reqPerMin)
	t.Logf("GitHub API calls:  install=%d token=%d", env.installationCalls.Load(), env.tokenCalls.Load())

	// Latency percentiles.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		p50 := latencies[len(latencies)*50/100]
		p95 := latencies[len(latencies)*95/100]
		p99 := latencies[len(latencies)*99/100]
		t.Logf("Latency p50=%v p95=%v p99=%v", p50, p95, p99)

		if p99 > 2*time.Second {
			t.Errorf("p99 latency %v exceeds 2s threshold", p99)
		}
	}

	// Must achieve at least 1000 req/min equivalent throughput.
	if reqPerMin < 1000 {
		t.Errorf("throughput %.0f req/min is below 1000 req/min target", reqPerMin)
	}

	// Success rate should be >95%.
	successRate := float64(successReqs) / float64(totalReqs) * 100
	if successRate < 95 {
		t.Errorf("success rate %.1f%% is below 95%% threshold", successRate)
	}

	// Installation ID should be fetched very few times (singleflight + caching).
	// With one org and 10s test, expect 1-2 fetches max.
	if env.installationCalls.Load() > 5 {
		t.Errorf("installation ID fetched %d times — singleflight/cache not working", env.installationCalls.Load())
	}
}

// ---------------------------------------------------------------------------
// Test: Burst handling (thundering herd)
// ---------------------------------------------------------------------------

func TestLoad_BurstHandling(t *testing.T) {
	env := newTestEnv(t, []string{"default"})
	defer env.close()

	const burstSize = 200

	var (
		successes   atomic.Int64
		latencies   []time.Duration
		latenciesMu sync.Mutex
	)

	// Fire all requests simultaneously.
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			bearer := env.signOIDCToken(t, "repo:testorg/testrepo:ref:refs/heads/main", fmt.Sprintf("burst-jti-%d", id))
			code, lat := doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
			if code == http.StatusOK {
				successes.Add(1)
			}
			latenciesMu.Lock()
			latencies = append(latencies, lat)
			latenciesMu.Unlock()
		}(i)
	}
	wg.Wait()
	burstDuration := time.Since(start)

	t.Logf("Burst: %d requests in %v", burstSize, burstDuration)
	t.Logf("Successes: %d/%d", successes.Load(), burstSize)
	t.Logf("GitHub API calls: install=%d token=%d", env.installationCalls.Load(), env.tokenCalls.Load())

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		p99 := latencies[len(latencies)*99/100]
		t.Logf("Latency p99=%v", p99)
	}

	// With singleflight, installation ID should be fetched very few times
	// despite 200 concurrent requests.
	if env.installationCalls.Load() > 5 {
		t.Errorf("installation ID fetched %d times during burst — singleflight not effective", env.installationCalls.Load())
	}

	// Success rate should be high.
	successRate := float64(successes.Load()) / float64(burstSize) * 100
	if successRate < 95 {
		t.Errorf("burst success rate %.1f%% is below 95%%", successRate)
	}
}

// ---------------------------------------------------------------------------
// Test: Multi-app isolation
// ---------------------------------------------------------------------------

func TestLoad_MultiAppIsolation(t *testing.T) {
	apps := []string{"app-alpha", "app-beta", "app-gamma"}
	env := newTestEnv(t, apps)
	defer env.close()

	const reqsPerApp = 100

	type appResult struct {
		app       string
		successes int64
		errors    int64
	}

	results := make([]appResult, len(apps))

	var wg sync.WaitGroup
	for ai, appName := range apps {
		wg.Add(1)
		go func(idx int, app string) {
			defer wg.Done()
			var s, e int64
			for i := 0; i < reqsPerApp; i++ {
				bearer := env.signOIDCToken(t,
					"repo:testorg/testrepo:ref:refs/heads/main",
					fmt.Sprintf("multi-%s-%d", app, i),
				)
				code, _ := doExchange(env.handler, bearer, "testorg/testrepo", "ci", app)
				if code == http.StatusOK {
					s++
				} else {
					e++
				}
			}
			results[idx] = appResult{app: app, successes: s, errors: e}
		}(ai, appName)
	}
	wg.Wait()

	for _, r := range results {
		t.Logf("App %s: successes=%d errors=%d", r.app, r.successes, r.errors)
		successRate := float64(r.successes) / float64(reqsPerApp) * 100
		if successRate < 95 {
			t.Errorf("app %s success rate %.1f%% is below 95%%", r.app, successRate)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: JTI replay detection under load
// ---------------------------------------------------------------------------

func TestLoad_JTIReplayUnderLoad(t *testing.T) {
	env := newTestEnv(t, []string{"default"})
	defer env.close()

	// Sign one token to be replayed.
	bearer := env.signOIDCToken(t, "repo:testorg/testrepo:ref:refs/heads/main", "replay-target")

	// First request should succeed.
	code, _ := doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
	if code != http.StatusOK {
		t.Fatalf("first request should succeed, got %d", code)
	}

	// Now replay the same token concurrently — all should be rejected.
	const replays = 100
	var rejected atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < replays; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
			if code == http.StatusConflict {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()

	t.Logf("Replay rejections: %d/%d", rejected.Load(), replays)
	if rejected.Load() != int64(replays) {
		t.Errorf("expected all %d replays rejected, got %d", replays, rejected.Load())
	}
}

// ---------------------------------------------------------------------------
// Test: Cache efficiency — GitHub API call count should plateau
// ---------------------------------------------------------------------------

func TestLoad_CacheEfficiency(t *testing.T) {
	env := newTestEnv(t, []string{"default"})
	defer env.close()

	const (
		warmupReqs = 10
		steadyReqs = 200
	)

	// Warm-up: populate caches.
	for i := 0; i < warmupReqs; i++ {
		bearer := env.signOIDCToken(t, "repo:testorg/testrepo:ref:refs/heads/main", fmt.Sprintf("warmup-%d", i))
		doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
	}

	// Record GitHub API call count after warm-up.
	installAfterWarmup := env.installationCalls.Load()
	// Note: token calls grow with every request (mandatory), but installation
	// and policy calls should not.

	// Steady-state traffic.
	for i := 0; i < steadyReqs; i++ {
		bearer := env.signOIDCToken(t, "repo:testorg/testrepo:ref:refs/heads/main", fmt.Sprintf("steady-%d", i))
		doExchange(env.handler, bearer, "testorg/testrepo", "ci", "")
	}

	installAfterSteady := env.installationCalls.Load()
	newInstallCalls := installAfterSteady - installAfterWarmup

	t.Logf("Installation calls: warmup=%d steady=%d (new=%d)", installAfterWarmup, installAfterSteady, newInstallCalls)
	t.Logf("Total token calls: %d (expected ~%d)", env.tokenCalls.Load(), warmupReqs+steadyReqs)

	// Installation calls should not grow during steady state (cache is warm).
	if newInstallCalls > 2 {
		t.Errorf("installation ID fetched %d times during steady state — cache not effective", newInstallCalls)
	}
}

// ---------------------------------------------------------------------------
// Test: Graceful degradation on upstream failure
// ---------------------------------------------------------------------------

func TestLoad_GracefulDegradation(t *testing.T) {
	// Custom GitHub mock that returns 503 for token creation.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	var oidcServer *httptest.Server
	oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   oidcServer.URL,
				"jwks_uri": oidcServer.URL + "/jwks",
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
	defer oidcServer.Close()

	githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/installation"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 99999})
		case strings.Contains(r.URL.Path, "/contents/"):
			_, _ = w.Write([]byte(fmt.Sprintf(`issuer: %s
subject_pattern: "repo:testorg/testrepo:.*"
permissions:
  contents: read
`, oidcServer.URL)))
		case strings.Contains(r.URL.Path, "/access_tokens"):
			// Simulate upstream failure.
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"service unavailable"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer githubServer.Close()

	jtiC := jti.NewInMemoryCache(1 * time.Hour)
	defer jtiC.Stop()

	slogger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError}))
	provider := github.NewAppTokenProvider("default", 1000, key, githubServer.URL, nil)
	policyLoader := policy.NewGitHubLoader(
		map[string]policy.TokenProvider{"default": provider},
		nil,
		githubServer.URL,
		".github/sts",
		60*time.Second,
		slogger,
		nil,
	)

	h := handler.NewExchangeHandler(
		jtiC,
		policyLoader,
		map[string]*github.AppTokenProvider{"default": provider},
		[]string{oidcServer.URL},
		audit.NopLogger{},
		slogger,
		false,
	)

	// Send requests — all should get 502, not 500 or panic.
	const reqs = 50
	var badGateway atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < reqs; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			claims := jwt.MapClaims{
				"iss": oidcServer.URL,
				"sub": "repo:testorg/testrepo:ref:refs/heads/main",
				"aud": "github-sts",
				"exp": now.Add(10 * time.Minute).Unix(),
				"iat": now.Unix(),
				"jti": fmt.Sprintf("degrade-%d", id),
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = "test-key-1"
			bearer, _ := tok.SignedString(key)
			code, _ := doExchange(h, bearer, "testorg/testrepo", "ci", "")
			if code == http.StatusBadGateway {
				badGateway.Add(1)
			}
		}(i)
	}
	wg.Wait()

	t.Logf("Bad gateway responses: %d/%d", badGateway.Load(), reqs)
	if badGateway.Load() != int64(reqs) {
		t.Errorf("expected all %d requests to return 502, got %d", reqs, badGateway.Load())
	}
}
