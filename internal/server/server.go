// Package server provides the HTTP server with middleware, routing, and
// lifecycle management for github-sts.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/handler"
	"github.com/depthmark/github-sts/internal/jti"
	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/depthmark/github-sts/internal/ratelimit"

	"github.com/redis/go-redis/v9"
)

const traceIDKey = handler.TraceIDKey

// Server is the main HTTP server orchestrator.
type Server struct {
	httpServer         *http.Server
	cfg                *config.Settings
	ready              atomic.Bool
	auditLogger        audit.Logger
	jtiCache           jti.Cache
	rateLimitPoller    *github.RateLimitPoller
	reachabilityProber *github.ReachabilityProber
	ipRateLimiter      *ratelimit.IPRateLimiter
	redisClient        *redis.Client
	slogger            *slog.Logger
}

// New creates a new Server with all services initialized.
func New(cfg *config.Settings, slogger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		slogger: slogger,
	}

	// Initialize JTI cache.
	switch cfg.JTI.Backend {
	case "redis":
		opts, err := redis.ParseURL(cfg.JTI.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("parsing redis url: %w", err)
		}
		s.redisClient = redis.NewClient(opts)
		s.jtiCache = jti.NewRedisCache(s.redisClient, cfg.JTI.TTL)
		slogger.Info("jti cache initialized", "backend", "redis")
	default:
		s.jtiCache = jti.NewInMemoryCache(cfg.JTI.TTL)
		slogger.Info("jti cache initialized", "backend", "memory")
		slogger.Warn("in-memory JTI cache does not survive restarts and is not shared across replicas; consider redis for production",
			"backend", "memory",
		)
	}

	// Initialize audit logger.
	var auditPath string
	if cfg.Audit.FileEnabled {
		auditPath = cfg.Audit.FilePath
	}
	auditSlogger := slogger.With("log_channel", "audit")
	al, err := audit.NewFileLogger(auditPath, cfg.Audit.BufferSize, auditSlogger)
	if err != nil {
		return nil, fmt.Errorf("creating audit logger: %w", err)
	}
	s.auditLogger = al

	// Initialize GitHub App token providers.
	appProviders := make(map[string]*github.AppTokenProvider, len(cfg.Apps))
	appConfigs := make(map[string]github.AppConfig, len(cfg.Apps))
	apiURL := "https://api.github.com"

	for name, app := range cfg.Apps {
		provider := github.NewAppTokenProvider(name, app.AppID, app.ParsedKey, apiURL, nil)
		appProviders[name] = provider
		appConfigs[name] = github.AppConfig{
			AppID:         app.AppID,
			PrivateKey:    app.ParsedKey,
			OrgPolicyRepo: app.OrgPolicyRepo,
		}
		slogger.Info("github app initialized", "app", name, "app_id", app.AppID)
	}

	// Initialize policy loader (uses the first app's token provider for API access).
	var policyTP policy.TokenProvider
	for _, provider := range appProviders {
		policyTP = provider
		break
	}
	policyLoader := policy.NewGitHubLoader(
		policyTP, apiURL,
		firstOrgPolicyRepo(cfg.Apps),
		cfg.Policy.BasePath,
		cfg.Policy.CacheTTL,
		slogger,
	)

	// Initialize rate limit poller.
	if cfg.Metrics.RateLimitPollEnabled && len(appConfigs) > 0 {
		s.rateLimitPoller = github.NewRateLimitPoller(appConfigs, apiURL, cfg.Metrics.RateLimitPollInterval)
	}

	// Initialize reachability prober.
	if cfg.Metrics.ReachabilityProbeEnabled && len(appConfigs) > 0 {
		s.reachabilityProber = github.NewReachabilityProber(appConfigs, apiURL, cfg.Metrics.ReachabilityProbeInterval)
	}

	// Initialize per-IP rate limiter.
	if cfg.RateLimit.Enabled {
		rl, err := ratelimit.New(cfg.RateLimit.Rate, cfg.RateLimit.Burst, cfg.RateLimit.ExemptCIDRs)
		if err != nil {
			return nil, fmt.Errorf("creating rate limiter: %w", err)
		}
		s.ipRateLimiter = rl
		slogger.Info("per-IP rate limiting enabled",
			"rate", cfg.RateLimit.Rate,
			"burst", cfg.RateLimit.Burst,
			"exempt_cidrs", cfg.RateLimit.ExemptCIDRs,
		)
	}

	// Register metrics.
	metrics.Register()

	// Create exchange handler.
	exchangeHandler := handler.NewExchangeHandler(
		s.jtiCache,
		policyLoader,
		appProviders,
		cfg.AllowedIssuers(),
		s.auditLogger,
		slogger,
		cfg.Server.TrustForwardedHeaders,
	)

	// Wrap exchange handler with rate limiting if enabled.
	var exchangeH http.Handler = exchangeHandler
	if s.ipRateLimiter != nil {
		exchangeH = rateLimitMiddleware(exchangeH, s.ipRateLimiter, cfg.Server.TrustForwardedHeaders)
	}

	// Register routes.
	mux := http.NewServeMux()
	mux.Handle("GET /sts/exchange", exchangeH)
	mux.Handle("POST /sts/exchange", exchangeH)
	mux.HandleFunc("GET /health", handler.HealthHandler())
	mux.HandleFunc("GET /ready", handler.ReadinessHandler(&s.ready))
	if cfg.Metrics.Enabled {
		mux.Handle("GET /metrics", handler.MetricsHandler(cfg.Metrics.AuthToken))
	}

	// Build middleware chain.
	var h http.Handler = mux
	h = metricsMiddleware(h)
	h = accessLogMiddleware(h, slogger, cfg.Server.SuppressHealthLogs)
	h = traceIDMiddleware(h)
	h = securityHeadersMiddleware(h)

	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s, nil
}

// ListenAndServe starts the server and blocks until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Start background services.
	if s.rateLimitPoller != nil {
		s.rateLimitPoller.Start()
		s.slogger.Info("rate limit poller started")
	}
	if s.reachabilityProber != nil {
		s.reachabilityProber.Start()
		s.slogger.Info("reachability prober started")
	}

	// Mark ready.
	s.ready.Store(true)
	metrics.Ready.Set(1)
	s.slogger.Info("server ready", "addr", s.httpServer.Addr)

	// Start HTTP server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		s.slogger.Info("shutdown signal received")
		return s.Shutdown()
	case err := <-errCh:
		return err
	}
}

// Shutdown performs ordered graceful shutdown.
func (s *Server) Shutdown() error {
	// Mark not ready.
	s.ready.Store(false)
	metrics.Ready.Set(0)

	// Shutdown HTTP server with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.slogger.Error("http server shutdown error", "error", err)
	}

	// Stop background services.
	if s.reachabilityProber != nil {
		s.reachabilityProber.Stop()
		s.slogger.Info("reachability prober stopped")
	}
	if s.rateLimitPoller != nil {
		s.rateLimitPoller.Stop()
		s.slogger.Info("rate limit poller stopped")
	}
	if s.ipRateLimiter != nil {
		s.ipRateLimiter.Stop()
	}

	// Close audit logger.
	if err := s.auditLogger.Close(); err != nil {
		s.slogger.Error("audit logger close error", "error", err)
	}

	// Close Redis client.
	if s.redisClient != nil {
		if err := s.redisClient.Close(); err != nil {
			s.slogger.Error("redis client close error", "error", err)
		}
	}

	s.slogger.Info("server shutdown complete")
	return nil
}

// securityHeadersMiddleware sets security headers on all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// traceIDMiddleware generates a unique trace ID for each request.
func traceIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := generateTraceID()
		ctx := context.WithValue(r.Context(), traceIDKey, id)
		w.Header().Set("X-Trace-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// accessLogMiddleware logs HTTP request/response details.
func accessLogMiddleware(next http.Handler, slogger *slog.Logger, suppressHealth bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		duration := time.Since(start).Milliseconds()

		traceID := "no-trace"
		if v, ok := r.Context().Value(traceIDKey).(string); ok {
			traceID = v
		}

		level := slog.LevelInfo
		if suppressHealth && isHealthPath(r.URL.Path) {
			level = slog.LevelDebug
		} else if sw.status >= 500 {
			level = slog.LevelError
		} else if sw.status >= 400 {
			level = slog.LevelWarn
		}

		slogger.Log(r.Context(), level, "access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", duration,
			"trace_id", traceID,
		)
	})
}

// metricsMiddleware records Prometheus HTTP metrics.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.InFlight.Inc()
		defer metrics.InFlight.Dec()

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)

		path := routePattern(r)
		status := strconv.Itoa(sw.status)

		metrics.RequestCount.WithLabelValues(r.Method, path, status).Inc()
		metrics.RequestLatency.WithLabelValues(r.Method, path).Observe(time.Since(start).Seconds())
	})
}

// rateLimitMiddleware wraps a handler with per-IP rate limiting.
func rateLimitMiddleware(next http.Handler, limiter *ratelimit.IPRateLimiter, trustForwarded bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r, trustForwarded)
		if !limiter.Allow(ip) {
			metrics.RateLimitRejections.Inc()
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractIP extracts the client IP for rate limiting, respecting the
// trust_forwarded_headers setting.
func extractIP(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.SplitN(fwd, ",", 2)
			return strings.TrimSpace(parts[0])
		}
	}
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.wroteHeader {
		sw.status = code
		sw.wroteHeader = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.wroteHeader = true
	}
	return sw.ResponseWriter.Write(b)
}

// generateTraceID generates a 16-character hex string.
func generateTraceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// isHealthPath returns true for paths that should be suppressed from access logs.
func isHealthPath(path string) bool {
	switch path {
	case "/health", "/ready", "/metrics", "/healthz", "/readyz":
		return true
	}
	return false
}

// routePattern returns a stable route pattern for metrics labels.
func routePattern(r *http.Request) string {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/sts/exchange"):
		return "/sts/exchange"
	case path == "/health":
		return "/health"
	case path == "/ready":
		return "/ready"
	case path == "/metrics":
		return "/metrics"
	default:
		return "other"
	}
}

// firstOrgPolicyRepo returns the org_policy_repo from the first app that has one.
func firstOrgPolicyRepo(apps map[string]config.AppConfig) string {
	for _, app := range apps {
		if app.OrgPolicyRepo != "" {
			return app.OrgPolicyRepo
		}
	}
	return ""
}
