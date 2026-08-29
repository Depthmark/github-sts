// Package server provides the HTTP server with middleware, routing, and
// lifecycle management for github-sts.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/depthmark/github-sts/internal/audit"
	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/handler"
	"github.com/depthmark/github-sts/internal/jti"
	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/depthmark/github-sts/internal/oidc"
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
	bundleManager      bundle.LifecycleManager // nil when bundle integration is disabled
	slogger            *slog.Logger
	certReloader       *certReloader
}

// New creates a new Server with all services initialized.
func New(cfg *config.Settings, slogger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		slogger: slogger,
	}

	// Install per-issuer JWKS host overrides for providers that publish their
	// JWKS on a different host than the issuer (e.g., Google). Default
	// behavior with no overrides is strict same-host pinning.
	oidc.SetTrustedJWKSHosts(cfg.OIDC.TrustedJWKSHosts)

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

	// Shared HTTP transport tuned for high-throughput GitHub API calls.
	// Default Go transport uses MaxIdleConnsPerHost=2, which causes
	// excessive TCP+TLS handshakes at scale. Most connections target
	// api.github.com, so a higher per-host pool avoids this bottleneck.
	githubTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	githubHTTPClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: githubTransport,
	}

	apiURL := "https://api.github.com"

	// Flatten every app's normalized instances into one list — shared by
	// the background pollers below, which sweep every physical instance of
	// every app regardless of pooling, the same way they always have.
	var poolInstances []github.PoolInstanceConfig
	for name, app := range cfg.Apps {
		for _, inst := range app.Instances {
			poolInstances = append(poolInstances, github.PoolInstanceConfig{
				LogicalApp: name,
				Instance:   inst.Name,
				AppConfig: github.AppConfig{
					AppID:         inst.AppID,
					PrivateKey:    inst.ParsedKey,
					OrgPolicyRepo: app.OrgPolicyRepo,
				},
			})
		}
	}

	// Initialize the reachability prober before the app pools below, which
	// take it as an optional dependency for their baseline liveness filter.
	if cfg.Metrics.ReachabilityProbeEnabled && len(poolInstances) > 0 {
		s.reachabilityProber = github.NewReachabilityProber(poolInstances, apiURL, cfg.Metrics.ReachabilityProbeInterval)
	}

	// Initialize rate limit poller.
	if cfg.Metrics.RateLimitPollEnabled && len(poolInstances) > 0 {
		s.rateLimitPoller = github.NewRateLimitPoller(poolInstances, apiURL, cfg.Metrics.RateLimitPollInterval)
	}

	// Initialize one AppPool per logical app, each wrapping every one of
	// its (normalized) instances. Every app goes through a pool, even a
	// single-instance one — that's what makes "pool of 1" behaviorally
	// identical to a direct AppTokenProvider (see github.AppPool doc).
	var reachability github.ReachabilityChecker
	if s.reachabilityProber != nil {
		// Assigned only when the concrete pointer is non-nil: passing a nil
		// *ReachabilityProber directly as a ReachabilityChecker would
		// produce a non-nil interface wrapping a nil pointer, defeating
		// AppPool's own nil check for "no checker configured".
		reachability = s.reachabilityProber
	}

	// pools is concrete (not an interface map) so the same *AppPool value
	// can populate both appProviders (github.ExchangeApp, for the exchange
	// handler's target-resolution/mint flow) and policyTPs (policy.TokenProvider,
	// for the policy-read mint) below without an invalid interface-to-interface
	// conversion — ExchangeApp and policy.TokenProvider don't share a method
	// set, so a variable statically typed as one can't assign into the other.
	pools := make(map[string]*github.AppPool, len(cfg.Apps))
	for name, app := range cfg.Apps {
		members := make([]github.PoolMember, 0, len(app.Instances))
		for _, inst := range app.Instances {
			provider := github.NewAppTokenProvider(name, inst.Name, inst.AppID, inst.ParsedKey, apiURL, githubHTTPClient)
			members = append(members, github.PoolMember{Instance: inst.Name, Provider: provider})
		}

		pools[name] = github.NewAppPool(name, members, app.Rotation.Strategy, app.Rotation.MinRemainingPct, app.Rotation.MaxAttempts, reachability)

		if app.Rotation.Strategy == "rate_limit_aware" {
			slogger.Warn("rotation.strategy=rate_limit_aware is configured but this build does not yet implement the proactive rate-limit-aware ranking — the pool behaves like round_robin until that ships",
				"app", name,
			)
		}
		slogger.Info("github app pool initialized", "app", name, "instances", len(members), "rotation_strategy", app.Rotation.Strategy)
	}

	for _, w := range cfg.DuplicateAppIDWarnings() {
		slogger.Warn(w)
	}

	appProviders := make(map[string]github.ExchangeApp, len(pools))
	for name, pool := range pools {
		appProviders[name] = pool
	}

	// Initialize policy loader with per-app token providers (the pools
	// above), org policy repos, and resolution modes.
	policyTPs := make(map[string]policy.TokenProvider, len(pools))
	orgPolicyRepos := make(map[string]string, len(cfg.Apps))
	policyModes := make(map[string]policy.Resolution, len(cfg.Apps))
	for name, pool := range pools {
		policyTPs[name] = pool
	}
	for name, app := range cfg.Apps {
		if app.OrgPolicyRepo != "" {
			orgPolicyRepos[name] = app.OrgPolicyRepo
		}
		if app.PolicyResolution != "" {
			policyModes[name] = app.PolicyResolution
		}
	}
	policyLoader := policy.NewGitHubLoader(
		policyTPs,
		orgPolicyRepos,
		policyModes,
		apiURL,
		cfg.Policy.BasePath,
		cfg.Policy.CacheTTL,
		slogger,
		githubHTTPClient,
	)

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
	if cfg.RequireImmutableSubjectClaims() {
		metrics.ImmutableSubjectClaimsRequired.Set(1)
	} else {
		metrics.ImmutableSubjectClaimsRequired.Set(0)
		slogger.Warn("immutable GitHub subject claims are not required",
			"setting", "oidc.require_immutable_subject_claims",
			"risk", "legacy subject format is vulnerable to repository namespace reuse",
		)
	}
	yamlOnlyAuthPossible := yamlOnlyAuthorizationPossible(cfg)
	if cfg.BundleEnforcement == config.BundleEnforcementRequired {
		metrics.BundleEnforcementRequired.Set(1)
	} else {
		metrics.BundleEnforcementRequired.Set(0)
		slogger.Warn("enterprise bundle enforcement is explicitly optional",
			"setting", "bundle_enforcement",
			"yaml_only_authorization_possible", yamlOnlyAuthPossible,
			"risk", "token exchange does not require enterprise policy participation",
		)
	}

	// Initialize bundle manager. When bundle.enabled=false the handler
	// receives the no-op Disabled manager and skips the engine call
	// entirely. When enabled, Init() pulls/verifies/compiles synchronously;
	// any failure here causes server creation to fail with a clear error
	// — silent degrade to YAML-only would mask a security misconfiguration.
	bundleMgr, liveBundleMgr, err := initBundleManager(cfg, slogger)
	if err != nil {
		return nil, fmt.Errorf("initializing bundle manager: %w", err)
	}
	s.bundleManager = liveBundleMgr

	// Create exchange handler.
	exchangeHandler := handler.NewExchangeHandler(
		s.jtiCache,
		policyLoader,
		appProviders,
		cfg.AllowedIssuers(),
		cfg.RequiredAudience(),
		cfg.RequireImmutableSubjectClaims(),
		s.auditLogger,
		slogger,
		cfg.Server.TrustForwardedHeaders,
		bundleMgr,
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
	// Trust-policy schema, served from the loaded bundle. 503 when
	// bundle integration is disabled; see SchemaHandler for codes.
	schemaHandler := handler.NewSchemaHandler(bundleMgr)
	mux.Handle("GET /sts/v1/trust-policy.json", schemaHandler)
	mux.Handle("HEAD /sts/v1/trust-policy.json", schemaHandler)
	mux.Handle("POST /sts/v1/trust-policy/validate", handler.NewPolicyValidationHandler())
	// /health includes bundle status when the integration is enabled.
	// liveBundleMgr is nil when bundle.enabled=false; HealthHandler
	// degrades gracefully in that case (just returns status: ok).
	var bundleReporter handler.BundleHealthReporter
	if liveBundleMgr != nil {
		bundleReporter = liveBundleMgr
	}
	healthHandler := handler.HealthHandler(bundleReporter, handler.SecurityPosture{
		RequireImmutableSubjectClaims: cfg.RequireImmutableSubjectClaims(),
		BundleEnforcement:             cfg.BundleEnforcement,
		YAMLOnlyAuthorizationPossible: yamlOnlyAuthPossible,
	})
	mux.Handle("GET /health", handler.OptionalBearerAuth(cfg.Health.AuthToken, "health", healthHandler))
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

	tlsCfg, reloader, err := buildTLSConfig(cfg, slogger)
	if err != nil {
		return nil, err
	}
	s.certReloader = reloader
	if reloader != nil && cfg.Server.TLS.ReloadInterval > 0 {
		slogger.Info("tls cert hot-reload enabled", "interval", cfg.Server.TLS.ReloadInterval)
	}

	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)),
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s, nil
}

func yamlOnlyAuthorizationPossible(cfg *config.Settings) bool {
	if cfg.BundleEnforcement == config.BundleEnforcementRequired {
		return false
	}
	for app := range cfg.Apps {
		covered := false
		for _, configuredBundle := range cfg.Bundles {
			if len(configuredBundle.Apps) == 0 || slices.Contains(configuredBundle.Apps, app) {
				covered = true
				break
			}
		}
		if !covered {
			return true
		}
	}
	return false
}

// buildTLSConfig loads TLS configuration and, when TLS is enabled, creates a
// certReloader that serves the certificate via GetCertificate. It returns nil
// for both outputs when native TLS is not configured.
func buildTLSConfig(cfg *config.Settings, slogger *slog.Logger) (*tls.Config, *certReloader, error) {
	if !cfg.Server.TLSEnabled() {
		return nil, nil, nil
	}

	reloader, err := newCertReloader(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.ReloadInterval,
		slogger,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("loading TLS key pair: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:     cfg.Server.TLSMinVersion(),
		GetCertificate: reloader.GetCertificate,
	}

	if ids := cfg.Server.TLSCipherSuiteIDs(); len(ids) > 0 {
		tlsCfg.CipherSuites = ids
	}

	if cfg.Server.ClientAuthEnabled() {
		caPEM, err := os.ReadFile(cfg.Server.TLS.ClientCAFile)
		if err != nil {
			reloader.Stop()
			return nil, nil, fmt.Errorf("reading client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			reloader.Stop()
			return nil, nil, fmt.Errorf("client CA file contains no valid certificates")
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = pool
	}

	return tlsCfg, reloader, nil
}

// certReloader holds a TLS certificate in memory and optionally refreshes it
// from disk on an interval, enabling zero-downtime certificate rotation.
type certReloader struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	certFile string
	keyFile  string
	stop     chan struct{}
}

func newCertReloader(certFile, keyFile string, interval time.Duration, slogger *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	if interval > 0 {
		r.stop = make(chan struct{})
		go r.watch(interval, slogger)
	}
	return r, nil
}

// GetCertificate implements tls.Config.GetCertificate and always returns the
// currently loaded certificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	return nil
}

func (r *certReloader) watch(interval time.Duration, slogger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastCertMod := modTime(r.certFile)
	lastKeyMod := modTime(r.keyFile)

	for {
		select {
		case <-ticker.C:
			certMod := modTime(r.certFile)
			keyMod := modTime(r.keyFile)
			if certMod.Equal(lastCertMod) && keyMod.Equal(lastKeyMod) {
				continue
			}
			if err := r.load(); err != nil {
				slogger.Error("tls cert reload failed", "error", err)
				continue
			}
			lastCertMod, lastKeyMod = certMod, keyMod
			slogger.Info("tls cert reloaded")
		case <-r.stop:
			return
		}
	}
}

// Stop halts the background reload goroutine, if one was started.
func (r *certReloader) Stop() {
	if r.stop != nil {
		close(r.stop)
	}
}

// modTime returns the modification time of path, or zero if stat fails.
func modTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
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
	if s.bundleManager != nil {
		// Use background context so the poll loop keeps running even if
		// ListenAndServe's ctx is cancelled on shutdown — Stop() below
		// is the authoritative drain.
		s.bundleManager.Start(context.Background())
	}

	// Mark ready.
	s.ready.Store(true)
	metrics.Ready.Set(1)
	s.slogger.Info("server ready", "addr", s.httpServer.Addr, "tls", s.httpServer.TLSConfig != nil)

	// Start HTTP server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.httpServer.TLSConfig != nil {
			// Certificates are pre-loaded in TLSConfig, so the file paths are
			// intentionally empty here.
			err = s.httpServer.ListenAndServeTLS("", "")
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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

// ReloadBundle triggers an on-demand bundle reload. Used by the SIGHUP
// handler. No-op (returns nil) when bundle integration is disabled,
// rather than an error, so SIGHUP behaviour is consistent regardless
// of config — operators get a single signal they can wire into any ops
// runbook.
func (s *Server) ReloadBundle(ctx context.Context) error {
	if s.bundleManager == nil {
		return nil
	}
	_, err := s.bundleManager.Reload(ctx)
	return err
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
	if s.bundleManager != nil {
		s.bundleManager.Stop()
	}
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

	// Stop cert reloader.
	if s.certReloader != nil {
		s.certReloader.Stop()
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

// initBundleManager constructs and initializes a bundle.Manager based on
// configuration. Returns bundle.Disabled{} when bundle integration is
// off; otherwise constructs a LiveManager and runs Init synchronously
// — a failed Init returns a non-nil error and the server fails to come
// up. This is intentional: a misconfigured bundle is a security
// configuration error, not something to silently degrade through.
//
// The returned *LiveManager (if any) is wrapped as bundle.Manager for
// dependency injection but exposed separately so server lifecycle code
// can call Start/Stop/Reload on it.
func initBundleManager(cfg *config.Settings, slogger *slog.Logger) (bundle.Manager, bundle.LifecycleManager, error) {
	bundles := cfg.EffectiveBundles()
	if len(bundles) == 0 {
		slogger.Info("bundle integration disabled")
		return bundle.Disabled{}, nil, nil
	}
	children := make([]bundle.LifecycleManager, 0, len(bundles))
	for _, bc := range bundles {
		src := bundle.Source{Raw: bc.Ref}
		loader, err := bundle.NewLoader(src)
		if err != nil {
			return nil, nil, fmt.Errorf("constructing bundle loader for %q: %w", bc.Ref, err)
		}
		verify := bundle.VerifyConfig{
			CertificateIdentityRegexp: bc.Cosign.CertificateIdentityRegexp,
			CertificateOIDCIssuer:     bc.Cosign.CertificateOIDCIssuer,
			PublicKeyRef:              bc.Cosign.PublicKeyRef,
			SkipVerification:          bc.Cosign.SkipVerification,
			RegistryAuth: bundle.RegistryAuthConfig{
				Mode:         bc.Registry.Auth.Mode,
				Username:     bc.Registry.Auth.Username,
				PasswordFile: bc.Registry.Auth.PasswordFile,
				PasswordEnv:  bc.Registry.Auth.PasswordEnv,
			},
		}
		mgr := bundle.NewLiveManager(loader, src, verify, slogger.With("bundle", bc.Name), bundle.LiveOpts{
			Name:                   bc.Name,
			Apps:                   bc.Apps,
			Mandatory:              cfg.BundleEnforcement == config.BundleEnforcementRequired && len(bc.Apps) == 0,
			ExpectedPolicyRevision: bc.ExpectedPolicyRevision,
			PollInterval:           bc.PollInterval,
			MaxStaleness:           bc.MaxStaleness,
			FailMode:               bc.FailMode,
		})
		initCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := mgr.Init(initCtx); err != nil {
			cancel()
			return nil, nil, err
		}
		cancel()
		children = append(children, mgr)
		slogger.Info("bundle integration enabled",
			"bundle", bc.Name,
			"source", bc.Ref,
			"apps", bc.Apps,
			"digest", mgr.Digest(),
			"poll_interval", bc.PollInterval,
			"max_staleness", bc.MaxStaleness,
			"fail_mode", bc.FailMode,
		)
	}
	mgr := bundle.NewMultiManager(children, cfg.BundleEnforcement)
	return mgr, mgr, nil
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
			if r.URL.Path == "/health" && sw.status == http.StatusUnauthorized {
				level = slog.LevelWarn
			}
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
	case path == "/sts/v1/trust-policy.json":
		return "/sts/v1/trust-policy.json"
	case path == "/sts/v1/trust-policy/validate":
		return "/sts/v1/trust-policy/validate"
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
