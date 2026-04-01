// Package config loads and validates application configuration from YAML files
// and environment variable overrides.
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Settings is the top-level configuration struct.
type Settings struct {
	Server    ServerConfig         `yaml:"server"`
	Apps      map[string]AppConfig `yaml:"apps"`
	OIDC      OIDCConfig           `yaml:"oidc"`
	JTI       JTIConfig            `yaml:"jti"`
	Policy    PolicyConfig         `yaml:"policy"`
	Audit     AuditConfig          `yaml:"audit"`
	Metrics   MetricsConfig        `yaml:"metrics"`
	RateLimit RateLimitConfig      `yaml:"rate_limit"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host                  string        `yaml:"host"`
	Port                  int           `yaml:"port"`
	LogLevel              string        `yaml:"log_level"`
	SuppressHealthLogs    bool          `yaml:"suppress_health_logs"`
	ShutdownTimeout       time.Duration `yaml:"shutdown_timeout"`
	TrustForwardedHeaders bool          `yaml:"trust_forwarded_headers"`
}

// AppConfig holds per-application GitHub App settings.
type AppConfig struct {
	AppID          int64  `yaml:"app_id"`
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyPath string `yaml:"private_key_path"`
	OrgPolicyRepo  string `yaml:"org_policy_repo"`

	// ParsedKey is the RSA private key parsed from PrivateKey or PrivateKeyPath.
	// Not serialized — populated during Load().
	ParsedKey *rsa.PrivateKey `yaml:"-"`
}

// OIDCConfig holds OIDC validation settings.
type OIDCConfig struct {
	AllowedIssuers []string `yaml:"allowed_issuers"`
}

// JTIConfig holds JTI replay prevention settings.
type JTIConfig struct {
	Backend  string        `yaml:"backend"`
	RedisURL string        `yaml:"redis_url"`
	TTL      time.Duration `yaml:"ttl"`
}

// PolicyConfig holds trust policy loader settings.
type PolicyConfig struct {
	BasePath string        `yaml:"base_path"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// AuditConfig holds audit logging settings.
type AuditConfig struct {
	FileEnabled bool   `yaml:"file_enabled"`
	FilePath    string `yaml:"file_path"`
	BufferSize  int    `yaml:"buffer_size"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled                   bool          `yaml:"enabled"`
	AuthToken                 string        `yaml:"auth_token"`
	RateLimitPollEnabled      bool          `yaml:"rate_limit_poll_enabled"`
	RateLimitPollInterval     time.Duration `yaml:"rate_limit_poll_interval"`
	ReachabilityProbeEnabled  bool          `yaml:"reachability_probe_enabled"`
	ReachabilityProbeInterval time.Duration `yaml:"reachability_probe_interval"`
}

// RateLimitConfig holds per-IP rate limiting settings.
type RateLimitConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Rate        float64  `yaml:"rate"`
	Burst       int      `yaml:"burst"`
	ExemptCIDRs []string `yaml:"exempt_cidrs"`
}

// defaults returns a Settings with default values applied.
func defaults() *Settings {
	return &Settings{
		Server: ServerConfig{
			Host:               "0.0.0.0",
			Port:               8080,
			LogLevel:           "info",
			SuppressHealthLogs: true,
			ShutdownTimeout:    10 * time.Second,
		},
		Apps: make(map[string]AppConfig),
		OIDC: OIDCConfig{
			AllowedIssuers: nil,
		},
		JTI: JTIConfig{
			Backend: "memory",
			TTL:     1 * time.Hour,
		},
		Policy: PolicyConfig{
			BasePath: ".github/sts",
			CacheTTL: 60 * time.Second,
		},
		Audit: AuditConfig{
			FileEnabled: true,
			FilePath:    "/var/log/github-sts/audit.json",
			BufferSize:  1024,
		},
		Metrics: MetricsConfig{
			Enabled:                   true,
			RateLimitPollEnabled:      true,
			RateLimitPollInterval:     60 * time.Second,
			ReachabilityProbeEnabled:  true,
			ReachabilityProbeInterval: 30 * time.Second,
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			Rate:    10,
			Burst:   20,
		},
	}
}

// Load reads configuration from a YAML file and applies environment variable
// overrides. If path is empty, only defaults and env vars are used.
func Load(path string) (*Settings, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	if err := cfg.parsePrivateKeys(); err != nil {
		return nil, fmt.Errorf("parsing private keys: %w", err)
	}

	return cfg, nil
}

// Validate checks configuration for required fields and consistency.
func (s *Settings) Validate() error {
	if len(s.Apps) == 0 {
		return fmt.Errorf("at least one app must be configured")
	}

	for name, app := range s.Apps {
		if app.AppID == 0 {
			return fmt.Errorf("app %q: app_id is required", name)
		}
		hasInline := app.PrivateKey != ""
		hasPath := app.PrivateKeyPath != ""
		if !hasInline && !hasPath {
			return fmt.Errorf("app %q: private_key or private_key_path is required", name)
		}
		if hasInline && hasPath {
			return fmt.Errorf("app %q: private_key and private_key_path are mutually exclusive", name)
		}
	}

	if s.JTI.Backend == "redis" && s.RedisURL() == "" {
		return fmt.Errorf("jti.redis_url is required when backend is redis")
	}

	if s.Server.Port < 1 || s.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}

	level := strings.ToLower(s.Server.LogLevel)
	switch level {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("server.log_level must be debug, info, warn, or error")
	}

	if len(s.OIDC.AllowedIssuers) == 0 {
		return fmt.Errorf("oidc.allowed_issuers must contain at least one issuer")
	}

	if s.RateLimit.Enabled {
		if s.RateLimit.Rate <= 0 {
			return fmt.Errorf("rate_limit.rate must be positive when rate limiting is enabled")
		}
		if s.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be positive when rate limiting is enabled")
		}
		for _, cidr := range s.RateLimit.ExemptCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("rate_limit.exempt_cidrs: invalid CIDR %q: %w", cidr, err)
			}
		}
	}

	return nil
}

// RedisURL returns the JTI Redis URL.
func (s *Settings) RedisURL() string {
	return s.JTI.RedisURL
}

// DefaultAppName returns the name of the single configured app, or empty if
// multiple apps are configured.
func (s *Settings) DefaultAppName() string {
	if len(s.Apps) == 1 {
		for name := range s.Apps {
			return name
		}
	}
	return ""
}

// AppNames returns all configured app names.
func (s *Settings) AppNames() []string {
	names := make([]string, 0, len(s.Apps))
	for name := range s.Apps {
		names = append(names, name)
	}
	return names
}

// AllowedIssuers returns the OIDC allowed issuers list.
func (s *Settings) AllowedIssuers() []string {
	return s.OIDC.AllowedIssuers
}

// GetApp returns the AppConfig for the given name.
func (s *Settings) GetApp(name string) (AppConfig, bool) {
	app, ok := s.Apps[name]
	return app, ok
}

// parsePrivateKeys parses PEM-encoded private keys for all apps.
func (s *Settings) parsePrivateKeys() error {
	for name, app := range s.Apps {
		var pemData []byte
		if app.PrivateKey != "" {
			pemData = []byte(app.PrivateKey)
		} else {
			data, err := os.ReadFile(app.PrivateKeyPath)
			if err != nil {
				return fmt.Errorf("app %q: reading private key file: %w", name, err)
			}
			pemData = data
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			return fmt.Errorf("app %q: invalid PEM data", name)
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 as fallback.
			parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return fmt.Errorf("app %q: parsing private key: %w", name, err)
			}
			rsaKey, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("app %q: private key is not RSA", name)
			}
			key = rsaKey
		}

		app.ParsedKey = key
		s.Apps[name] = app
	}
	return nil
}

// applyEnvOverrides applies GITHUBSTS_* environment variable overrides.
func applyEnvOverrides(cfg *Settings) {
	// Server
	if v := os.Getenv("GITHUBSTS_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
		}
	}
	if v := os.Getenv("GITHUBSTS_SERVER_LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_SUPPRESS_HEALTH_LOGS"); v != "" {
		cfg.Server.SuppressHealthLogs = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_SERVER_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.ShutdownTimeout = d
		}
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TRUST_FORWARDED_HEADERS"); v != "" {
		cfg.Server.TrustForwardedHeaders = parseBool(v)
	}

	// OIDC
	if v := os.Getenv("GITHUBSTS_OIDC_ALLOWED_ISSUERS"); v != "" {
		issuers := parseCommaSeparated(v)
		if len(issuers) > 0 {
			cfg.OIDC.AllowedIssuers = issuers
		}
	}

	// JTI
	if v := os.Getenv("GITHUBSTS_JTI_BACKEND"); v != "" {
		cfg.JTI.Backend = v
	}
	if v := os.Getenv("GITHUBSTS_JTI_REDIS_URL"); v != "" {
		cfg.JTI.RedisURL = v
	}
	if v := os.Getenv("GITHUBSTS_JTI_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.JTI.TTL = d
		}
	}

	// Policy
	if v := os.Getenv("GITHUBSTS_POLICY_BASE_PATH"); v != "" {
		cfg.Policy.BasePath = v
	}
	if v := os.Getenv("GITHUBSTS_POLICY_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Policy.CacheTTL = d
		}
	}

	// Audit
	if v := os.Getenv("GITHUBSTS_AUDIT_FILE_ENABLED"); v != "" {
		cfg.Audit.FileEnabled = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_AUDIT_FILE_PATH"); v != "" {
		cfg.Audit.FilePath = v
	}
	if v := os.Getenv("GITHUBSTS_AUDIT_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Audit.BufferSize = n
		}
	}

	// Metrics
	if v := os.Getenv("GITHUBSTS_METRICS_AUTH_TOKEN"); v != "" {
		cfg.Metrics.AuthToken = v
	}
	if v := os.Getenv("GITHUBSTS_METRICS_ENABLED"); v != "" {
		cfg.Metrics.Enabled = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_METRICS_RATE_LIMIT_POLL_ENABLED"); v != "" {
		cfg.Metrics.RateLimitPollEnabled = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_METRICS_RATE_LIMIT_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Metrics.RateLimitPollInterval = d
		}
	}
	if v := os.Getenv("GITHUBSTS_METRICS_REACHABILITY_PROBE_ENABLED"); v != "" {
		cfg.Metrics.ReachabilityProbeEnabled = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_METRICS_REACHABILITY_PROBE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Metrics.ReachabilityProbeInterval = d
		}
	}

	// Rate limit
	if v := os.Getenv("GITHUBSTS_RATE_LIMIT_ENABLED"); v != "" {
		cfg.RateLimit.Enabled = parseBool(v)
	}
	if v := os.Getenv("GITHUBSTS_RATE_LIMIT_RATE"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.RateLimit.Rate = n
		}
	}
	if v := os.Getenv("GITHUBSTS_RATE_LIMIT_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.Burst = n
		}
	}
	if v := os.Getenv("GITHUBSTS_RATE_LIMIT_EXEMPT_CIDRS"); v != "" {
		cidrs := parseCommaSeparated(v)
		if len(cidrs) > 0 {
			cfg.RateLimit.ExemptCIDRs = cidrs
		}
	}

	// Per-app env vars
	for name, app := range cfg.Apps {
		upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_APP_ID"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				app.AppID = n
			}
		}
		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_PRIVATE_KEY"); v != "" {
			app.PrivateKey = v
		}
		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_PRIVATE_KEY_PATH"); v != "" {
			app.PrivateKeyPath = v
		}
		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_ORG_POLICY_REPO"); v != "" {
			app.OrgPolicyRepo = v
		}
		cfg.Apps[name] = app
	}
}

// parseCommaSeparated splits a comma-separated string, trims whitespace, and
// discards empty entries.
func parseCommaSeparated(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseBool parses common boolean strings.
func parseBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
