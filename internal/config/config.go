// Package config loads and validates application configuration from YAML files
// and environment variable overrides.
package config

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/policy"
	"github.com/depthmark/github-sts/internal/yamlstrict"
	"gopkg.in/yaml.v3"
)

// instanceNamePattern restricts an instance's optional name to the same safe
// character set as handler.safeFieldPattern (internal/handler/exchange.go),
// since instance names become Prometheus label values. Duplicated here
// rather than importing internal/handler from internal/config, which would
// be an unusual upward layering dependency for one regex literal.
var instanceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._/\-]+$`)

// Settings is the top-level configuration struct.
type Settings struct {
	Server            ServerConfig         `yaml:"server"`
	Apps              map[string]AppConfig `yaml:"apps"`
	OIDC              OIDCConfig           `yaml:"oidc"`
	JTI               JTIConfig            `yaml:"jti"`
	Policy            PolicyConfig         `yaml:"policy"`
	BundleEnforcement string               `yaml:"bundle_enforcement"`
	Bundles           []BundleConfig       `yaml:"bundles"`
	Audit             AuditConfig          `yaml:"audit"`
	Metrics           MetricsConfig        `yaml:"metrics"`
	RateLimit         RateLimitConfig      `yaml:"rate_limit"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host                  string        `yaml:"host"`
	Port                  int           `yaml:"port"`
	LogLevel              string        `yaml:"log_level"`
	SuppressHealthLogs    bool          `yaml:"suppress_health_logs"`
	ShutdownTimeout       time.Duration `yaml:"shutdown_timeout"`
	TrustForwardedHeaders bool          `yaml:"trust_forwarded_headers"`
	TLS                   TLSConfig     `yaml:"tls"`
}

// TLSConfig holds native TLS/mTLS settings for the HTTP server. TLS is enabled
// implicitly when CertFile and KeyFile are both set. Client certificate
// verification (mTLS) is enabled when ClientCAFile is set.
type TLSConfig struct {
	CertFile       string        `yaml:"cert_file"`
	KeyFile        string        `yaml:"key_file"`
	ClientCAFile   string        `yaml:"client_ca_file"`
	MinVersion     string        `yaml:"min_version"`     // "1.2" (default) | "1.3"
	CipherSuites   []string      `yaml:"cipher_suites"`   // TLS 1.2 only; empty = Go defaults
	ReloadInterval time.Duration `yaml:"reload_interval"` // 0 = disabled
}

// tlsCipherSuiteNames maps IANA cipher suite names to their TLS IDs.
// Built from tls.CipherSuites() — only non-insecure suites are included.
var tlsCipherSuiteNames = func() map[string]uint16 {
	m := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		m[cs.Name] = cs.ID
	}
	return m
}()

// TLSEnabled reports whether native TLS is configured (certificate and key).
func (s *ServerConfig) TLSEnabled() bool {
	return s.TLS.CertFile != "" && s.TLS.KeyFile != ""
}

// ClientAuthEnabled reports whether client certificate verification (mTLS) is
// configured via a trusted client CA.
func (s *ServerConfig) ClientAuthEnabled() bool {
	return s.TLS.ClientCAFile != ""
}

// TLSMinVersion returns the numeric TLS version constant for the configured
// min_version. Defaults to TLS 1.2 when unset.
func (s *ServerConfig) TLSMinVersion() uint16 {
	if s.TLS.MinVersion == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// TLSCipherSuiteIDs returns the numeric cipher suite IDs for the configured
// names. Returns nil when no suites are configured (Go selects defaults).
func (s *ServerConfig) TLSCipherSuiteIDs() []uint16 {
	if len(s.TLS.CipherSuites) == 0 {
		return nil
	}
	ids := make([]uint16, len(s.TLS.CipherSuites))
	for i, name := range s.TLS.CipherSuites {
		ids[i] = tlsCipherSuiteNames[name]
	}
	return ids
}

// AppConfig holds per-application GitHub App settings. An app is backed by
// either the legacy flat fields (AppID/PrivateKey(Path)) or a pool of
// physical instances (Instances) — Validate rejects configs setting both or
// neither. Load normalizes the flat form into a single-element Instances
// pool, so every consumer downstream of Load only ever sees the Instances
// shape; see (*Settings).normalizeInstances.
type AppConfig struct {
	// Legacy flat fields. Mutually exclusive with Instances.
	AppID          int64  `yaml:"app_id"`
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyPath string `yaml:"private_key_path"`

	// Instances backs this logical app with a pool of N physical GitHub
	// Apps so github-sts can spread /sts/exchange traffic across
	// independent rate-limit buckets. Populated directly from YAML, or
	// synthesized by Load from the legacy flat fields above.
	Instances []AppInstanceConfig `yaml:"instances"`

	// Rotation controls how AppPool selects among Instances. Only
	// meaningful when Instances is set — Validate rejects it on a
	// flat-form app.
	Rotation RotationConfig `yaml:"rotation"`

	OrgPolicyRepo string `yaml:"org_policy_repo"`

	// PolicyResolution selects how the policy loader resolves an identity
	// when both the requesting repo and the org policy repo could host it.
	// Valid: "org_first" (default when org_policy_repo is set), "repo_first"
	// (legacy; repo overrides org on collision), "org_only" (org repo only,
	// no repo-local fallback). Ignored when org_policy_repo is unset.
	PolicyResolution policy.Resolution `yaml:"policy_resolution"`
}

// AppInstanceConfig holds one physical GitHub App backing a pooled logical
// app (AppConfig.Instances). Each instance has its own app_id and private
// key, and therefore its own independent GitHub rate-limit bucket.
type AppInstanceConfig struct {
	// Name labels this instance in metrics and audit events. Optional —
	// defaults to AppID (stringified) when omitted.
	Name           string `yaml:"name"`
	AppID          int64  `yaml:"app_id"`
	PrivateKey     string `yaml:"private_key"`
	PrivateKeyPath string `yaml:"private_key_path"`

	// ParsedKey is the RSA private key parsed from PrivateKey or
	// PrivateKeyPath. Not serialized — populated during Load().
	ParsedKey *rsa.PrivateKey `yaml:"-"`
}

// RotationConfig controls how AppPool selects among a logical app's pooled
// instances. Only meaningful when AppConfig.Instances is set.
type RotationConfig struct {
	// Strategy selects the instance-selection algorithm: "round_robin"
	// (default) or "rate_limit_aware" (opt-in).
	Strategy string `yaml:"strategy"`

	// MinRemainingPct applies only to the rate_limit_aware strategy: skip a
	// candidate instance whose last-observed remaining/limit percentage is
	// below this value. Ignored by round_robin.
	MinRemainingPct float64 `yaml:"min_remaining_pct"`

	// MaxAttempts bounds failover fan-out per request. Defaults to
	// min(len(Instances), 3).
	MaxAttempts int `yaml:"max_attempts"`
}

// OIDCConfig holds OIDC validation settings.
type OIDCConfig struct {
	AllowedIssuers []string `yaml:"allowed_issuers"`

	// RequireImmutableSubjectClaims requires GitHub.com Actions subjects to
	// include immutable owner and repository IDs. Separate signed ID claims are
	// still required when this legacy-format escape hatch is false.
	RequireImmutableSubjectClaims bool `yaml:"require_immutable_subject_claims"`

	// TrustedJWKSHosts pins additional `jwks_uri` hosts per issuer for
	// providers that publish JWKS on a different host than the issuer
	// (e.g., Google: accounts.google.com → www.googleapis.com). Default
	// behavior is same-host pinning; this map is the escape hatch.
	TrustedJWKSHosts map[string][]string `yaml:"trusted_jwks_hosts"`

	// RequiredAudience, when set, is enforced on every exchange before
	// per-policy audience checks. Defense-in-depth against a permissive or
	// misconfigured policy file leaking cross-RP token acceptance.
	RequiredAudience string `yaml:"required_audience"`
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

// BundleConfig holds one OPA bundle setting for the org-rego guardrail layer.
// The broker loads every configured bundle, discovers every package exposing a
// decision document, and consults them on each token exchange between the YAML
// policy match and the GitHub API mint. A deny returns 403 org_policy_denied;
// the YAML policy and all bundle decisions must allow.
//
// OCI bundle refs require cosign verification settings unless explicitly
// configured to skip verification. PollInterval, MaxStaleness, and FailMode
// control reload and stale-bundle behavior. The
// defaults are conservative: a 5 minute poll, a 10 minute staleness ceiling,
// and fail-closed when stale.
type BundleConfig struct {
	Name                   string         `yaml:"name"`
	Ref                    string         `yaml:"ref"`
	Apps                   []string       `yaml:"apps"`
	ExpectedPolicyRevision string         `yaml:"expected_policy_revision"`
	AllowMutableRef        bool           `yaml:"allow_mutable_ref"`
	Cosign                 CosignConfig   `yaml:"cosign"`
	Registry               RegistryConfig `yaml:"registry"`
	PollInterval           time.Duration  `yaml:"poll_interval"`
	MaxStaleness           time.Duration  `yaml:"max_staleness"`
	FailMode               string         `yaml:"fail_mode"`
}

// Bundle enforcement modes.
const (
	BundleEnforcementRequired = "required"
	BundleEnforcementOptional = "optional"
)

// Bundle fail mode constants. closed is the secure default — when the
// bundle exceeds MaxStaleness, eval refuses with bundle_stale. open is
// the availability-first option — eval proceeds with a stale bundle but
// emits a warning + metric per request so operators see the drift.
const (
	BundleFailModeClosed = "closed"
	BundleFailModeOpen   = "open"
)

// CosignConfig holds cosign verification parameters. OCI bundle refs require
// either keyless certificate identity/issuer fields or PublicKeyRef, unless
// SkipVerification is explicitly enabled for local/private-registry use.
type CosignConfig struct {
	CertificateIdentityRegexp string `yaml:"certificate_identity_regexp"`
	CertificateOIDCIssuer     string `yaml:"certificate_oidc_issuer"`
	PublicKeyRef              string `yaml:"public_key_ref"`
	SkipVerification          bool   `yaml:"skip_verification"`
}

// RegistryConfig holds optional OCI registry authentication settings.
type RegistryConfig struct {
	Auth RegistryAuthConfig `yaml:"auth"`
}

// RegistryAuthConfig currently supports basic auth only. Password material must
// be referenced through a file or environment variable, never inline config.
type RegistryAuthConfig struct {
	Mode         string `yaml:"mode"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	PasswordEnv  string `yaml:"password_env"`
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
			AllowedIssuers:                nil,
			RequireImmutableSubjectClaims: true,
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
		if hasTopLevelYAMLKey(data, "bundle") {
			return nil, fmt.Errorf("parsing config file: field bundle is no longer supported; use bundles")
		}
		if err := yamlstrict.Decode(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, fmt.Errorf("applying environment overrides: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	cfg.normalizeInstances()

	if err := cfg.parsePrivateKeys(); err != nil {
		return nil, fmt.Errorf("parsing private keys: %w", err)
	}

	return cfg, nil
}

func hasTopLevelYAMLKey(data []byte, field string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) != 1 {
		return false
	}
	document := root.Content[0]
	if document.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(document.Content); i += 2 {
		if document.Content[i].Value == field {
			return true
		}
	}
	return false
}

// Validate checks configuration for required fields and consistency.
func (s *Settings) Validate() error {
	switch s.BundleEnforcement {
	case BundleEnforcementRequired, BundleEnforcementOptional:
		// valid
	case "":
		return fmt.Errorf("bundle_enforcement is required")
	default:
		return fmt.Errorf("bundle_enforcement must be %q or %q (got %q)", BundleEnforcementRequired, BundleEnforcementOptional, s.BundleEnforcement)
	}

	if len(s.Apps) == 0 {
		return fmt.Errorf("at least one app must be configured")
	}

	for name, app := range s.Apps {
		hasFlatForm := app.AppID != 0 || app.PrivateKey != "" || app.PrivateKeyPath != ""
		hasInstances := len(app.Instances) > 0

		if hasFlatForm && hasInstances {
			return fmt.Errorf("app %q: app_id/private_key/private_key_path and instances are mutually exclusive", name)
		}

		if hasInstances {
			if err := validateInstances(name, app.Instances); err != nil {
				return err
			}
		} else {
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

		// rotation: is only meaningful on a pooled app — otherwise it's
		// valid YAML that would silently do nothing.
		hasRotation := app.Rotation.Strategy != "" || app.Rotation.MinRemainingPct != 0 || app.Rotation.MaxAttempts != 0
		if hasRotation && !hasInstances {
			return fmt.Errorf("app %q: rotation has no effect without instances (it does not apply to a flat app_id/private_key config)", name)
		}
		if hasInstances {
			if err := validateRotation(&app.Rotation, len(app.Instances)); err != nil {
				return fmt.Errorf("app %q: %w", name, err)
			}
		}

		// Default and validate policy_resolution. The mode is only meaningful
		// when an org policy repo is configured; otherwise it is ignored.
		if app.OrgPolicyRepo != "" {
			if app.PolicyResolution == "" {
				app.PolicyResolution = policy.ResolutionOrgFirst
			}
			if !policy.ValidResolution(app.PolicyResolution) {
				return fmt.Errorf("app %q: policy_resolution must be one of org_first, repo_first, org_only (got %q)", name, app.PolicyResolution)
			}
		} else if app.PolicyResolution != "" {
			// Modes that consult the org repo make no sense without one.
			if app.PolicyResolution == policy.ResolutionOrgFirst || app.PolicyResolution == policy.ResolutionOrgOnly {
				return fmt.Errorf("app %q: policy_resolution=%q requires org_policy_repo", name, app.PolicyResolution)
			}
			if !policy.ValidResolution(app.PolicyResolution) {
				return fmt.Errorf("app %q: policy_resolution must be one of org_first, repo_first, org_only (got %q)", name, app.PolicyResolution)
			}
		}

		s.Apps[name] = app
	}

	if s.JTI.Backend == "redis" && s.RedisURL() == "" {
		return fmt.Errorf("jti.redis_url is required when backend is redis")
	}

	if err := s.validateBundles(); err != nil {
		return err
	}

	if s.Server.Port < 1 || s.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}

	hasCert := s.Server.TLS.CertFile != ""
	hasKey := s.Server.TLS.KeyFile != ""
	if hasCert != hasKey {
		return fmt.Errorf("server.tls.cert_file and server.tls.key_file must be set together")
	}
	if s.Server.TLS.ClientCAFile != "" && !hasCert {
		return fmt.Errorf("server.tls.client_ca_file requires server.tls.cert_file and server.tls.key_file")
	}
	switch s.Server.TLS.MinVersion {
	case "", "1.2", "1.3":
		// valid
	default:
		return fmt.Errorf("server.tls.min_version must be \"1.2\" or \"1.3\" (got %q)", s.Server.TLS.MinVersion)
	}
	if s.Server.TLS.MinVersion == "1.3" && len(s.Server.TLS.CipherSuites) > 0 {
		return fmt.Errorf("server.tls.cipher_suites has no effect when min_version is \"1.3\" and must not be set")
	}
	for _, name := range s.Server.TLS.CipherSuites {
		if _, ok := tlsCipherSuiteNames[name]; !ok {
			return fmt.Errorf("server.tls.cipher_suites: unknown or insecure cipher suite %q", name)
		}
	}
	if s.Server.TLS.ReloadInterval != 0 && !hasCert {
		return fmt.Errorf("server.tls.reload_interval requires server.tls.cert_file and server.tls.key_file")
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
		if math.IsNaN(s.RateLimit.Rate) || math.IsInf(s.RateLimit.Rate, 0) || s.RateLimit.Rate <= 0 {
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

// validateInstances validates a pooled app's instance list: each instance
// needs an app_id and exactly one private key source, an optional name must
// match the same safe character set used for Prometheus label values
// elsewhere, and app_id must be unique within this one pool (a duplicate
// here almost certainly means the same physical App was pasted in twice).
// app_id reuse *across* different logical apps' pools is intentionally not
// checked here — see (*Settings).DuplicateAppIDWarnings.
func validateInstances(appName string, instances []AppInstanceConfig) error {
	seen := make(map[int64]string, len(instances))
	nameSeen := make(map[string]string, len(instances))
	for i, inst := range instances {
		label := inst.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i)
		}

		if inst.AppID == 0 {
			return fmt.Errorf("app %q: instances[%d]: app_id is required", appName, i)
		}
		hasInline := inst.PrivateKey != ""
		hasPath := inst.PrivateKeyPath != ""
		if !hasInline && !hasPath {
			return fmt.Errorf("app %q: instance %s: private_key or private_key_path is required", appName, label)
		}
		if hasInline && hasPath {
			return fmt.Errorf("app %q: instance %s: private_key and private_key_path are mutually exclusive", appName, label)
		}
		if inst.Name != "" {
			if len(inst.Name) > 100 {
				return fmt.Errorf("app %q: instance %s: name exceeds maximum length of 100", appName, label)
			}
			if !instanceNamePattern.MatchString(inst.Name) {
				return fmt.Errorf("app %q: instance %s: name contains invalid characters", appName, label)
			}
		}
		if prev, dup := seen[inst.AppID]; dup {
			return fmt.Errorf("app %q: duplicate app_id %d within pool (instances %s and %s)", appName, inst.AppID, prev, label)
		}
		seen[inst.AppID] = label

		// Compare the *effective* name — inst.Name, or the app_id-as-string
		// default normalizeInstances will later fill in when it's empty —
		// so an explicit name colliding with another instance's future
		// default is caught here too, not just two explicit names matching.
		effectiveName := inst.Name
		if effectiveName == "" {
			effectiveName = strconv.FormatInt(inst.AppID, 10)
		}
		if prev, dup := nameSeen[effectiveName]; dup {
			return fmt.Errorf("app %q: instance name %q used by both instances %s and %s", appName, effectiveName, prev, label)
		}
		nameSeen[effectiveName] = label
	}
	return nil
}

func (s *Settings) validateBundles() error {
	if s.BundleEnforcement == BundleEnforcementRequired && len(s.Bundles) == 0 {
		return fmt.Errorf("at least one bundle is required when bundle_enforcement is %q", BundleEnforcementRequired)
	}

	seen := make(map[string]struct{}, len(s.Bundles))
	globalBundles := 0
	for i, b := range s.Bundles {
		prefix := fmt.Sprintf("bundles[%d]", i)
		if b.Name == "" {
			return fmt.Errorf("%s.name is required", prefix)
		}
		if _, ok := seen[b.Name]; ok {
			return fmt.Errorf("bundle name %q is duplicated", b.Name)
		}
		seen[b.Name] = struct{}{}
		if b.Ref == "" {
			return fmt.Errorf("%s.ref is required", prefix)
		}
		if b.ExpectedPolicyRevision == "" {
			if s.BundleEnforcement == BundleEnforcementRequired {
				return fmt.Errorf("%s.expected_policy_revision is required when bundle_enforcement is %q", prefix, BundleEnforcementRequired)
			}
		} else if _, err := bundle.ParsePolicyRevision(b.ExpectedPolicyRevision); err != nil {
			return fmt.Errorf("%s.expected_policy_revision is invalid: %w", prefix, err)
		}
		if err := s.validateBundleApps(prefix, b.Apps); err != nil {
			return err
		}
		isOCI := strings.HasPrefix(b.Ref, "oci://")
		isPinnedOCI := isPinnedOCIRef(b.Ref)
		switch s.BundleEnforcement {
		case BundleEnforcementRequired:
			if b.AllowMutableRef {
				return fmt.Errorf("%s.allow_mutable_ref cannot be true when bundle_enforcement is %q", prefix, BundleEnforcementRequired)
			}
			if !isPinnedOCI {
				return fmt.Errorf("%s.ref must be an OCI reference pinned exactly to @sha256: followed by 64 lowercase hexadecimal characters when bundle_enforcement is %q", prefix, BundleEnforcementRequired)
			}
			if b.Cosign.SkipVerification {
				return fmt.Errorf("%s.cosign.skip_verification cannot be true when bundle_enforcement is %q", prefix, BundleEnforcementRequired)
			}
		case BundleEnforcementOptional:
			switch {
			case b.AllowMutableRef && !isOCI:
				return fmt.Errorf("%s.allow_mutable_ref can only be true for mutable OCI refs", prefix)
			case b.AllowMutableRef && isPinnedOCI:
				return fmt.Errorf("%s.allow_mutable_ref cannot be true for a digest-pinned OCI ref", prefix)
			case isOCI && !isPinnedOCI && !b.AllowMutableRef:
				return fmt.Errorf("%s.allow_mutable_ref must be true for a mutable OCI ref", prefix)
			}
		}
		if isOCI {
			hasKeyless := b.Cosign.CertificateIdentityRegexp != "" || b.Cosign.CertificateOIDCIssuer != ""
			hasPublicKey := b.Cosign.PublicKeyRef != ""
			if b.Cosign.SkipVerification && (hasKeyless || hasPublicKey) {
				return fmt.Errorf("%s.cosign.skip_verification cannot be combined with certificate identity/issuer or public_key_ref", prefix)
			}
			if hasKeyless && hasPublicKey {
				return fmt.Errorf("%s.cosign must use either keyless certificate identity/issuer or public_key_ref, not both", prefix)
			}
			if !b.Cosign.SkipVerification && !hasKeyless && !hasPublicKey {
				return fmt.Errorf("%s.cosign requires certificate_identity_regexp and certificate_oidc_issuer, public_key_ref, or skip_verification=true, for oci bundles", prefix)
			}
			if hasKeyless && b.Cosign.CertificateIdentityRegexp == "" {
				return fmt.Errorf("%s.cosign.certificate_identity_regexp is required for keyless oci bundles", prefix)
			}
			if hasKeyless && b.Cosign.CertificateOIDCIssuer == "" {
				return fmt.Errorf("%s.cosign.certificate_oidc_issuer is required for keyless oci bundles", prefix)
			}
		}
		if err := validateRegistryAuth(prefix, b.Registry.Auth); err != nil {
			return err
		}
		if b.Cosign.CertificateIdentityRegexp != "" {
			if _, err := regexp.Compile(b.Cosign.CertificateIdentityRegexp); err != nil {
				return fmt.Errorf("%s.cosign.certificate_identity_regexp: invalid regex: %w", prefix, err)
			}
		}
		if b.PollInterval == 0 {
			b.PollInterval = 5 * time.Minute
		}
		if b.MaxStaleness == 0 {
			b.MaxStaleness = 10 * time.Minute
		}
		if b.FailMode == "" {
			b.FailMode = BundleFailModeClosed
		}
		if b.PollInterval <= 0 {
			return fmt.Errorf("%s.poll_interval must be positive (got %s)", prefix, b.PollInterval)
		}
		if b.MaxStaleness <= 0 {
			return fmt.Errorf("%s.max_staleness must be positive (got %s)", prefix, b.MaxStaleness)
		}
		if b.MaxStaleness < b.PollInterval {
			return fmt.Errorf("%s.max_staleness (%s) must be >= poll_interval (%s)", prefix, b.MaxStaleness, b.PollInterval)
		}
		switch b.FailMode {
		case BundleFailModeClosed, BundleFailModeOpen:
			// valid
		default:
			return fmt.Errorf("%s.fail_mode must be %q or %q (got %q)", prefix, BundleFailModeClosed, BundleFailModeOpen, b.FailMode)
		}
		if s.BundleEnforcement == BundleEnforcementRequired && len(b.Apps) == 0 {
			globalBundles++
			if b.FailMode != BundleFailModeClosed {
				return fmt.Errorf("%s.fail_mode must be %q for the globally applicable baseline when bundle_enforcement is %q", prefix, BundleFailModeClosed, BundleEnforcementRequired)
			}
		}
		s.Bundles[i] = b
	}
	if s.BundleEnforcement == BundleEnforcementRequired && globalBundles != 1 {
		return fmt.Errorf("bundle_enforcement %q requires exactly one globally applicable bundle with apps empty (got %d)", BundleEnforcementRequired, globalBundles)
	}
	return nil
}

// validateRotation validates a pooled app's rotation config in place,
// applying defaults for strategy and max_attempts when left unset.
func validateRotation(r *RotationConfig, numInstances int) error {
	switch r.Strategy {
	case "":
		r.Strategy = "round_robin"
	case "round_robin", "rate_limit_aware":
		// valid
	default:
		return fmt.Errorf("rotation.strategy must be round_robin or rate_limit_aware (got %q)", r.Strategy)
	}
	if r.MinRemainingPct < 0 || r.MinRemainingPct >= 100 {
		return fmt.Errorf("rotation.min_remaining_pct must be in [0,100) (got %v)", r.MinRemainingPct)
	}
	if r.MaxAttempts < 0 {
		return fmt.Errorf("rotation.max_attempts must be >= 1 (got %d)", r.MaxAttempts)
	}
	if r.MaxAttempts == 0 {
		r.MaxAttempts = numInstances
		if r.MaxAttempts > 3 {
			r.MaxAttempts = 3
		}
	}
	return nil
}

func isPinnedOCIRef(ref string) bool {
	const (
		ociPrefix    = "oci://"
		digestMarker = "@sha256:"
	)
	if !strings.HasPrefix(ref, ociPrefix) {
		return false
	}
	marker := strings.LastIndex(ref, digestMarker)
	if marker <= len(ociPrefix) {
		return false
	}
	digest := ref[marker+len(digestMarker):]
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (s *Settings) validateBundleApps(prefix string, apps []string) error {
	seen := make(map[string]struct{}, len(apps))
	for _, app := range apps {
		if app == "" {
			return fmt.Errorf("%s.apps must not contain empty app names", prefix)
		}
		if _, ok := seen[app]; ok {
			return fmt.Errorf("%s.apps contains duplicate app %q", prefix, app)
		}
		seen[app] = struct{}{}
		if _, ok := s.Apps[app]; !ok {
			return fmt.Errorf("%s.apps references unknown app %q", prefix, app)
		}
	}
	return nil
}

// DuplicateAppIDWarnings returns a human-readable warning for every app_id
// that appears in more than one logical app's pool. This is deliberately
// not a validation error (see Validate/validateInstances, which only
// enforces uniqueness *within* one pool): today's config has never forbidden
// two logical app names from sharing an app_id, and rejecting it now would
// be a silent breaking change for any deployment that already does this.
//
// Must be called after a successful Load (which normalizes every app's
// Instances list before returning) — this walks Instances directly and
// won't see a flat-form app's app_id otherwise.
func (s *Settings) DuplicateAppIDWarnings() []string {
	type owner struct {
		appName  string
		instance string
	}
	byAppID := make(map[int64][]owner)
	for name, app := range s.Apps {
		for _, inst := range app.Instances {
			label := inst.Name
			if label == "" {
				label = strconv.FormatInt(inst.AppID, 10)
			}
			byAppID[inst.AppID] = append(byAppID[inst.AppID], owner{appName: name, instance: label})
		}
	}

	var warnings []string
	for appID, owners := range byAppID {
		names := make(map[string]bool, len(owners))
		for _, o := range owners {
			names[o.appName] = true
		}
		if len(names) < 2 {
			continue
		}
		list := make([]string, 0, len(names))
		for n := range names {
			list = append(list, n)
		}
		sort.Strings(list)
		warnings = append(warnings, fmt.Sprintf(
			"app_id %d is used by more than one logical app (%s) — each shares the same GitHub rate-limit bucket; this is allowed but may be unintentional",
			appID, strings.Join(list, ", ")))
	}
	sort.Strings(warnings)
	return warnings
}

func validateRegistryAuth(prefix string, auth RegistryAuthConfig) error {
	if auth.Mode == "" {
		if auth.Username != "" || auth.PasswordFile != "" || auth.PasswordEnv != "" {
			return fmt.Errorf("%s.registry.auth.mode is required when registry auth fields are set", prefix)
		}
		return nil
	}
	if auth.Mode != "basic" {
		return fmt.Errorf("%s.registry.auth.mode must be %q (got %q)", prefix, "basic", auth.Mode)
	}
	if auth.Username == "" {
		return fmt.Errorf("%s.registry.auth.username is required for basic auth", prefix)
	}
	hasPasswordFile := auth.PasswordFile != ""
	hasPasswordEnv := auth.PasswordEnv != ""
	if hasPasswordFile == hasPasswordEnv {
		return fmt.Errorf("%s.registry.auth must set exactly one of password_file or password_env for basic auth", prefix)
	}
	return nil
}

func (s *Settings) EffectiveBundles() []BundleConfig {
	out := make([]BundleConfig, len(s.Bundles))
	copy(out, s.Bundles)
	return out
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

// RequiredAudience returns the server-wide required audience (empty if unset).
func (s *Settings) RequiredAudience() string {
	return s.OIDC.RequiredAudience
}

// RequireImmutableSubjectClaims reports whether GitHub.com Actions subjects
// must carry immutable owner and repository IDs in their repo segment.
func (s *Settings) RequireImmutableSubjectClaims() bool {
	return s.OIDC.RequireImmutableSubjectClaims
}

// GetApp returns the AppConfig for the given name.
func (s *Settings) GetApp(name string) (AppConfig, bool) {
	app, ok := s.Apps[name]
	return app, ok
}

// normalizeInstances ensures every app's Instances list is populated,
// synthesizing a single-element pool from the legacy flat fields when
// Instances wasn't set in YAML/env. It also fills in the default instance
// name (app_id, stringified) and default rotation settings. After this
// runs, every downstream consumer — parsePrivateKeys and everything in
// internal/server/internal/github beyond it — only ever sees the general
// N-instance shape; no parallel single/multi code paths propagate further.
//
// Must run after Validate() (which needs to distinguish the flat form from
// the pooled form to enforce mutual exclusion) and before parsePrivateKeys.
func (s *Settings) normalizeInstances() {
	for name, app := range s.Apps {
		if len(app.Instances) == 0 {
			app.Instances = []AppInstanceConfig{{
				AppID:          app.AppID,
				PrivateKey:     app.PrivateKey,
				PrivateKeyPath: app.PrivateKeyPath,
			}}
		}
		for i := range app.Instances {
			if app.Instances[i].Name == "" {
				app.Instances[i].Name = strconv.FormatInt(app.Instances[i].AppID, 10)
			}
		}
		if app.Rotation.Strategy == "" {
			app.Rotation.Strategy = "round_robin"
		}
		if app.Rotation.MaxAttempts == 0 {
			app.Rotation.MaxAttempts = len(app.Instances)
			if app.Rotation.MaxAttempts > 3 {
				app.Rotation.MaxAttempts = 3
			}
		}
		s.Apps[name] = app
	}
}

// parsePrivateKeys parses PEM-encoded private keys for every instance of
// every app. Must run after normalizeInstances, which guarantees Instances
// is populated for every app regardless of whether it was configured via
// the legacy flat fields or the instances: list.
func (s *Settings) parsePrivateKeys() error {
	for name, app := range s.Apps {
		for i := range app.Instances {
			inst := &app.Instances[i]

			var pemData []byte
			if inst.PrivateKey != "" {
				pemData = []byte(inst.PrivateKey)
			} else {
				data, err := os.ReadFile(inst.PrivateKeyPath)
				if err != nil {
					return fmt.Errorf("app %q instance %q: reading private key file: %w", name, inst.Name, err)
				}
				pemData = data
			}

			block, _ := pem.Decode(pemData)
			if block == nil {
				return fmt.Errorf("app %q instance %q: invalid PEM data", name, inst.Name)
			}

			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				// Try PKCS8 as fallback.
				parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err2 != nil {
					return fmt.Errorf("app %q instance %q: parsing private key: %w", name, inst.Name, err)
				}
				rsaKey, ok := parsed.(*rsa.PrivateKey)
				if !ok {
					return fmt.Errorf("app %q instance %q: private key is not RSA", name, inst.Name)
				}
				key = rsaKey
			}

			inst.ParsedKey = key
		}
		s.Apps[name] = app
	}
	return nil
}

// applyEnvOverrides applies GITHUBSTS_* environment variable overrides.
func applyEnvOverrides(cfg *Settings) error {
	if v, ok := os.LookupEnv("GITHUBSTS_BUNDLE_ENFORCEMENT"); ok {
		cfg.BundleEnforcement = v
	}

	// Server
	if v := os.Getenv("GITHUBSTS_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if err := envInt("GITHUBSTS_SERVER_PORT", &cfg.Server.Port); err != nil {
		return err
	}
	if v := os.Getenv("GITHUBSTS_SERVER_LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = v
	}
	if err := envBool("GITHUBSTS_SERVER_SUPPRESS_HEALTH_LOGS", &cfg.Server.SuppressHealthLogs); err != nil {
		return err
	}
	if err := envDuration("GITHUBSTS_SERVER_SHUTDOWN_TIMEOUT", &cfg.Server.ShutdownTimeout); err != nil {
		return err
	}
	if err := envBool("GITHUBSTS_SERVER_TRUST_FORWARDED_HEADERS", &cfg.Server.TrustForwardedHeaders); err != nil {
		return err
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLS.CertFile = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLS.KeyFile = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE"); v != "" {
		cfg.Server.TLS.ClientCAFile = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TLS_MIN_VERSION"); v != "" {
		cfg.Server.TLS.MinVersion = v
	}
	if v := os.Getenv("GITHUBSTS_SERVER_TLS_CIPHER_SUITES"); v != "" {
		if suites := parseCommaSeparated(v); len(suites) > 0 {
			cfg.Server.TLS.CipherSuites = suites
		}
	}
	if err := envDuration("GITHUBSTS_SERVER_TLS_RELOAD_INTERVAL", &cfg.Server.TLS.ReloadInterval); err != nil {
		return err
	}

	// OIDC
	if v, ok := os.LookupEnv("GITHUBSTS_OIDC_ALLOWED_ISSUERS"); ok {
		cfg.OIDC.AllowedIssuers = parseCommaSeparated(v)
	}
	if v := os.Getenv("GITHUBSTS_OIDC_REQUIRED_AUDIENCE"); v != "" {
		cfg.OIDC.RequiredAudience = v
	}
	if err := envBool("GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS", &cfg.OIDC.RequireImmutableSubjectClaims); err != nil {
		return err
	}

	// JTI
	if v := os.Getenv("GITHUBSTS_JTI_BACKEND"); v != "" {
		cfg.JTI.Backend = v
	}
	if v := os.Getenv("GITHUBSTS_JTI_REDIS_URL"); v != "" {
		cfg.JTI.RedisURL = v
	}
	if err := envDuration("GITHUBSTS_JTI_TTL", &cfg.JTI.TTL); err != nil {
		return err
	}

	// Policy
	if v := os.Getenv("GITHUBSTS_POLICY_BASE_PATH"); v != "" {
		cfg.Policy.BasePath = v
	}
	if err := envDuration("GITHUBSTS_POLICY_CACHE_TTL", &cfg.Policy.CacheTTL); err != nil {
		return err
	}

	// Audit
	if err := envBool("GITHUBSTS_AUDIT_FILE_ENABLED", &cfg.Audit.FileEnabled); err != nil {
		return err
	}
	if v := os.Getenv("GITHUBSTS_AUDIT_FILE_PATH"); v != "" {
		cfg.Audit.FilePath = v
	}
	if err := envInt("GITHUBSTS_AUDIT_BUFFER_SIZE", &cfg.Audit.BufferSize); err != nil {
		return err
	}

	// Metrics
	if v := os.Getenv("GITHUBSTS_METRICS_AUTH_TOKEN"); v != "" {
		cfg.Metrics.AuthToken = v
	}
	if err := envBool("GITHUBSTS_METRICS_ENABLED", &cfg.Metrics.Enabled); err != nil {
		return err
	}
	if err := envBool("GITHUBSTS_METRICS_RATE_LIMIT_POLL_ENABLED", &cfg.Metrics.RateLimitPollEnabled); err != nil {
		return err
	}
	if err := envDuration("GITHUBSTS_METRICS_RATE_LIMIT_POLL_INTERVAL", &cfg.Metrics.RateLimitPollInterval); err != nil {
		return err
	}
	if err := envBool("GITHUBSTS_METRICS_REACHABILITY_PROBE_ENABLED", &cfg.Metrics.ReachabilityProbeEnabled); err != nil {
		return err
	}
	if err := envDuration("GITHUBSTS_METRICS_REACHABILITY_PROBE_INTERVAL", &cfg.Metrics.ReachabilityProbeInterval); err != nil {
		return err
	}

	// Rate limit
	if err := envBool("GITHUBSTS_RATE_LIMIT_ENABLED", &cfg.RateLimit.Enabled); err != nil {
		return err
	}
	if err := envFloat64("GITHUBSTS_RATE_LIMIT_RATE", &cfg.RateLimit.Rate); err != nil {
		return err
	}
	if err := envInt("GITHUBSTS_RATE_LIMIT_BURST", &cfg.RateLimit.Burst); err != nil {
		return err
	}
	if v, ok := os.LookupEnv("GITHUBSTS_RATE_LIMIT_EXEMPT_CIDRS"); ok {
		cfg.RateLimit.ExemptCIDRs = parseCommaSeparated(v)
	}

	// Per-app env vars
	for name, app := range cfg.Apps {
		upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if err := envInt64("GITHUBSTS_APP_"+upper+"_APP_ID", &app.AppID); err != nil {
			return err
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
		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_POLICY_RESOLUTION"); v != "" {
			app.PolicyResolution = policy.Resolution(v)
		}

		if v := os.Getenv("GITHUBSTS_APP_" + upper + "_ROTATION_STRATEGY"); v != "" {
			app.Rotation.Strategy = v
		}
		if err := envFloat64("GITHUBSTS_APP_"+upper+"_ROTATION_MIN_REMAINING_PCT", &app.Rotation.MinRemainingPct); err != nil {
			return err
		}
		if err := envInt("GITHUBSTS_APP_"+upper+"_ROTATION_MAX_ATTEMPTS", &app.Rotation.MaxAttempts); err != nil {
			return err
		}

		// Indexed instance overrides: GITHUBSTS_APP_{NAME}_INSTANCE_{N}_*,
		// 1-based and contiguous — stop at the first index where none of the
		// four fields is set.
		for i := 1; ; i++ {
			prefix := fmt.Sprintf("GITHUBSTS_APP_%s_INSTANCE_%d_", upper, i)
			appIDStr := os.Getenv(prefix + "APP_ID")
			privKey := os.Getenv(prefix + "PRIVATE_KEY")
			privKeyPath := os.Getenv(prefix + "PRIVATE_KEY_PATH")
			instName := os.Getenv(prefix + "NAME")
			if appIDStr == "" && privKey == "" && privKeyPath == "" && instName == "" {
				break
			}
			for len(app.Instances) < i {
				app.Instances = append(app.Instances, AppInstanceConfig{})
			}
			inst := &app.Instances[i-1]
			if appIDStr != "" {
				n, err := strconv.ParseInt(appIDStr, 10, 64)
				if err != nil {
					return fmt.Errorf("%sAPP_ID must be an integer: %w", prefix, err)
				}
				inst.AppID = n
			}
			if privKey != "" {
				inst.PrivateKey = privKey
			}
			if privKeyPath != "" {
				inst.PrivateKeyPath = privKeyPath
			}
			if instName != "" {
				inst.Name = instName
			}
		}

		cfg.Apps[name] = app
	}

	return nil
}

func envBool(name string, target *bool) error {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	*target = parsed
	return nil
}

func envInt(name string, target *int) error {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%s must be an integer: %w", name, err)
	}
	*target = parsed
	return nil
}

func envInt64(name string, target *int64) error {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("%s must be an integer: %w", name, err)
	}
	*target = parsed
	return nil
}

func envFloat64(name string, target *float64) error {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		if err == nil {
			err = fmt.Errorf("value must be finite")
		}
		return fmt.Errorf("%s must be a number: %w", name, err)
	}
	*target = parsed
	return nil
}

func envDuration(name string, target *time.Duration) error {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s must be a duration: %w", name, err)
	}
	*target = parsed
	return nil
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
