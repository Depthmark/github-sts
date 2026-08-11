package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPEM is a valid RSA private key (PKCS8) for testing.
const testPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgBiE4FP7J8Tfe
rQU7GaUbvIeAfndTBb+f6QLw6N48ociKJD9VEjuLF210JN3WUDbuo4vxQ7in6o6F
LBerpacQs4J/R1doiVJAKzY2qOlu22Ji7ZlI3Udz6YDYr5kGZ+UM/U0WfAl/10PE
hwsmf/DlbFbAnLfwlawBLTX2jwLHm69NPI1Ro1nqy5vIUb2xp9vvFqKJqHgbbLIN
r70CqDUVvbcUrvDKGAGUQBAjmyYz14Kat3WfZFiBMfr4BjgXNGChTYfx0bqYJHv5
I2UixtY4tDbgaJgL3zliKWfCb/gPOIG3xyGfvtf/mbhL2I5wVO+B84foJlmY2rgu
qkKctMszAgMBAAECggEAF+PvdPigN073I1MWRLg2aF/Rn31dIkhxqA8EVkavNI4Y
Qcsdyee429tyu7kWwz0orohYazFKpvWXn1IVcCOpTlmmaAZmpupGEDvLe0bGJiFV
O7GU8DVQ4mabbABF9G3t+lWk++ncZXrCalnwcXmhagYEtmPAJfMANdvpblLP/BNG
JUMJAX0mnwXU5QtfKTFEZRLNzRzf5j7sgjM9ptUmhO9V2N2OCrFpKa2+KY/qwmHx
4HS/NS2q/9jaBJanzKgsuZNaFMOrg3rPAsm4nHwqA76ayo9d41gH07ZO7LGLSnJC
iufCchMgZJ/MN88mHrEbN2dx6HG2yyh17FM720DUuQKBgQD1yPFZchzOzMysgNti
KFzfilPg5gl4I0Gp/z9TCKw6M7Rw6NibKXUc51dJqqeCM1xydriBHxG2QkcA+8zw
cu5V94oq98N1rj2+we04/+COdd4C1m/GuGBKIuPsrH1DDk0aBn5jqmbOnSRJGkTW
eE7ihvtL+yvlzSziHVdcHfALpQKBgQDpVaiPY8l/R5b8ETR9uiPq+3tVn5Ewt9qj
zF6eIixtYc2vzUh5S4fUaKxFH9SapoffqnAmpipDGfb1iXoitU6ZTjl3tjD7uTWo
GHP8zdrxk5AKBPwPreYvd5oSCKJ0GO2RCmQzbwEitFFJja98ansezMr8YOLkJDO2
UXSXptoj9wKBgG9lVnXKsWHNEoqwkD3pu0YZhLCuseYAXLd2lzXD/YMXghWWgu24
GXszIq2hqe/p5WF/i1oCQd3QJiw884KbJIhT/AxDZRRGF3gInsKxvg3zP98bX2e6
kvGm5JSVDOTCa5F7FfeH+LZ2JEb5n+9wcZhbwzOJsDikCE6nK7v1WaF9AoGAckI7
1Fts5CLOUIisR5TK2dpjvr3wfwbIzcTZ4F2jm7x02E2R27Ocw+qt0PuRRFmf12rC
mGpt74XbZMj5Qd2+q1ue0Hwq6Fj9aV7wDS9Qs1MrCXz/YT4qpbvPel04D9nVG10X
TAhjafcahwYWlLofqClojMV01XrUx8aDbW+LCmkCgYEA2GaoiyYET+zTbRCP2tQK
FbbbOKtPstRCiNNGtHwYF56GkFZ9Gc5KPTBqp4g0wupY1dCyC6PE/3srDUTj0pAL
rC8dJV1CH2nSPGPYnqD9rYVyLkA5eYOXE+hENXEgpAvvPzHtcXQsa8wy6e3FSNE6
hLAjpuJh79q2JhYArvCdjQA=
-----END PRIVATE KEY-----`

const testPinnedBundleRef = "oci://ghcr.io/org/sts-policy@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte(testPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_FullYAML(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
bundle_enforcement: optional
server:
  host: "127.0.0.1"
  port: 9090
  log_level: "debug"
  suppress_health_logs: false
  shutdown_timeout: 15s
apps:
  myapp:
    app_id: 12345
    private_key_path: "` + keyPath + `"
    org_policy_repo: ".github"
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
  require_immutable_subject_claims: false
jti:
  backend: "memory"
  ttl: 30m
policy:
  base_path: ".github/sts"
  cache_ttl: 120s
audit:
  file_enabled: true
  file_path: "/tmp/audit.json"
  buffer_size: 512
metrics:
  enabled: true
  rate_limit_poll_enabled: false
  rate_limit_poll_interval: 30s
  reachability_probe_enabled: false
  reachability_probe_interval: 15s
`
	path := writeTestConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.Server.LogLevel)
	}
	if cfg.Server.SuppressHealthLogs {
		t.Error("suppress_health_logs should be false")
	}
	if cfg.Server.ShutdownTimeout != 15*time.Second {
		t.Errorf("shutdown_timeout = %v, want 15s", cfg.Server.ShutdownTimeout)
	}

	app, ok := cfg.Apps["myapp"]
	if !ok {
		t.Fatal("app myapp not found")
	}
	if app.AppID != 12345 {
		t.Errorf("app_id = %d, want 12345", app.AppID)
	}
	if app.ParsedKey == nil {
		t.Error("ParsedKey is nil")
	}

	if len(cfg.OIDC.AllowedIssuers) != 1 {
		t.Fatalf("allowed_issuers len = %d, want 1", len(cfg.OIDC.AllowedIssuers))
	}
	if cfg.OIDC.RequireImmutableSubjectClaims {
		t.Error("require_immutable_subject_claims should be false from YAML")
	}

	if cfg.JTI.TTL != 30*time.Minute {
		t.Errorf("jti.ttl = %v, want 30m", cfg.JTI.TTL)
	}

	if cfg.Metrics.RateLimitPollEnabled {
		t.Error("rate_limit_poll_enabled should be false from YAML")
	}
	if cfg.Metrics.RateLimitPollInterval != 30*time.Second {
		t.Errorf("rate_limit_poll_interval = %v, want 30s", cfg.Metrics.RateLimitPollInterval)
	}
}

func TestLoad_Defaults(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
oidc:
  allowed_issuers:
    - "https://test.example.com"
`
	path := writeTestConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("default port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.JTI.Backend != "memory" {
		t.Errorf("default jti backend = %q, want memory", cfg.JTI.Backend)
	}
	if cfg.Policy.BasePath != ".github/sts" {
		t.Errorf("default base_path = %q, want .github/sts", cfg.Policy.BasePath)
	}
	if cfg.Audit.BufferSize != 1024 {
		t.Errorf("default buffer_size = %d, want 1024", cfg.Audit.BufferSize)
	}
	if !cfg.OIDC.RequireImmutableSubjectClaims {
		t.Error("require_immutable_subject_claims default = false, want true")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
oidc:
  allowed_issuers:
    - "https://placeholder.example.com"
`
	path := writeTestConfig(t, yaml)

	t.Setenv("GITHUBSTS_SERVER_PORT", "3000")
	t.Setenv("GITHUBSTS_SERVER_LOG_LEVEL", "warn")
	t.Setenv("GITHUBSTS_OIDC_ALLOWED_ISSUERS", "https://issuer1.com, https://issuer2.com")
	t.Setenv("GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS", "false")
	t.Setenv("GITHUBSTS_JTI_TTL", "2h")
	t.Setenv("GITHUBSTS_AUDIT_FILE_ENABLED", "false")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Port != 3000 {
		t.Errorf("port = %d, want 3000", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "warn" {
		t.Errorf("log_level = %q, want warn", cfg.Server.LogLevel)
	}
	if len(cfg.OIDC.AllowedIssuers) != 2 {
		t.Fatalf("allowed_issuers len = %d, want 2", len(cfg.OIDC.AllowedIssuers))
	}
	if cfg.OIDC.AllowedIssuers[1] != "https://issuer2.com" {
		t.Errorf("issuer[1] = %q, want https://issuer2.com", cfg.OIDC.AllowedIssuers[1])
	}
	if cfg.OIDC.RequireImmutableSubjectClaims {
		t.Error("require_immutable_subject_claims env override = true, want false")
	}
	if cfg.JTI.TTL != 2*time.Hour {
		t.Errorf("jti.ttl = %v, want 2h", cfg.JTI.TTL)
	}
	if cfg.Audit.FileEnabled {
		t.Error("audit.file_enabled should be false from env override")
	}
}

func TestLoad_BundleEnforcementEnvOverride(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
bundles:
  - name: enterprise
    ref: "`+testPinnedBundleRef+`"
    cosign:
      public_key_ref: cosign.pub
`)
	t.Setenv("GITHUBSTS_BUNDLE_ENFORCEMENT", BundleEnforcementRequired)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.BundleEnforcement != BundleEnforcementRequired {
		t.Errorf("bundle_enforcement = %q, want %q", cfg.BundleEnforcement, BundleEnforcementRequired)
	}
}

func TestLoad_BundleEnforcementOmitted(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
apps:
  default:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
`)

	_, err := Load(path)
	if err == nil || !contains(err.Error(), "bundle_enforcement") {
		t.Fatalf("expected bundle_enforcement error, got: %v", err)
	}
}

func TestLoad_InvalidImmutableSubjectEnvFails(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
`)
	t.Setenv("GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS", "treu")

	_, err := Load(path)
	if err == nil || !contains(err.Error(), "GITHUBSTS_OIDC_REQUIRE_IMMUTABLE_SUBJECT_CLAIMS") {
		t.Fatalf("expected strict immutable-subject env error, got: %v", err)
	}
}

func TestLoad_StrictYAML(t *testing.T) {
	keyPath := writeTestKey(t)
	base := `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
oidc:
  allowed_issuers:
    - https://issuer.example.com
`
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "unknown top level", content: base + "bundels: []\n", want: "field bundels not found"},
		{name: "unknown nested", content: base + "  claim_patern: true\n", want: "field claim_patern not found"},
		{name: "duplicate key", content: base + "oidc:\n  allowed_issuers: [https://other.example.com]\n", want: "already defined"},
		{name: "multiple documents", content: base + "---\n{}\n", want: "multiple YAML documents"},
		{name: "singular bundle", content: base + "bundle: {}\n", want: "field bundle is no longer supported; use bundles"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTestConfig(t, tt.content))
			if err == nil || !contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoad_InvalidTypedEnvironmentOverridesFail(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  default:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - https://issuer.example.com
`)
	tests := []struct {
		name  string
		value string
	}{
		{name: "GITHUBSTS_SERVER_PORT", value: "eighty"},
		{name: "GITHUBSTS_SERVER_SUPPRESS_HEALTH_LOGS", value: "sometimes"},
		{name: "GITHUBSTS_JTI_TTL", value: "tomorrow"},
		{name: "GITHUBSTS_RATE_LIMIT_RATE", value: "fast"},
		{name: "GITHUBSTS_RATE_LIMIT_RATE", value: "NaN"},
		{name: "GITHUBSTS_RATE_LIMIT_RATE", value: "+Inf"},
		{name: "GITHUBSTS_APP_DEFAULT_APP_ID", value: "one"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.name, tt.value)
			_, err := Load(path)
			if err == nil || !contains(err.Error(), tt.name) {
				t.Fatalf("error = %v, want variable name %q", err, tt.name)
			}
		})
	}
}

// validDefaults returns a defaults() config with the minimum required
// fields populated to pass validation.
func validDefaults() *Settings {
	cfg := defaults()
	cfg.BundleEnforcement = BundleEnforcementOptional
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: testPEM}
	cfg.OIDC.AllowedIssuers = []string{"https://test.example.com"}
	return cfg
}

func validRequiredBundle(name string) BundleConfig {
	return BundleConfig{
		Name: name,
		Ref:  testPinnedBundleRef,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
	}
}

func TestValidate_BundleEnforcementInvalid(t *testing.T) {
	cfg := validDefaults()
	cfg.BundleEnforcement = "sometimes"

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "bundle_enforcement") {
		t.Fatalf("expected bundle_enforcement error, got: %v", err)
	}
}

func TestValidate_BundleEnforcementOptionalAllowsNoBundles(t *testing.T) {
	cfg := validDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundleEnforcementRequiredRejectsNoBundles(t *testing.T) {
	cfg := validDefaults()
	cfg.BundleEnforcement = BundleEnforcementRequired

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "at least one bundle") {
		t.Fatalf("expected required bundle error, got: %v", err)
	}
}

func TestValidate_BundleEnforcementRequiredRejectsAppOnlyBaseline(t *testing.T) {
	cfg := validDefaults()
	cfg.BundleEnforcement = BundleEnforcementRequired
	bundle := validRequiredBundle("app-policy")
	bundle.Apps = []string{"test"}
	cfg.Bundles = []BundleConfig{bundle}

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "exactly one globally applicable bundle") {
		t.Fatalf("expected global baseline error, got: %v", err)
	}
}

func TestValidate_BundleEnforcementRequiredRejectsMultipleGlobalBaselines(t *testing.T) {
	cfg := validDefaults()
	cfg.BundleEnforcement = BundleEnforcementRequired
	cfg.Bundles = []BundleConfig{
		validRequiredBundle("enterprise-a"),
		validRequiredBundle("enterprise-b"),
	}

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "exactly one globally applicable bundle") {
		t.Fatalf("expected global baseline error, got: %v", err)
	}
}

func TestValidate_BundleEnforcementRequiredAcceptsPinnedVerifiedGlobalBaseline(t *testing.T) {
	cfg := validDefaults()
	cfg.BundleEnforcement = BundleEnforcementRequired
	additive := validRequiredBundle("app-policy")
	additive.Apps = []string{"test"}
	cfg.Bundles = []BundleConfig{
		validRequiredBundle("enterprise"),
		additive,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Bundles[0].FailMode != BundleFailModeClosed {
		t.Errorf("global baseline fail_mode = %q, want %q", cfg.Bundles[0].FailMode, BundleFailModeClosed)
	}
}

func TestValidate_BundleEnforcementRequiredRejectsUnsafeBundles(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*BundleConfig)
		want      string
	}{
		{
			name: "filesystem ref",
			configure: func(bundle *BundleConfig) {
				bundle.Ref = "file:///tmp/bundle.tar.gz"
			},
			want: "pinned exactly",
		},
		{
			name: "tag ref",
			configure: func(bundle *BundleConfig) {
				bundle.Ref = "oci://ghcr.io/org/sts-policy:v1"
			},
			want: "pinned exactly",
		},
		{
			name: "skipped verification",
			configure: func(bundle *BundleConfig) {
				bundle.Cosign = CosignConfig{SkipVerification: true}
			},
			want: "skip_verification",
		},
		{
			name: "open fail mode",
			configure: func(bundle *BundleConfig) {
				bundle.FailMode = BundleFailModeOpen
			},
			want: "fail_mode",
		},
		{
			name: "mutable ref opt-in",
			configure: func(bundle *BundleConfig) {
				bundle.AllowMutableRef = true
			},
			want: "allow_mutable_ref",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDefaults()
			cfg.BundleEnforcement = BundleEnforcementRequired
			bundle := validRequiredBundle("enterprise")
			tt.configure(&bundle)
			cfg.Bundles = []BundleConfig{bundle}

			err := cfg.Validate()
			if err == nil || !contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidate_BundleEnforcementOptionalMutableRefOptIn(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*BundleConfig)
		want      string
	}{
		{
			name: "tag requires opt-in",
			configure: func(bundle *BundleConfig) {
				bundle.Ref = "oci://ghcr.io/org/sts-policy:v1"
			},
			want: "allow_mutable_ref",
		},
		{
			name: "tag with opt-in",
			configure: func(bundle *BundleConfig) {
				bundle.Ref = "oci://ghcr.io/org/sts-policy:v1"
				bundle.AllowMutableRef = true
			},
		},
		{
			name: "pinned ref rejects opt-in",
			configure: func(bundle *BundleConfig) {
				bundle.AllowMutableRef = true
			},
			want: "digest-pinned",
		},
		{
			name: "filesystem ref rejects opt-in",
			configure: func(bundle *BundleConfig) {
				bundle.Ref = "file:///tmp/bundle.tar.gz"
				bundle.AllowMutableRef = true
			},
			want: "only be true for mutable OCI refs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDefaults()
			bundle := validRequiredBundle("enterprise")
			tt.configure(&bundle)
			cfg.Bundles = []BundleConfig{bundle}

			err := cfg.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidate_NoApps(t *testing.T) {
	cfg := defaults()
	cfg.BundleEnforcement = BundleEnforcementOptional
	cfg.OIDC.AllowedIssuers = []string{"https://test.example.com"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for no apps")
	}
}

func TestValidate_MissingAppID(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{PrivateKey: testPEM}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "app_id is required") {
		t.Errorf("expected app_id error, got: %v", err)
	}
}

func TestValidate_BothKeyAndPath(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: "x", PrivateKeyPath: "/y"}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestValidate_RedisWithoutURL(t *testing.T) {
	cfg := validDefaults()
	cfg.JTI.Backend = "redis"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "redis_url is required") {
		t.Errorf("expected redis_url error, got: %v", err)
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.LogLevel = "verbose"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "log_level") {
		t.Errorf("expected log_level error, got: %v", err)
	}
}

func TestValidate_EmptyAllowedIssuers(t *testing.T) {
	cfg := defaults()
	cfg.BundleEnforcement = BundleEnforcementOptional
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: testPEM}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "allowed_issuers") {
		t.Errorf("expected allowed_issuers error, got: %v", err)
	}
}

func TestValidate_RateLimitInvalidCIDR(t *testing.T) {
	cfg := validDefaults()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Rate = 10
	cfg.RateLimit.Burst = 20
	cfg.RateLimit.ExemptCIDRs = []string{"not-a-cidr"}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected CIDR error, got: %v", err)
	}
}

func TestValidate_RateLimitValidCIDR(t *testing.T) {
	cfg := validDefaults()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Rate = 10
	cfg.RateLimit.Burst = 20
	cfg.RateLimit.ExemptCIDRs = []string{"10.0.0.0/8", "fd00::/8"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesDefaultsAndValidation(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name: "enterprise-security",
		Ref:  "file:///tmp/bundle.tar.gz",
	}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Bundles[0].PollInterval; got != 5*time.Minute {
		t.Errorf("poll_interval default = %s, want 5m", got)
	}
	if got := cfg.Bundles[0].MaxStaleness; got != 10*time.Minute {
		t.Errorf("max_staleness default = %s, want 10m", got)
	}
	if got := cfg.Bundles[0].FailMode; got != BundleFailModeClosed {
		t.Errorf("fail_mode default = %q, want closed", got)
	}
}

func TestValidate_BundlesDuplicateNameRejected(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{
		{Name: "enterprise", Ref: "file:///tmp/a.tar.gz"},
		{Name: "enterprise", Ref: "file:///tmp/b.tar.gz"},
	}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "duplicated") {
		t.Errorf("expected duplicate bundle name error, got: %v", err)
	}
}

func TestValidate_BundlesOCIRequiresCosign(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "skip_verification") {
		t.Errorf("expected cosign identity requirement, got: %v", err)
	}
}

func TestValidate_BundlesOCIAcceptsSkipVerification(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://harbor.local/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			SkipVerification: true,
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesOCIRejectsSkipVerificationWithCosignMode(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://harbor.local/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef:     "cosign.pub",
			SkipVerification: true,
		},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "cannot be combined") {
		t.Errorf("expected skip verification conflict error, got: %v", err)
	}
}

func TestValidate_BundlesOCIAcceptsPublicKeyRef(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesAcceptsKnownAppScope(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name: "enterprise",
		Ref:  "file:///tmp/bundle.tar.gz",
		Apps: []string{"test"},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesRejectsUnknownAppScope(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name: "enterprise",
		Ref:  "file:///tmp/bundle.tar.gz",
		Apps: []string{"missing"},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "unknown app") {
		t.Errorf("expected unknown app scope error, got: %v", err)
	}
}

func TestValidate_BundlesRejectsDuplicateAppScope(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name: "enterprise",
		Ref:  "file:///tmp/bundle.tar.gz",
		Apps: []string{"test", "test"},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "duplicate app") {
		t.Errorf("expected duplicate app scope error, got: %v", err)
	}
}

func TestValidate_BundlesOCIRejectsMixedCosignModes(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			CertificateIdentityRegexp: "^https://github.com/org/repo/.*$",
			CertificateOIDCIssuer:     "https://token.actions.githubusercontent.com",
			PublicKeyRef:              "cosign.pub",
		},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "not both") {
		t.Errorf("expected mixed cosign mode error, got: %v", err)
	}
}

func TestValidate_BundlesOCIAcceptsBasicRegistryAuthPasswordFile(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
		Registry: RegistryConfig{Auth: RegistryAuthConfig{
			Mode:         "basic",
			Username:     "robot$github-sts",
			PasswordFile: "/var/run/secrets/harbor/password",
		}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesOCIAcceptsBasicRegistryAuthPasswordEnv(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
		Registry: RegistryConfig{Auth: RegistryAuthConfig{
			Mode:        "basic",
			Username:    "robot$github-sts",
			PasswordEnv: "HARBOR_PASSWORD",
		}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_BundlesOCIRejectsBasicRegistryAuthWithoutSecretRef(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
		Registry: RegistryConfig{Auth: RegistryAuthConfig{
			Mode:     "basic",
			Username: "robot$github-sts",
		}},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "password_file or password_env") {
		t.Errorf("expected registry auth secret ref error, got: %v", err)
	}
}

func TestValidate_BundlesOCIRejectsUnsupportedRegistryAuthMode(t *testing.T) {
	cfg := validDefaults()
	cfg.Bundles = []BundleConfig{{
		Name:            "enterprise",
		Ref:             "oci://ghcr.io/org/sts-policy:v1",
		AllowMutableRef: true,
		Cosign: CosignConfig{
			PublicKeyRef: "cosign.pub",
		},
		Registry: RegistryConfig{Auth: RegistryAuthConfig{
			Mode:        "oidc",
			Username:    "robot$github-sts",
			PasswordEnv: "HARBOR_PASSWORD",
		}},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "registry.auth.mode") {
		t.Errorf("expected registry auth mode error, got: %v", err)
	}
}

func TestParsePrivateKeys_InvalidPEM(t *testing.T) {
	cfg := defaults()
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: "not-a-pem"}
	err := cfg.parsePrivateKeys()
	if err == nil || !contains(err.Error(), "invalid PEM") {
		t.Errorf("expected PEM error, got: %v", err)
	}
}

func TestValidate_PolicyResolution_DefaultsToOrgFirst(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.OrgPolicyRepo = ".github"
	cfg.Apps["test"] = app

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Apps["test"].PolicyResolution; got != "org_first" {
		t.Errorf("policy_resolution default = %q, want org_first", got)
	}
}

func TestValidate_PolicyResolution_UnknownValueRejected(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.OrgPolicyRepo = ".github"
	app.PolicyResolution = "bogus"
	cfg.Apps["test"] = app

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "policy_resolution") {
		t.Errorf("expected policy_resolution error, got: %v", err)
	}
}

func TestValidate_PolicyResolution_OrgFirstRequiresOrgRepo(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.PolicyResolution = "org_first" // no OrgPolicyRepo set
	cfg.Apps["test"] = app

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "requires org_policy_repo") {
		t.Errorf("expected org_policy_repo requirement error, got: %v", err)
	}
}

func TestValidate_PolicyResolution_OrgOnlyRequiresOrgRepo(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.PolicyResolution = "org_only"
	cfg.Apps["test"] = app

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "requires org_policy_repo") {
		t.Errorf("expected org_policy_repo requirement error, got: %v", err)
	}
}

func TestValidate_PolicyResolution_RepoFirstAllowedWithoutOrgRepo(t *testing.T) {
	// repo_first is meaningful even without an org repo (it just degenerates
	// to repo-only). Keep this allowed for parity with the legacy default.
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.PolicyResolution = "repo_first"
	cfg.Apps["test"] = app

	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_PolicyResolution_ExplicitOrgFirstAccepted(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.OrgPolicyRepo = ".github"
	app.PolicyResolution = "org_first"
	cfg.Apps["test"] = app

	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDefaultAppName_SingleApp(t *testing.T) {
	cfg := defaults()
	cfg.Apps["myapp"] = AppConfig{}
	if got := cfg.DefaultAppName(); got != "myapp" {
		t.Errorf("DefaultAppName() = %q, want myapp", got)
	}
}

func TestDefaultAppName_MultipleApps(t *testing.T) {
	cfg := defaults()
	cfg.Apps["app1"] = AppConfig{}
	cfg.Apps["app2"] = AppConfig{}
	if got := cfg.DefaultAppName(); got != "" {
		t.Errorf("DefaultAppName() = %q, want empty", got)
	}
}

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a, b, c", 3},
		{" , , ", 0},
		{"single", 1},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseCommaSeparated(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseCommaSeparated(%q) len = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
