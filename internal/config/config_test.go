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
	if len(app.Instances) != 1 || app.Instances[0].ParsedKey == nil {
		t.Error("Instances[0].ParsedKey is nil")
	}

	if len(cfg.OIDC.AllowedIssuers) != 1 {
		t.Fatalf("allowed_issuers len = %d, want 1", len(cfg.OIDC.AllowedIssuers))
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
}

func TestLoad_EnvOverrides(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
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
	if cfg.JTI.TTL != 2*time.Hour {
		t.Errorf("jti.ttl = %v, want 2h", cfg.JTI.TTL)
	}
	if cfg.Audit.FileEnabled {
		t.Error("audit.file_enabled should be false from env override")
	}
}

func TestLoad_EnvOverrides_TLS(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
apps:
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
oidc:
  allowed_issuers:
    - "https://placeholder.example.com"
`
	path := writeTestConfig(t, yaml)

	t.Setenv("GITHUBSTS_SERVER_TLS_CERT_FILE", "/etc/tls/tls.crt")
	t.Setenv("GITHUBSTS_SERVER_TLS_KEY_FILE", "/etc/tls/tls.key")
	t.Setenv("GITHUBSTS_SERVER_TLS_CLIENT_CA_FILE", "/etc/tls/ca.crt")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.TLS.CertFile != "/etc/tls/tls.crt" {
		t.Errorf("tls.cert_file = %q, want /etc/tls/tls.crt", cfg.Server.TLS.CertFile)
	}
	if cfg.Server.TLS.KeyFile != "/etc/tls/tls.key" {
		t.Errorf("tls.key_file = %q, want /etc/tls/tls.key", cfg.Server.TLS.KeyFile)
	}
	if cfg.Server.TLS.ClientCAFile != "/etc/tls/ca.crt" {
		t.Errorf("tls.client_ca_file = %q, want /etc/tls/ca.crt", cfg.Server.TLS.ClientCAFile)
	}
}

// validDefaults returns a defaults() config with the minimum required
// fields populated to pass validation.
func validDefaults() *Settings {
	cfg := defaults()
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: testPEM}
	cfg.OIDC.AllowedIssuers = []string{"https://test.example.com"}
	return cfg
}

func TestValidate_NoApps(t *testing.T) {
	cfg := defaults()
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

func TestValidate_TLSCertWithoutKey(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "must be set together") {
		t.Errorf("expected cert/key together error, got: %v", err)
	}
}

func TestValidate_TLSKeyWithoutCert(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "must be set together") {
		t.Errorf("expected cert/key together error, got: %v", err)
	}
}

func TestValidate_TLSClientCAWithoutTLS(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.ClientCAFile = "/path/ca.crt"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "client_ca_file") {
		t.Errorf("expected client_ca_file requires TLS error, got: %v", err)
	}
}

func TestValidate_TLSValid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.ClientCAFile = "/path/ca.crt"
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_TLSMinVersionInvalid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.MinVersion = "1.1"
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "min_version") {
		t.Errorf("expected min_version error, got: %v", err)
	}
}

func TestValidate_TLSMinVersionTLS13Valid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.MinVersion = "1.3"
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_TLSCipherSuitesInvalid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.CipherSuites = []string{"NOT_A_REAL_SUITE"}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "cipher_suites") {
		t.Errorf("expected cipher_suites error, got: %v", err)
	}
}

func TestValidate_TLSCipherSuitesValid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.CipherSuites = []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_TLSCipherSuitesWithTLS13MinVersion(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.MinVersion = "1.3"
	cfg.Server.TLS.CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "cipher_suites") {
		t.Errorf("expected cipher_suites+min_version error, got: %v", err)
	}
}

func TestValidate_TLSReloadIntervalWithoutTLS(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.ReloadInterval = 30 * time.Second
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "reload_interval") {
		t.Errorf("expected reload_interval error, got: %v", err)
	}
}

func TestValidate_TLSReloadIntervalValid(t *testing.T) {
	cfg := validDefaults()
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	cfg.Server.TLS.ReloadInterval = 30 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerTLSMinVersion_Default(t *testing.T) {
	cfg := defaults()
	if got := cfg.Server.TLSMinVersion(); got != 0x0303 { // tls.VersionTLS12 = 0x0303
		t.Errorf("TLSMinVersion() = %#x, want TLS 1.2 (%#x)", got, uint16(0x0303))
	}
}

func TestServerTLSMinVersion_TLS13(t *testing.T) {
	cfg := defaults()
	cfg.Server.TLS.MinVersion = "1.3"
	if got := cfg.Server.TLSMinVersion(); got != 0x0304 { // tls.VersionTLS13 = 0x0304
		t.Errorf("TLSMinVersion() = %#x, want TLS 1.3 (%#x)", got, uint16(0x0304))
	}
}

func TestServerTLSCipherSuiteIDs_Empty(t *testing.T) {
	cfg := defaults()
	if ids := cfg.Server.TLSCipherSuiteIDs(); ids != nil {
		t.Errorf("expected nil IDs when no cipher suites configured, got %v", ids)
	}
}

func TestServerTLSCipherSuiteIDs_Known(t *testing.T) {
	cfg := defaults()
	cfg.Server.TLS.CipherSuites = []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}
	ids := cfg.Server.TLSCipherSuiteIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 cipher suite IDs, got %d", len(ids))
	}
	for i, id := range ids {
		if id == 0 {
			t.Errorf("cipher suite ID[%d] is zero (unknown name)", i)
		}
	}
}

func TestServerTLSEnabled(t *testing.T) {
	cfg := defaults()
	if cfg.Server.TLSEnabled() {
		t.Error("TLSEnabled() should be false when no cert/key configured")
	}
	cfg.Server.TLS.CertFile = "/path/tls.crt"
	if cfg.Server.TLSEnabled() {
		t.Error("TLSEnabled() should be false when only cert is configured")
	}
	cfg.Server.TLS.KeyFile = "/path/tls.key"
	if !cfg.Server.TLSEnabled() {
		t.Error("TLSEnabled() should be true when cert and key are configured")
	}
}

func TestServerClientAuthEnabled(t *testing.T) {
	cfg := defaults()
	if cfg.Server.ClientAuthEnabled() {
		t.Error("ClientAuthEnabled() should be false by default")
	}
	cfg.Server.TLS.ClientCAFile = "/path/ca.crt"
	if !cfg.Server.ClientAuthEnabled() {
		t.Error("ClientAuthEnabled() should be true when client CA is configured")
	}
}

func TestParsePrivateKeys_InvalidPEM(t *testing.T) {
	cfg := defaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{{AppID: 1, PrivateKey: "not-a-pem"}}}
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

// --- Multi-instance pool config (instances:/rotation:) ---

func TestLoad_LegacyFlatForm_NormalizesToPoolOfOne(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
apps:
  default:
    app_id: 12345
    private_key_path: "` + keyPath + `"
oidc:
  allowed_issuers:
    - "https://test.example.com"
`
	cfg, err := Load(writeTestConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	app := cfg.Apps["default"]
	if len(app.Instances) != 1 {
		t.Fatalf("Instances len = %d, want 1", len(app.Instances))
	}
	inst := app.Instances[0]
	if inst.AppID != 12345 {
		t.Errorf("Instances[0].AppID = %d, want 12345", inst.AppID)
	}
	if inst.Name != "12345" {
		t.Errorf("Instances[0].Name = %q, want %q (defaults to app_id)", inst.Name, "12345")
	}
	if inst.ParsedKey == nil {
		t.Error("Instances[0].ParsedKey is nil")
	}
	if app.Rotation.Strategy != "round_robin" {
		t.Errorf("Rotation.Strategy = %q, want round_robin", app.Rotation.Strategy)
	}
	if app.Rotation.MaxAttempts != 1 {
		t.Errorf("Rotation.MaxAttempts = %d, want 1 (min(len(instances),3))", app.Rotation.MaxAttempts)
	}
}

func TestLoad_InstancesForm_Parses(t *testing.T) {
	key1, key2 := writeTestKey(t), writeTestKey(t)
	yaml := `
apps:
  checkout:
    org_policy_repo: ".github"
    instances:
      - name: checkout-1
        app_id: 111111
        private_key_path: "` + key1 + `"
      - name: checkout-2
        app_id: 222222
        private_key_path: "` + key2 + `"
    rotation:
      strategy: round_robin
      max_attempts: 2
oidc:
  allowed_issuers:
    - "https://test.example.com"
`
	cfg, err := Load(writeTestConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	app := cfg.Apps["checkout"]
	if len(app.Instances) != 2 {
		t.Fatalf("Instances len = %d, want 2", len(app.Instances))
	}
	if app.Instances[0].Name != "checkout-1" || app.Instances[0].AppID != 111111 {
		t.Errorf("Instances[0] = %+v", app.Instances[0])
	}
	if app.Instances[1].Name != "checkout-2" || app.Instances[1].AppID != 222222 {
		t.Errorf("Instances[1] = %+v", app.Instances[1])
	}
	if app.Instances[0].ParsedKey == nil || app.Instances[1].ParsedKey == nil {
		t.Error("expected both instances to have a ParsedKey")
	}
	if app.Rotation.MaxAttempts != 2 {
		t.Errorf("Rotation.MaxAttempts = %d, want 2 (explicit)", app.Rotation.MaxAttempts)
	}
}

func TestValidate_FlatAndInstances_MutuallyExclusive(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{
		AppID:      1,
		PrivateKey: testPEM,
		Instances:  []AppInstanceConfig{{AppID: 2, PrivateKey: testPEM}},
	}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestValidate_Instances_MissingAppID(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{{PrivateKey: testPEM}}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "app_id is required") {
		t.Errorf("expected app_id error, got: %v", err)
	}
}

func TestValidate_Instances_BothKeyAndPath(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{
		{AppID: 1, PrivateKey: "x", PrivateKeyPath: "/y"},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestValidate_Instances_InvalidNameChars(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{
		{Name: "checkout 1;drop", AppID: 1, PrivateKey: testPEM},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "invalid characters") {
		t.Errorf("expected invalid-characters error, got: %v", err)
	}
}

func TestValidate_Instances_DuplicateAppIDWithinPool(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{
		{Name: "a", AppID: 1, PrivateKey: testPEM},
		{Name: "b", AppID: 1, PrivateKey: testPEM},
	}}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "duplicate app_id") {
		t.Errorf("expected duplicate app_id error, got: %v", err)
	}
}

func TestValidate_DuplicateAppIDAcrossPools_NotAnError(t *testing.T) {
	// The same app_id reused across two different logical apps must NOT
	// fail Validate() — only a within-pool duplicate is a hard error. This
	// guards the backward-compatibility argument that adding pooling
	// support cannot retroactively break an existing multi-app deployment
	// that happens to reuse an app_id across apps.
	cfg := validDefaults()
	cfg.Apps["app1"] = AppConfig{AppID: 1, PrivateKey: testPEM}
	cfg.Apps["app2"] = AppConfig{AppID: 1, PrivateKey: testPEM}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDuplicateAppIDWarnings_CrossPoolReuse(t *testing.T) {
	// validDefaults() seeds app "test" with app_id 1 — use a non-colliding
	// ID here so the warning is a clean, isolated 2-way collision.
	cfg := validDefaults()
	cfg.Apps["app1"] = AppConfig{AppID: 101, PrivateKey: testPEM}
	cfg.Apps["app2"] = AppConfig{AppID: 101, PrivateKey: testPEM}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg.normalizeInstances()

	warnings := cfg.DuplicateAppIDWarnings()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly 1", warnings)
	}
	if !contains(warnings[0], "app1") || !contains(warnings[0], "app2") {
		t.Errorf("warning = %q, want it to name both app1 and app2", warnings[0])
	}
}

func TestDuplicateAppIDWarnings_NoReuse(t *testing.T) {
	// validDefaults() already seeds app "test" with app_id 1, so pick
	// non-colliding IDs here.
	cfg := validDefaults()
	cfg.Apps["app1"] = AppConfig{AppID: 101, PrivateKey: testPEM}
	cfg.Apps["app2"] = AppConfig{AppID: 102, PrivateKey: testPEM}
	cfg.normalizeInstances()
	if warnings := cfg.DuplicateAppIDWarnings(); len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
}

func TestValidate_Rotation_RejectedOnFlatForm(t *testing.T) {
	cfg := validDefaults()
	app := cfg.Apps["test"]
	app.Rotation.Strategy = "round_robin"
	cfg.Apps["test"] = app

	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "rotation has no effect") {
		t.Errorf("expected rotation-without-instances error, got: %v", err)
	}
}

func TestValidate_Rotation_DefaultsAndMaxAttemptsCap(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{Instances: []AppInstanceConfig{
		{AppID: 1, PrivateKey: testPEM},
		{AppID: 2, PrivateKey: testPEM},
		{AppID: 3, PrivateKey: testPEM},
		{AppID: 4, PrivateKey: testPEM},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	app := cfg.Apps["test"]
	if app.Rotation.Strategy != "round_robin" {
		t.Errorf("Rotation.Strategy = %q, want round_robin default", app.Rotation.Strategy)
	}
	if app.Rotation.MaxAttempts != 3 {
		t.Errorf("Rotation.MaxAttempts = %d, want 3 (capped, 4 instances)", app.Rotation.MaxAttempts)
	}
}

func TestValidate_Rotation_InvalidStrategy(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{
		Instances: []AppInstanceConfig{{AppID: 1, PrivateKey: testPEM}},
		Rotation:  RotationConfig{Strategy: "bogus"},
	}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "rotation.strategy") {
		t.Errorf("expected rotation.strategy error, got: %v", err)
	}
}

func TestValidate_Rotation_RateLimitAwareAccepted(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{
		Instances: []AppInstanceConfig{{AppID: 1, PrivateKey: testPEM}},
		Rotation:  RotationConfig{Strategy: "rate_limit_aware"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_Rotation_MinRemainingPctOutOfRange(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{
		Instances: []AppInstanceConfig{{AppID: 1, PrivateKey: testPEM}},
		Rotation:  RotationConfig{MinRemainingPct: 100},
	}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "min_remaining_pct") {
		t.Errorf("expected min_remaining_pct error, got: %v", err)
	}
}

func TestValidate_Rotation_NegativeMaxAttempts(t *testing.T) {
	cfg := validDefaults()
	cfg.Apps["test"] = AppConfig{
		Instances: []AppInstanceConfig{{AppID: 1, PrivateKey: testPEM}},
		Rotation:  RotationConfig{MaxAttempts: -1},
	}
	err := cfg.Validate()
	if err == nil || !contains(err.Error(), "max_attempts") {
		t.Errorf("expected max_attempts error, got: %v", err)
	}
}

func TestLoad_EnvOverrides_IndexedInstances(t *testing.T) {
	keyPath := writeTestKey(t)
	yaml := `
apps:
  checkout: {}
oidc:
  allowed_issuers:
    - "https://test.example.com"
`
	path := writeTestConfig(t, yaml)

	t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_APP_ID", "111111")
	t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_PRIVATE_KEY_PATH", keyPath)
	t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_NAME", "checkout-1")
	t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_2_APP_ID", "222222")
	t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_2_PRIVATE_KEY_PATH", keyPath)
	t.Setenv("GITHUBSTS_APP_CHECKOUT_ROTATION_STRATEGY", "round_robin")
	t.Setenv("GITHUBSTS_APP_CHECKOUT_ROTATION_MAX_ATTEMPTS", "2")
	t.Setenv("GITHUBSTS_APP_CHECKOUT_ROTATION_MIN_REMAINING_PCT", "5")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	app := cfg.Apps["checkout"]
	if len(app.Instances) != 2 {
		t.Fatalf("Instances len = %d, want 2", len(app.Instances))
	}
	if app.Instances[0].AppID != 111111 || app.Instances[0].Name != "checkout-1" {
		t.Errorf("Instances[0] = %+v", app.Instances[0])
	}
	if app.Instances[1].AppID != 222222 {
		t.Errorf("Instances[1] = %+v", app.Instances[1])
	}
	if app.Rotation.MaxAttempts != 2 {
		t.Errorf("Rotation.MaxAttempts = %d, want 2", app.Rotation.MaxAttempts)
	}
	if app.Rotation.MinRemainingPct != 5 {
		t.Errorf("Rotation.MinRemainingPct = %v, want 5", app.Rotation.MinRemainingPct)
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
