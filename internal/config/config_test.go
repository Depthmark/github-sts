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
	if app.ParsedKey == nil {
		t.Error("ParsedKey is nil")
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

func TestParsePrivateKeys_InvalidPEM(t *testing.T) {
	cfg := defaults()
	cfg.Apps["test"] = AppConfig{AppID: 1, PrivateKey: "not-a-pem"}
	err := cfg.parsePrivateKeys()
	if err == nil || !contains(err.Error(), "invalid PEM") {
		t.Errorf("expected PEM error, got: %v", err)
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
