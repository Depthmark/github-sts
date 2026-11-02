package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/oidc"
)

const testEnterpriseIssuer = oidc.GitHubActionsIssuer + "/octocat-inc"

func TestLoad_GitHubIssuers(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  deploy:
    app_id: 1
    private_key_path: "`+keyPath+`"
  other:
    app_id: 2
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "`+oidc.GitHubActionsIssuer+`"
    - "`+testEnterpriseIssuer+`"
  github_issuers:
    - issuer: "`+testEnterpriseIssuer+`"
      apps: ["deploy"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	issuers := cfg.GitHubIssuers()
	if len(issuers) != 1 {
		t.Fatalf("GitHubIssuers() len = %d, want 1", len(issuers))
	}
	got := issuers[0]
	if got.Issuer != testEnterpriseIssuer || got.Instance != oidc.GitHubDotComInstance || !slices.Equal(got.Apps, []string{"deploy"}) {
		t.Fatalf("GitHubIssuers()[0] = %+v", got)
	}
}

func TestLoad_NoGitHubIssuersByDefault(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  deploy:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "`+oidc.GitHubActionsIssuer+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if issuers := cfg.GitHubIssuers(); len(issuers) != 0 {
		t.Fatalf("GitHubIssuers() = %+v, want none", issuers)
	}
}

// A typo in the new block must stop the service, not silently drop an App list.
func TestLoad_GitHubIssuersUnknownFieldRejected(t *testing.T) {
	keyPath := writeTestKey(t)
	path := writeTestConfig(t, `
bundle_enforcement: optional
apps:
  deploy:
    app_id: 1
    private_key_path: "`+keyPath+`"
oidc:
  allowed_issuers:
    - "`+testEnterpriseIssuer+`"
  github_issuers:
    - issuer: "`+testEnterpriseIssuer+`"
      app: ["deploy"]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted an unknown field under oidc.github_issuers")
	}
}

func TestValidate_GitHubIssuers(t *testing.T) {
	const ghes = "https://github.example.com/_services/token"
	const gheCom = "https://token.actions.octocorp.ghe.com/octocorp"

	tests := []struct {
		name    string
		allowed []string
		issuers []GitHubIssuerConfig
		wantErr string
	}{
		{
			name:    "valid",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"default"}}},
		},
		{
			name:    "GitHub Enterprise Server issuer is not accepted yet",
			allowed: []string{ghes},
			issuers: []GitHubIssuerConfig{{Issuer: ghes, Apps: []string{"default"}}},
			wantErr: `oidc.github_issuers[0].issuer must be ` + oidc.GitHubActionsIssuer + `/<enterprise-slug> (got "` + ghes + `")`,
		},
		{
			name:    "GHE.com issuer is hosted outside GitHub.com",
			allowed: []string{gheCom},
			issuers: []GitHubIssuerConfig{{Issuer: gheCom, Apps: []string{"default"}}},
			wantErr: `oidc.github_issuers[0].issuer must be`,
		},
		{
			name:    "default issuer needs no declaration",
			allowed: []string{oidc.GitHubActionsIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: oidc.GitHubActionsIssuer, Apps: []string{"default"}}},
			wantErr: `oidc.github_issuers[0].issuer must be`,
		},
		{
			name:    "empty issuer",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Apps: []string{"default"}}},
			wantErr: `oidc.github_issuers[0].issuer must be`,
		},
		{
			name:    "missing from allowed_issuers",
			allowed: []string{oidc.GitHubActionsIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"default"}}},
			wantErr: `oidc.github_issuers[0].issuer must also be listed in oidc.allowed_issuers (got "` + testEnterpriseIssuer + `")`,
		},
		{
			name:    "unknown app",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"default", "missing"}}},
			wantErr: `oidc.github_issuers[0].apps references unknown app "missing"`,
		},
		{
			name:    "empty apps",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer}},
			wantErr: `oidc.github_issuers[0].apps must list at least one app`,
		},
		{
			name:    "empty app name",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{""}}},
			wantErr: `oidc.github_issuers[0].apps must not contain empty app names`,
		},
		{
			name:    "duplicate app",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{{Issuer: testEnterpriseIssuer, Apps: []string{"default", "default"}}},
			wantErr: `oidc.github_issuers[0].apps contains duplicate app "default"`,
		},
		{
			name:    "duplicate issuer names the second entry",
			allowed: []string{testEnterpriseIssuer},
			issuers: []GitHubIssuerConfig{
				{Issuer: testEnterpriseIssuer, Apps: []string{"default"}},
				{Issuer: testEnterpriseIssuer, Apps: []string{"default"}},
			},
			wantErr: `oidc.github_issuers[1].issuer duplicates an earlier issuer`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDefaults()
			cfg.Apps = map[string]AppConfig{"default": {AppID: 1, PrivateKeyPath: writeTestKey(t)}}
			cfg.OIDC.AllowedIssuers = tt.allowed
			cfg.OIDC.GitHubIssuers = tt.issuers

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
