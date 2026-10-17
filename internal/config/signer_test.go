package config

import (
	"strings"
	"testing"
)

const testKeyID = "https://example.vault.azure.net/keys/github-app"

// signerYAML wraps an apps block in the smallest configuration Load accepts.
func signerYAML(apps string) string {
	return `
bundle_enforcement: optional
apps:
` + apps + `
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
`
}

func TestLoad_SignerFlatForm(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, signerYAML(`
  default:
    app_id: 123456
    signer:
      provider: azure
      key_id: "`+testKeyID+`"
`)))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	inst := cfg.Apps["default"].Instances[0]
	if inst.Signer.Provider != "azure" || inst.Signer.KeyID != testKeyID {
		t.Errorf("Instances[0].Signer = %+v, want the flat signer", inst.Signer)
	}
	if inst.ParsedKey != nil {
		t.Error("an instance with a signer must hold no parsed private key")
	}
	if inst.Name != "123456" {
		t.Errorf("Instances[0].Name = %q, want the app_id", inst.Name)
	}
}

func TestLoad_SignerPerInstance(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, signerYAML(`
  checkout:
    instances:
      - name: checkout-1
        app_id: 111111
        signer:
          provider: azure
          key_id: "https://example.vault.azure.net/keys/checkout-1"
      - name: checkout-2
        app_id: 222222
        signer:
          provider: azure
          key_id: "https://example.vault.azure.net/keys/checkout-2"
`)))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for i, inst := range cfg.Apps["checkout"].Instances {
		if !inst.Signer.IsSet() || inst.ParsedKey != nil {
			t.Errorf("Instances[%d] = signer %+v, parsed key %v; want a signer and no key", i, inst.Signer, inst.ParsedKey != nil)
		}
	}
}

func TestLoad_SignerRejected(t *testing.T) {
	keyPath := writeTestKey(t)
	tests := []struct {
		name string
		apps string
		want []string
	}{
		{
			name: "no key source",
			apps: `
  default:
    app_id: 1
`,
			want: []string{`app "default"`, "one of private_key, private_key_path or signer is required"},
		},
		{
			name: "signer and a PEM path",
			apps: `
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
    signer:
      provider: azure
      key_id: "` + testKeyID + `"
`,
			want: []string{`app "default"`, "private_key_path and signer are mutually exclusive"},
		},
		{
			name: "signer and a PEM on an instance",
			apps: `
  checkout:
    instances:
      - name: checkout-1
        app_id: 1
        private_key: "inline"
        signer:
          provider: azure
          key_id: "` + testKeyID + `"
`,
			want: []string{`app "checkout": instance checkout-1`, "private_key and signer are mutually exclusive"},
		},
		{
			name: "no provider",
			apps: `
  default:
    app_id: 1
    signer:
      key_id: "` + testKeyID + `"
`,
			want: []string{`app "default"`, "signer.provider is required"},
		},
		{
			name: "unknown provider",
			apps: `
  default:
    app_id: 1
    signer:
      provider: vault
      key_id: "` + testKeyID + `"
`,
			want: []string{`app "default"`, `signer.provider must be one of azure (got "vault")`},
		},
		{
			name: "no key identifier",
			apps: `
  default:
    app_id: 1
    signer:
      provider: azure
`,
			want: []string{`app "default"`, "signer.key_id is required"},
		},
		{
			name: "flat signer beside instances",
			apps: `
  checkout:
    signer:
      provider: azure
      key_id: "` + testKeyID + `"
    instances:
      - app_id: 1
        signer:
          provider: azure
          key_id: "` + testKeyID + `"
`,
			want: []string{`app "checkout"`, "mutually exclusive"},
		},
		{
			name: "a vault key in one app and a PEM in another",
			apps: `
  deploy:
    app_id: 2
    private_key_path: "` + keyPath + `"
  release:
    app_id: 1
    signer:
      provider: azure
      key_id: "` + testKeyID + `"
`,
			want: []string{"never a mix", `app "release" instance "1" uses signer`, `app "deploy" instance "2" uses private_key_path`},
		},
		{
			name: "a vault key and a PEM in one pool",
			apps: `
  checkout:
    instances:
      - name: checkout-1
        app_id: 1
        signer:
          provider: azure
          key_id: "` + testKeyID + `"
      - name: checkout-2
        app_id: 2
        private_key: "inline"
`,
			want: []string{"never a mix", `instance "checkout-1" uses signer`, `instance "checkout-2" uses private_key`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTestConfig(t, signerYAML(tt.apps)))
			if err == nil {
				t.Fatal("Load() succeeded, want an error")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestLoad_SignerFromEnvironment(t *testing.T) {
	t.Run("flat", func(t *testing.T) {
		t.Setenv("GITHUBSTS_APP_DEFAULT_SIGNER_PROVIDER", "azure")
		t.Setenv("GITHUBSTS_APP_DEFAULT_SIGNER_KEY_ID", testKeyID)
		cfg, err := Load(writeTestConfig(t, signerYAML(`
  default:
    app_id: 123456
`)))
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if got := cfg.Apps["default"].Instances[0].Signer; got.Provider != "azure" || got.KeyID != testKeyID {
			t.Errorf("Signer = %+v, want the environment's", got)
		}
	})

	t.Run("instance", func(t *testing.T) {
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_APP_ID", "111111")
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_SIGNER_PROVIDER", "azure")
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_SIGNER_KEY_ID", testKeyID)
		cfg, err := Load(writeTestConfig(t, signerYAML(`
  checkout:
    org_policy_repo: ".github"
`)))
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		insts := cfg.Apps["checkout"].Instances
		if len(insts) != 1 || insts[0].Signer.KeyID != testKeyID || insts[0].AppID != 111111 {
			t.Errorf("Instances = %+v, want one instance with the environment's signer", insts)
		}
	})
}
