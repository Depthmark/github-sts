package config

import (
	"strings"
	"testing"
)

const (
	testKeyID    = "https://example.vault.azure.net/keys/github-app"
	testClientA  = "11111111-1111-1111-1111-111111111111"
	testClientB  = "22222222-2222-2222-2222-222222222222"
	testTenantID = "33333333-3333-3333-3333-333333333333"
)

// testIdentities defines the two cloud identities the signer tests name.
const testIdentities = `
cloud_identities:
  vault-one:
    azure:
      client_id: "` + testClientA + `"
      tenant_id: "` + testTenantID + `"
  vault-two:
    azure:
      client_id: "` + testClientB + `"
      tenant_id: "` + testTenantID + `"
`

// signerYAML wraps an apps block and any top-level blocks in the smallest
// configuration Load accepts.
func signerYAML(apps string, extra ...string) string {
	return `
bundle_enforcement: optional
apps:
` + apps + `
oidc:
  allowed_issuers:
    - "https://token.actions.githubusercontent.com"
` + strings.Join(extra, "\n")
}

// oneIdentity defines only vault-one, for tests whose keys all sign as it.
const oneIdentity = `
cloud_identities:
  vault-one:
    azure:
      client_id: "` + testClientA + `"
      tenant_id: "` + testTenantID + `"
`

func TestLoad_SignerFlatForm(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, signerYAML(`
  default:
    app_id: 123456
    signer:
      cloud_identity: vault-one
      key_id: "`+testKeyID+`"
`, oneIdentity)))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	inst := cfg.Apps["default"].Instances[0]
	if inst.Signer.CloudIdentity != "vault-one" || inst.Signer.KeyID != testKeyID {
		t.Errorf("Instances[0].Signer = %+v, want the flat signer", inst.Signer)
	}
	if inst.ParsedKey != nil {
		t.Error("an instance with a signer must hold no parsed private key")
	}
	if inst.Name != "123456" {
		t.Errorf("Instances[0].Name = %q, want the app_id", inst.Name)
	}
}

// TestLoad_SignerCloudIdentities checks that each key keeps the identity it
// names, in the flat form and per instance, and that each identity keeps its
// Azure fields and maps to the Azure provider.
func TestLoad_SignerCloudIdentities(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, signerYAML(`
  default:
    app_id: 123456
    signer:
      cloud_identity: vault-one
      key_id: "https://one.vault.azure.net/keys/default"
  checkout:
    instances:
      - name: checkout-1
        app_id: 111111
        signer:
          cloud_identity: vault-two
          key_id: "https://two.vault.azure.net/keys/checkout-1"
      - name: checkout-2
        app_id: 222222
        signer:
          cloud_identity: vault-one
          key_id: "https://one.vault.azure.net/keys/checkout-2"
`, testIdentities)))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	for _, tt := range []struct {
		app      string
		i        int
		identity string
	}{
		{"default", 0, "vault-one"},
		{"checkout", 0, "vault-two"},
		{"checkout", 1, "vault-one"},
	} {
		inst := cfg.Apps[tt.app].Instances[tt.i]
		if inst.Signer.CloudIdentity != tt.identity || inst.ParsedKey != nil {
			t.Errorf("%s instance %d: Signer %+v, parsed key %v; want identity %q and no key", tt.app, tt.i, inst.Signer, inst.ParsedKey != nil, tt.identity)
		}
	}
	two := cfg.CloudIdentities["vault-two"]
	if two.Azure == nil || two.Azure.ClientID != testClientB || two.Azure.TenantID != testTenantID {
		t.Errorf("cloud_identities.vault-two = %+v, want its client and tenant IDs", two.Azure)
	}
	if got := two.Provider(); got != "azure" {
		t.Errorf("Provider() = %q, want azure", got)
	}
}

func TestLoad_SignerRejected(t *testing.T) {
	keyPath := writeTestKey(t)
	tests := []struct {
		name  string
		apps  string
		extra string
		want  []string
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
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{`app "default"`, "private_key_path and signer are mutually exclusive"},
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
          cloud_identity: vault-one
          key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{`app "checkout": instance checkout-1`, "private_key and signer are mutually exclusive"},
		},
		{
			name: "no cloud identity",
			apps: `
  default:
    app_id: 1
    signer:
      key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{`app "default"`, "signer.cloud_identity is required"},
		},
		{
			name: "no key identifier",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
`,
			extra: oneIdentity,
			want:  []string{`app "default"`, "signer.key_id is required"},
		},
		{
			name: "the provider field of 0018",
			apps: `
  default:
    app_id: 1
    signer:
      provider: azure
      key_id: "` + testKeyID + `"
`,
			want: []string{"provider"},
		},
		{
			name: "an undefined cloud identity",
			apps: `
  checkout:
    instances:
      - name: checkout-1
        app_id: 1
        signer:
          cloud_identity: vault-three
          key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{`app "checkout": instance checkout-1`, `signer.cloud_identity "vault-three" is not defined`, "defined: vault-one"},
		},
		{
			name: "a cloud identity with no cloud_identities",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			want: []string{`app "default"`, `"vault-one" is not defined`, "cloud_identities is empty"},
		},
		{
			name: "an identity no signer names",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: testIdentities,
			want:  []string{"cloud_identities.vault-two", "no signer names this identity"},
		},
		{
			name: "an identity beside PEM keys",
			apps: `
  default:
    app_id: 1
    private_key_path: "` + keyPath + `"
`,
			extra: oneIdentity,
			want:  []string{"cloud_identities.vault-one", "no signer names this identity"},
		},
		{
			name: "an identity with no cloud",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: `
cloud_identities:
  vault-one: {}
`,
			want: []string{"cloud_identities.vault-one", "azure is required"},
		},
		{
			name: "an unknown cloud",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: `
cloud_identities:
  vault-one:
    aws:
      role_arn: "arn:aws:iam::123456789012:role/github-sts"
`,
			want: []string{"aws"},
		},
		{
			name: "an Azure identity with no client ID",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: `
cloud_identities:
  vault-one:
    azure:
      tenant_id: "` + testTenantID + `"
`,
			want: []string{"cloud_identities.vault-one", "azure.client_id is required"},
		},
		{
			name: "an Azure identity with no tenant ID",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: `
cloud_identities:
  vault-one:
    azure:
      client_id: "` + testClientA + `"
`,
			want: []string{"cloud_identities.vault-one", "azure.tenant_id is required"},
		},
		{
			name: "an identity name with a space",
			apps: `
  default:
    app_id: 1
    signer:
      cloud_identity: "vault one"
      key_id: "` + testKeyID + `"
`,
			extra: `
cloud_identities:
  "vault one":
    azure:
      client_id: "` + testClientA + `"
      tenant_id: "` + testTenantID + `"
`,
			want: []string{`cloud_identities.vault one`, "the name must be"},
		},
		{
			name: "flat signer beside instances",
			apps: `
  checkout:
    signer:
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
    instances:
      - app_id: 1
        signer:
          cloud_identity: vault-one
          key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{`app "checkout"`, "mutually exclusive"},
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
      cloud_identity: vault-one
      key_id: "` + testKeyID + `"
`,
			extra: oneIdentity,
			want:  []string{"never a mix", `app "release" instance "1" uses signer`, `app "deploy" instance "2" uses private_key_path`},
		},
		{
			name: "a vault key and a PEM in one pool",
			apps: `
  checkout:
    instances:
      - name: checkout-1
        app_id: 1
        signer:
          cloud_identity: vault-one
          key_id: "` + testKeyID + `"
      - name: checkout-2
        app_id: 2
        private_key: "inline"
`,
			extra: oneIdentity,
			want:  []string{"never a mix", `instance "checkout-1" uses signer`, `instance "checkout-2" uses private_key`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTestConfig(t, signerYAML(tt.apps, tt.extra)))
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

// TestLoad_SignerFromEnvironment checks that a signer can be set from the
// environment, naming an identity the YAML defines: cloud_identities itself
// has no environment form (ADR github-sts/0020).
func TestLoad_SignerFromEnvironment(t *testing.T) {
	t.Run("flat", func(t *testing.T) {
		t.Setenv("GITHUBSTS_APP_DEFAULT_SIGNER_CLOUD_IDENTITY", "vault-one")
		t.Setenv("GITHUBSTS_APP_DEFAULT_SIGNER_KEY_ID", testKeyID)
		cfg, err := Load(writeTestConfig(t, signerYAML(`
  default:
    app_id: 123456
`, oneIdentity)))
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if got := cfg.Apps["default"].Instances[0].Signer; got.CloudIdentity != "vault-one" || got.KeyID != testKeyID {
			t.Errorf("Signer = %+v, want the environment's", got)
		}
	})

	t.Run("instance", func(t *testing.T) {
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_APP_ID", "111111")
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_SIGNER_CLOUD_IDENTITY", "vault-one")
		t.Setenv("GITHUBSTS_APP_CHECKOUT_INSTANCE_1_SIGNER_KEY_ID", testKeyID)
		cfg, err := Load(writeTestConfig(t, signerYAML(`
  checkout:
    org_policy_repo: ".github"
`, oneIdentity)))
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		insts := cfg.Apps["checkout"].Instances
		if len(insts) != 1 || insts[0].Signer.KeyID != testKeyID || insts[0].Signer.CloudIdentity != "vault-one" || insts[0].AppID != 111111 {
			t.Errorf("Instances = %+v, want one instance with the environment's signer", insts)
		}
	})
}
