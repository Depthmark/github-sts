package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/signer"
	"github.com/depthmark/github-sts/internal/signer/azure"
)

const testVaultKeyID = "https://example.vault.azure.net/keys/checkout-1"

func settingsWithApps(apps map[string]config.AppConfig) *config.Settings {
	return &config.Settings{
		Server:            config.ServerConfig{Host: "127.0.0.1", Port: 8080, ShutdownTimeout: time.Second},
		Apps:              apps,
		OIDC:              config.OIDCConfig{AllowedIssuers: []string{"https://issuer.example.com"}},
		JTI:               config.JTIConfig{Backend: "memory", TTL: time.Minute},
		Policy:            config.PolicyConfig{BasePath: ".github/sts", CacheTTL: time.Minute},
		BundleEnforcement: config.BundleEnforcementOptional,
		Audit:             config.AuditConfig{BufferSize: 1},
	}
}

func vaultInstanceSettings() *config.Settings {
	return settingsWithApps(map[string]config.AppConfig{
		"checkout": {Instances: []config.AppInstanceConfig{{
			Name:   "checkout-1",
			AppID:  1,
			Signer: config.SignerConfig{Provider: signer.ProviderAzure, KeyID: testVaultKeyID},
		}}},
	})
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

type failingKey struct{ err error }

func (k failingKey) SignRS256(context.Context, []byte) ([]byte, error) { return nil, k.err }

// TestOpenAppCredentials_VaultKeyHoldsNoPrivateKey checks the step newServer
// takes before anything else touches GitHub. It calls openAppCredentials
// directly: a second successful newServer in this binary would register the
// Prometheus collectors twice.
func TestOpenAppCredentials_VaultKeyHoldsNoPrivateKey(t *testing.T) {
	vaultKey := signer.NewLocal(newTestRSAKey(t)) // stands in for the vault
	var opened []config.AppInstanceConfig
	openKey := func(inst config.AppInstanceConfig) (signer.Key, error) {
		opened = append(opened, inst)
		return vaultKey, nil
	}

	credentials, err := openAppCredentials(vaultInstanceSettings(), discardLogger(), openKey)
	if err != nil {
		t.Fatalf("openAppCredentials: %v", err)
	}

	if len(opened) != 1 || opened[0].Signer.KeyID != testVaultKeyID {
		t.Fatalf("opened %+v, want the one vault key", opened)
	}
	if opened[0].ParsedKey != nil {
		t.Fatal("a vault-backed instance reached the opener with a private key")
	}
	credential := credentials[appInstance{app: "checkout", instance: "checkout-1"}]
	if credential == nil || credential.AppID() != 1 {
		t.Fatalf("credentials = %v, want one source for checkout/checkout-1", credentials)
	}
}

func TestNewServer_RefusesToStart(t *testing.T) {
	tests := []struct {
		name    string
		openKey keyOpener
		want    []string
	}{
		{
			name: "the key cannot sign",
			openKey: func(config.AppInstanceConfig) (signer.Key, error) {
				return failingKey{err: errors.New("HTTP 403 Forbidden")}, nil
			},
			want: []string{`app "checkout" instance "checkout-1"`, `signer.key_id "` + testVaultKeyID + `" cannot sign`, "HTTP 403 Forbidden"},
		},
		{
			name: "the key cannot be opened",
			openKey: func(config.AppInstanceConfig) (signer.Key, error) {
				return nil, errors.New("signer: key_id is invalid")
			},
			want: []string{`app "checkout" instance "checkout-1"`, "signer: key_id is invalid"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newServer(vaultInstanceSettings(), discardLogger(), tt.openKey)
			if err == nil {
				t.Fatal("newServer succeeded, want an error")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestKeyOpener_OpensAPrivateKeyInProcess(t *testing.T) {
	key, err := newKeyOpener()(config.AppInstanceConfig{AppID: 1, ParsedKey: newTestRSAKey(t)})
	if err != nil {
		t.Fatalf("opening a PEM-backed instance: %v", err)
	}
	if _, ok := key.(*signer.Local); !ok {
		t.Fatalf("key = %T, want *signer.Local", key)
	}
}

func TestKeyOpener_HandlesEveryProvider(t *testing.T) {
	unsetCredentialType(t)
	for _, provider := range signer.Providers() {
		t.Run(provider, func(t *testing.T) {
			_, err := newKeyOpener()(config.AppInstanceConfig{
				AppID:  1,
				Signer: config.SignerConfig{Provider: provider, KeyID: testVaultKeyID},
			})
			if err != nil && strings.Contains(err.Error(), "is not supported") {
				t.Fatalf("provider %q is accepted by configuration but not opened by the server: %v", provider, err)
			}
		})
	}
}

func TestKeyOpener_AzureRejected(t *testing.T) {
	tests := []struct {
		name           string
		credentialType string
		keyID          string
		want           string
	}{
		{name: "no named credential", credentialType: "", keyID: testVaultKeyID, want: azure.TokenCredentialsEnv},
		{name: "a refused credential", credentialType: "AzureCLICredential", keyID: testVaultKeyID, want: azure.TokenCredentialsEnv},
		{name: "a secret, not a key", credentialType: "WorkloadIdentityCredential", keyID: "https://example.vault.azure.net/secrets/checkout-1", want: "key_id"},
		{name: "plain http", credentialType: "WorkloadIdentityCredential", keyID: "http://example.vault.azure.net/keys/checkout-1", want: "https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.credentialType == "" {
				unsetCredentialType(t)
			} else {
				t.Setenv(azure.TokenCredentialsEnv, tt.credentialType)
			}
			_, err := newKeyOpener()(config.AppInstanceConfig{
				AppID:  1,
				Signer: config.SignerConfig{Provider: signer.ProviderAzure, KeyID: tt.keyID},
			})
			if err == nil {
				t.Fatal("opening succeeded, want an error")
			}
			if !strings.Contains(err.Error(), "signer:") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q, want it to start with signer: and contain %q", err, tt.want)
			}
		})
	}
}

func unsetCredentialType(t *testing.T) {
	t.Helper()
	t.Setenv(azure.TokenCredentialsEnv, "")
	if err := os.Unsetenv(azure.TokenCredentialsEnv); err != nil {
		t.Fatalf("unsetting %s: %v", azure.TokenCredentialsEnv, err)
	}
}
