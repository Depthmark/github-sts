package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/signer"
	"github.com/depthmark/github-sts/internal/signer/azure"
)

const (
	testVaultKeyID = "https://example.vault.azure.net/keys/checkout-1"
	testClientID   = "11111111-1111-1111-1111-111111111111"
	testTenantID   = "33333333-3333-3333-3333-333333333333"
)

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
	cfg := settingsWithApps(map[string]config.AppConfig{
		"checkout": {Instances: []config.AppInstanceConfig{{
			Name:   "checkout-1",
			AppID:  1,
			Signer: config.SignerConfig{CloudIdentity: "vault-one", KeyID: testVaultKeyID},
		}}},
	})
	cfg.CloudIdentities = testIdentities(testClientID, testTenantID)
	return cfg
}

// testIdentities defines the one cloud identity vault-one.
func testIdentities(clientID, tenantID string) map[string]config.CloudIdentityConfig {
	return map[string]config.CloudIdentityConfig{
		"vault-one": {Azure: &config.AzureIdentityConfig{ClientID: clientID, TenantID: tenantID}},
	}
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
	key, err := newKeyOpener(nil)(config.AppInstanceConfig{AppID: 1, ParsedKey: newTestRSAKey(t)})
	if err != nil {
		t.Fatalf("opening a PEM-backed instance: %v", err)
	}
	if _, ok := key.(*signer.Local); !ok {
		t.Fatalf("key = %T, want *signer.Local", key)
	}
}

// TestKeyOpener_OpensAnAzureIdentity opens a vault key as the identity its
// signer names. Opening contacts no cloud: the token file is read and
// exchanged at the first signature.
func TestKeyOpener_OpensAnAzureIdentity(t *testing.T) {
	t.Setenv(azure.FederatedTokenFileEnv, writeTokenFile(t))
	key, err := newKeyOpener(testIdentities(testClientID, testTenantID))(config.AppInstanceConfig{
		AppID:  1,
		Signer: config.SignerConfig{CloudIdentity: "vault-one", KeyID: testVaultKeyID},
	})
	if err != nil {
		t.Fatalf("opening a vault key: %v", err)
	}
	if _, ok := key.(*azure.Key); !ok {
		t.Fatalf("key = %T, want *azure.Key", key)
	}
}

func TestKeyOpener_AzureRejected(t *testing.T) {
	tests := []struct {
		name      string
		tokenFile bool
		identity  string
		clientID  string
		tenantID  string
		keyID     string
		want      string
	}{
		{name: "no federated token file", clientID: testClientID, tenantID: testTenantID, keyID: testVaultKeyID, want: azure.FederatedTokenFileEnv},
		{name: "a secret, not a key", tokenFile: true, clientID: testClientID, tenantID: testTenantID, keyID: "https://example.vault.azure.net/secrets/checkout-1", want: "key_id"},
		{name: "plain http", tokenFile: true, clientID: testClientID, tenantID: testTenantID, keyID: "http://example.vault.azure.net/keys/checkout-1", want: "https"},
		{name: "an identity by name, not client ID", tokenFile: true, clientID: "id-github-sts-dev", tenantID: testTenantID, keyID: testVaultKeyID, want: "client ID"},
		{name: "a tenant by domain, not ID", tokenFile: true, clientID: testClientID, tenantID: "stsexample.onmicrosoft.com", keyID: testVaultKeyID, want: "tenant ID"},
		{name: "an identity Load would refuse", tokenFile: true, identity: "vault-two", keyID: testVaultKeyID, want: `"vault-two" names no cloud`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tokenFile {
				t.Setenv(azure.FederatedTokenFileEnv, writeTokenFile(t))
			} else {
				unsetTokenFile(t)
			}
			identity := tt.identity
			if identity == "" {
				identity = "vault-one"
			}
			_, err := newKeyOpener(testIdentities(tt.clientID, tt.tenantID))(config.AppInstanceConfig{
				AppID:  1,
				Signer: config.SignerConfig{CloudIdentity: identity, KeyID: tt.keyID},
			})
			if err == nil {
				t.Fatal("opening succeeded, want an error")
			}
			if !strings.HasPrefix(err.Error(), "signer") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q, want it to start with signer and contain %q", err, tt.want)
			}
		})
	}
}

// writeTokenFile writes a stand-in projected service account token. Nothing
// reads it before a signature, and no test signs against Azure.
func writeTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("not-a-real-token"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	return path
}

func unsetTokenFile(t *testing.T) {
	t.Helper()
	t.Setenv(azure.FederatedTokenFileEnv, "")
	if err := os.Unsetenv(azure.FederatedTokenFileEnv); err != nil {
		t.Fatalf("unsetting %s: %v", azure.FederatedTokenFileEnv, err)
	}
}
