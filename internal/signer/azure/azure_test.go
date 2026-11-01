package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/depthmark/github-sts/internal/signer"
)

func TestParseKeyID_Accepted(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want KeyID
	}{
		{
			name: "current version",
			raw:  "https://example.vault.azure.net/keys/github-app",
			want: KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"},
		},
		{
			name: "pinned version",
			raw:  "https://example.vault.azure.net/keys/github-app/0123456789abcdef0123456789abcdef",
			want: KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app", Version: "0123456789abcdef0123456789abcdef"},
		},
		{
			name: "trailing slash",
			raw:  "https://example.vault.azure.net/keys/github-app/",
			want: KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"},
		},
		{
			name: "managed HSM",
			raw:  "https://example.managedhsm.azure.net/keys/github-app",
			want: KeyID{VaultURL: "https://example.managedhsm.azure.net", Name: "github-app"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyID(tt.raw)
			if err != nil {
				t.Fatalf("ParseKeyID(%q): %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("ParseKeyID(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseKeyID_Rejected(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "plain http", raw: "http://example.vault.azure.net/keys/github-app"},
		{name: "no scheme", raw: "example.vault.azure.net/keys/github-app"},
		{name: "user information", raw: "https://user:pass@example.vault.azure.net/keys/github-app"},
		{name: "query", raw: "https://example.vault.azure.net/keys/github-app?api-version=7.4"},
		{name: "fragment", raw: "https://example.vault.azure.net/keys/github-app#v1"},
		{name: "a secret, not a key", raw: "https://example.vault.azure.net/secrets/github-app"},
		{name: "no key name", raw: "https://example.vault.azure.net/keys"},
		{name: "too many segments", raw: "https://example.vault.azure.net/keys/github-app/v1/extra"},
		{name: "invalid key name", raw: "https://example.vault.azure.net/keys/github_app"},
		{name: "invalid version", raw: "https://example.vault.azure.net/keys/github-app/v-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ParseKeyID(tt.raw); err == nil {
				t.Fatalf("ParseKeyID(%q) = %+v, want an error", tt.raw, got)
			}
		})
	}
}

func TestKeyID_StringRoundTrips(t *testing.T) {
	for _, raw := range []string{
		"https://example.vault.azure.net/keys/github-app",
		"https://example.vault.azure.net/keys/github-app/0123456789abcdef0123456789abcdef",
	} {
		id, err := ParseKeyID(raw)
		if err != nil {
			t.Fatalf("ParseKeyID(%q): %v", raw, err)
		}
		if got := id.String(); got != raw {
			t.Errorf("String() = %q, want %q", got, raw)
		}
	}
}

func TestNewProvider_NeedsTheFederatedTokenFile(t *testing.T) {
	tests := []struct {
		name    string
		value   *string
		wantErr bool
	}{
		{name: "unset", value: nil, wantErr: true},
		{name: "empty", value: ptr(""), wantErr: true},
		{name: "only spaces", value: ptr("  "), wantErr: true},
		{name: "a path", value: ptr("/var/run/secrets/github-sts-azure/token")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setTokenFile(t, tt.value)
			_, err := NewProvider()
			switch {
			case tt.wantErr && (err == nil || !strings.Contains(err.Error(), FederatedTokenFileEnv)):
				t.Fatalf("NewProvider: error = %v, want one naming %s", err, FederatedTokenFileEnv)
			case !tt.wantErr && err != nil:
				t.Fatalf("NewProvider: %v", err)
			}
		})
	}
}

const (
	identityA   = "11111111-1111-1111-1111-111111111111"
	identityB   = "22222222-2222-2222-2222-222222222222"
	tenantT     = "33333333-3333-3333-3333-333333333333"
	otherTenant = "44444444-4444-4444-4444-444444444444"
)

func TestProvider_OneClientPerVault(t *testing.T) {
	p := newProvider(fixedCredential(staticCredential{}), azkeys.ClientOptions{})
	for _, keyID := range []string{
		"https://one.vault.azure.net/keys/dev",
		"https://one.vault.azure.net/keys/production",
		"https://two.vault.azure.net/keys/dev",
	} {
		if _, err := p.Key(keyID, identityA, tenantT); err != nil {
			t.Fatalf("Key(%q): %v", keyID, err)
		}
	}
	if got := len(p.clients); got != 2 {
		t.Fatalf("clients = %d, want 2 (one per vault)", got)
	}
}

func TestParseIdentity_Accepted(t *testing.T) {
	tests := []struct {
		name               string
		clientID, tenantID string
		want               Identity
	}{
		{name: "lower case", clientID: identityA, tenantID: tenantT, want: Identity{ClientID: identityA, TenantID: tenantT}},
		{
			name:     "upper case is lowered",
			clientID: "AAAAAAAA-0000-4000-8000-0000000000FF",
			tenantID: "BBBBBBBB-0000-4000-8000-0000000000FF",
			want:     Identity{ClientID: "aaaaaaaa-0000-4000-8000-0000000000ff", TenantID: "bbbbbbbb-0000-4000-8000-0000000000ff"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIdentity(tt.clientID, tt.tenantID)
			if err != nil || got != tt.want {
				t.Fatalf("ParseIdentity(%q, %q) = %+v, %v; want %+v", tt.clientID, tt.tenantID, got, err, tt.want)
			}
		})
	}
}

func TestParseIdentity_Rejected(t *testing.T) {
	tests := []struct {
		name                     string
		clientID, tenantID, want string
	}{
		{name: "an identity's name", clientID: "id-github-sts-dev", tenantID: tenantT, want: "client ID"},
		{name: "a GUID without dashes", clientID: "11111111111111111111111111111111", tenantID: tenantT, want: "client ID"},
		{name: "a GUID in braces", clientID: "{11111111-1111-1111-1111-111111111111}", tenantID: tenantT, want: "client ID"},
		{name: "a leading space", clientID: " 11111111-1111-1111-1111-111111111111", tenantID: tenantT, want: "client ID"},
		{name: "no client ID", clientID: "", tenantID: tenantT, want: "client ID"},
		{name: "a tenant's domain", clientID: identityA, tenantID: "contoso.onmicrosoft.com", want: "tenant ID, a GUID"},
		{name: "no tenant ID", clientID: identityA, tenantID: "", want: "tenant ID, a GUID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseIdentity(tt.clientID, tt.tenantID); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseIdentity(%q, %q) error = %v, want one containing %q", tt.clientID, tt.tenantID, err, tt.want)
			}
		})
	}
}

// TestProvider_OneCredentialPerIdentity checks that the keys of one identity
// share its credential, whatever the vault and however its GUIDs are spelt,
// that the same client ID in another tenant is another identity, and that
// each vault and identity gets its own client.
func TestProvider_OneCredentialPerIdentity(t *testing.T) {
	built := map[Identity]int{}
	p := newProvider(func(id Identity) (azcore.TokenCredential, error) {
		built[id]++
		return staticCredential{}, nil
	}, azkeys.ClientOptions{})
	for _, k := range []struct{ keyID, clientID, tenantID string }{
		{"https://one.vault.azure.net/keys/a", identityA, tenantT},
		{"https://two.vault.azure.net/keys/b", identityA, tenantT},
		{"https://two.vault.azure.net/keys/c", strings.ToUpper(identityA), tenantT},
		{"https://two.vault.azure.net/keys/d", identityB, tenantT},
		{"https://three.vault.azure.net/keys/e", identityA, otherTenant},
		{"https://three.vault.azure.net/keys/f", identityA, strings.ToUpper(otherTenant)},
	} {
		if _, err := p.Key(k.keyID, k.clientID, k.tenantID); err != nil {
			t.Fatalf("Key(%q, %q, %q): %v", k.keyID, k.clientID, k.tenantID, err)
		}
	}
	want := []Identity{{ClientID: identityA, TenantID: tenantT}, {ClientID: identityB, TenantID: tenantT}, {ClientID: identityA, TenantID: otherTenant}}
	if len(built) != len(want) {
		t.Fatalf("credentials built = %v, want one each for %v", built, want)
	}
	for _, id := range want {
		if built[id] != 1 {
			t.Errorf("credentials built for %v = %d, want 1", id, built[id])
		}
	}
	if got := len(p.clients); got != 4 {
		t.Errorf("clients = %d, want 4 (one per vault and identity)", got)
	}
}

func TestProvider_KeyRejectsAnInvalidIdentity(t *testing.T) {
	tests := []struct {
		name               string
		clientID, tenantID string
	}{
		{name: "an identity's name", clientID: "id-github-sts-dev", tenantID: tenantT},
		{name: "no client ID", clientID: "", tenantID: tenantT},
		{name: "no tenant ID", clientID: identityA, tenantID: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProvider(fixedCredential(staticCredential{}), azkeys.ClientOptions{})
			if _, err := p.Key("https://example.vault.azure.net/keys/github-app", tt.clientID, tt.tenantID); err == nil {
				t.Fatalf("Key accepted identity %q in tenant %q", tt.clientID, tt.tenantID)
			}
			if len(p.creds) != 0 || len(p.clients) != 0 {
				t.Errorf("credentials = %d, clients = %d, want none built for a refused identity", len(p.creds), len(p.clients))
			}
		})
	}
}

func TestProvider_NamesTheIdentityWhoseCredentialFailed(t *testing.T) {
	p := newProvider(func(Identity) (azcore.TokenCredential, error) {
		return nil, errors.New("no token file")
	}, azkeys.ClientOptions{})
	_, err := p.Key("https://example.vault.azure.net/keys/github-app", identityA, tenantT)
	if err == nil || !strings.Contains(err.Error(), identityA+" in tenant "+tenantT) || !strings.Contains(err.Error(), "no token file") {
		t.Fatalf("error = %v, want it to name the identity and its tenant and keep the cause", err)
	}
}

// TestWorkloadIdentity_BuildsWithNoAzureVariable builds a credential with
// every Azure variable unset: the SDK cannot build one from the environment
// alone, so github-sts supplies everything it needs.
func TestWorkloadIdentity_BuildsWithNoAzureVariable(t *testing.T) {
	unsetEnv(t, "AZURE_CLIENT_ID")
	unsetEnv(t, "AZURE_TENANT_ID")
	unsetEnv(t, FederatedTokenFileEnv)
	build := workloadIdentity(azidentity.WorkloadIdentityCredentialOptions{TokenFilePath: "/var/run/secrets/github-sts-azure/token"})
	if _, err := build(Identity{ClientID: identityA, TenantID: tenantT}); err != nil {
		t.Fatalf("workload identity %s in tenant %s: %v", identityA, tenantT, err)
	}
}

// TestWorkloadIdentity_ConfiguredIdentityWinsOverTheEnvironment sets the
// variables the Azure workload identity webhook injects to another identity,
// tenant and token file, and checks against a fake Microsoft Entra ID that
// the token exchange still names the configured client ID and tenant and
// presents the configured token (ADR github-sts/0020: no default identity).
func TestWorkloadIdentity_ConfiguredIdentityWinsOverTheEnvironment(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", identityB)
	t.Setenv("AZURE_TENANT_ID", otherTenant)
	t.Setenv(FederatedTokenFileEnv, filepath.Join(t.TempDir(), "webhook-token"))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("projected-service-account-token"), 0o600); err != nil {
		t.Fatalf("writing the token file: %v", err)
	}

	entra := &fakeEntra{t: t}
	srv := httptest.NewTLSServer(entra)
	defer srv.Close()
	entra.base = srv.URL

	build := workloadIdentity(azidentity.WorkloadIdentityCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: srv.URL + "/"},
			Transport: srv.Client(),
		},
		DisableInstanceDiscovery: true,
		TokenFilePath:            tokenFile,
	})
	cred, err := build(Identity{ClientID: identityA, TenantID: tenantT})
	if err != nil {
		t.Fatalf("building the credential: %v", err)
	}
	if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}}); err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	entra.mu.Lock()
	defer entra.mu.Unlock()
	if entra.exchanges != 1 {
		t.Fatalf("token exchanges = %d, want 1", entra.exchanges)
	}
	if entra.tenant != tenantT {
		t.Errorf("exchanged in tenant %q, want the configured %q, not AZURE_TENANT_ID", entra.tenant, tenantT)
	}
	if got := entra.form.Get("client_id"); got != identityA {
		t.Errorf("client_id = %q, want the configured %q, not AZURE_CLIENT_ID", got, identityA)
	}
	if got := entra.form.Get("client_assertion"); got != "projected-service-account-token" {
		t.Errorf("client_assertion = %q, want the configured token file's content, not AZURE_FEDERATED_TOKEN_FILE's", got)
	}
}

// TestProvider_CachesNothingWhenTheClientFails checks that a Key whose vault
// client cannot be built leaves neither its credential nor a client behind,
// so every cached credential has a client.
func TestProvider_CachesNothingWhenTheClientFails(t *testing.T) {
	p := newProvider(fixedCredential(staticCredential{}), azkeys.ClientOptions{})
	p.newClient = func(string, azcore.TokenCredential, *azkeys.ClientOptions) (signClient, error) {
		return nil, errors.New("no client for this vault")
	}
	_, err := p.Key("https://example.vault.azure.net/keys/github-app", identityA, tenantT)
	if err == nil || !strings.Contains(err.Error(), "no client for this vault") {
		t.Fatalf("error = %v, want the client's failure", err)
	}
	if len(p.creds) != 0 || len(p.clients) != 0 {
		t.Errorf("credentials = %d, clients = %d, want none after a failed Key", len(p.creds), len(p.clients))
	}
}

func TestKey_SignRS256_NamesItsIdentity(t *testing.T) {
	k := &Key{
		id:       KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"},
		identity: Identity{ClientID: identityA, TenantID: tenantT},
		client:   &fakeSignClient{err: vaultError(http.StatusForbidden, "Forbidden", "Caller is not authorized to perform action on resource.")},
	}
	digest := sha256.Sum256([]byte("header.claims"))
	_, err := k.SignRS256(context.Background(), digest[:])
	if want := "as identity " + identityA + " in tenant " + tenantT; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want one containing %q", err, want)
	}
}

func TestProvider_KeyRejectsAnInvalidIdentifier(t *testing.T) {
	p := newProvider(fixedCredential(staticCredential{}), azkeys.ClientOptions{})
	if _, err := p.Key("https://example.vault.azure.net/secrets/github-app", identityA, tenantT); err == nil {
		t.Fatal("Key accepted a secret identifier")
	}
}

func TestKey_SignRS256_SendsTheDigestWithRS256(t *testing.T) {
	appKey := newRSAKey(t)
	fake := &fakeSignClient{key: appKey}
	k := &Key{id: KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app", Version: "v1"}, client: fake}
	digest := sha256.Sum256([]byte("header.claims"))

	sig, err := k.SignRS256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&appKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if fake.name != "github-app" || fake.version != "v1" {
		t.Errorf("signed with %s/%s, want github-app/v1", fake.name, fake.version)
	}
	if fake.alg != azkeys.SignatureAlgorithmRS256 {
		t.Errorf("algorithm = %q, want RS256", fake.alg)
	}
	if !bytes.Equal(fake.value, digest[:]) {
		t.Error("the vault did not receive the digest")
	}
}

func TestKey_SignRS256_Rejected(t *testing.T) {
	digest := sha256.Sum256([]byte("header.claims"))
	tests := []struct {
		name    string
		digest  []byte
		client  *fakeSignClient
		wantErr string
	}{
		{name: "digest of the wrong size", digest: digest[:20], client: &fakeSignClient{}, wantErr: "SHA-256"},
		{name: "no signature returned", digest: digest[:], client: &fakeSignClient{empty: true}, wantErr: "returned no signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{id: KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"}, client: tt.client}
			_, err := k.SignRS256(context.Background(), tt.digest)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestKey_SignRS256_ExplainsAVaultRefusal(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		code     string
		message  string
		wantHint string
	}{
		{
			name:     "no sign permission",
			status:   http.StatusForbidden,
			code:     "Forbidden",
			message:  "Caller is not authorized to perform action on resource.\r\nAction: 'Microsoft.KeyVault/vaults/keys/sign/action'",
			wantHint: "lacks the sign permission",
		},
		{name: "unknown key", status: http.StatusNotFound, code: "KeyNotFound", message: "A key with (name/id) github-app was not found in this key vault.", wantHint: "does not exist"},
		{name: "not an RSA key", status: http.StatusBadRequest, code: "BadParameter", message: "Key and signing algorithm are incompatible.", wantHint: "cannot sign RS256"},
		{name: "throttled", status: http.StatusTooManyRequests, code: "Throttled", message: "Request was not processed because too many requests were received.", wantHint: "throttling"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				id:     KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"},
				client: &fakeSignClient{err: vaultError(tt.status, tt.code, tt.message)},
			}
			digest := sha256.Sum256([]byte("header.claims"))
			_, err := k.SignRS256(context.Background(), digest[:])
			if err == nil {
				t.Fatal("SignRS256 succeeded, want an error")
			}
			msg := err.Error()
			for _, want := range []string{"https://example.vault.azure.net/keys/github-app", tt.code, tt.wantHint} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not contain %q", msg, want)
				}
			}
			if strings.ContainsAny(msg, "\r\n") {
				t.Errorf("error %q spans several lines", msg)
			}
			var respErr *azcore.ResponseError
			if !errors.As(err, &respErr) || respErr.StatusCode != tt.status {
				t.Errorf("errors.As(*azcore.ResponseError) lost the status %d", tt.status)
			}
		})
	}
}

func TestKey_SignRS256_KeepsTheCauseOfAFailureWithoutResponse(t *testing.T) {
	k := &Key{
		id:     KeyID{VaultURL: "https://example.vault.azure.net", Name: "github-app"},
		client: &fakeSignClient{err: context.DeadlineExceeded},
	}
	digest := sha256.Sum256([]byte("header.claims"))
	_, err := k.SignRS256(context.Background(), digest[:])
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

// TestKey_SignRS256_AgainstAFakeVault drives the real SDK client against a
// local server shaped like Key Vault: the authentication challenge, the
// request path and body, and the response the SDK decodes.
func TestKey_SignRS256_AgainstAFakeVault(t *testing.T) {
	appKey := newRSAKey(t)
	vault := &fakeVault{t: t, key: appKey}
	srv := httptest.NewTLSServer(vault)
	defer srv.Close()

	cred := &recordingCredential{token: "test-access-token"}
	p := newProvider(fixedCredential(cred), azkeys.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: srv.Client()},
		DisableChallengeResourceVerification: true,
	})
	k, err := p.Key(srv.URL+"/keys/github-app/v1", identityA, tenantT)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}

	digest := sha256.Sum256([]byte("header.claims"))
	sig, err := k.SignRS256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&appKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if vault.signs != 1 {
		t.Errorf("sign requests = %d, want 1", vault.signs)
	}
	if !vault.sawBearer {
		t.Error("the sign request did not carry the credential's token")
	}
	if len(cred.scopes) == 0 || cred.scopes[0] != "https://vault.azure.net/.default" {
		t.Errorf("token scopes = %v, want the vault scope from the challenge", cred.scopes)
	}
}

// TestKey_SignRS256_AsItsIdentity checks against the fake vault that two keys
// in one vault, naming two identities, each get their token from their own
// identity's credential.
func TestKey_SignRS256_AsItsIdentity(t *testing.T) {
	appKey := newRSAKey(t)
	vault := &fakeVault{t: t, key: appKey}
	srv := httptest.NewTLSServer(vault)
	defer srv.Close()

	creds := map[Identity]*recordingCredential{}
	p := newProvider(func(id Identity) (azcore.TokenCredential, error) {
		c := &recordingCredential{token: "token-for-" + id.ClientID}
		creds[id] = c
		return c, nil
	}, azkeys.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: srv.Client()},
		DisableChallengeResourceVerification: true,
	})
	if _, err := p.Key(srv.URL+"/keys/github-app-a/v1", identityA, tenantT); err != nil {
		t.Fatalf("Key as %s: %v", identityA, err)
	}
	k, err := p.Key(srv.URL+"/keys/github-app/v1", identityB, tenantT)
	if err != nil {
		t.Fatalf("Key as %s: %v", identityB, err)
	}
	digest := sha256.Sum256([]byte("header.claims"))
	if _, err := k.SignRS256(context.Background(), digest[:]); err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if c := creds[Identity{ClientID: identityA, TenantID: tenantT}]; c == nil || len(c.scopes) != 0 {
		t.Errorf("identity %s's credential was asked for a token for a key of %s", identityA, identityB)
	}
	if c := creds[Identity{ClientID: identityB, TenantID: tenantT}]; c == nil || len(c.scopes) == 0 {
		t.Errorf("identity %s's credential was not asked for a token", identityB)
	}
}

// fixedCredential builds the same credential for every identity.
func fixedCredential(cred azcore.TokenCredential) credentialFunc {
	return func(Identity) (azcore.TokenCredential, error) { return cred, nil }
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unsetting %s: %v", name, err)
	}
}

// setTokenFile sets FederatedTokenFileEnv to value, or unsets it for nil.
func setTokenFile(t *testing.T, value *string) {
	t.Helper()
	if value == nil {
		unsetEnv(t, FederatedTokenFileEnv)
		return
	}
	t.Setenv(FederatedTokenFileEnv, *value)
}

func ptr(s string) *string { return &s }

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

// vaultError builds the error the SDK returns for a Key Vault error response.
func vaultError(status int, code, message string) error {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    &http.Request{Method: http.MethodPost, URL: mustParseURL("https://example.vault.azure.net/keys/github-app/sign")},
	}
	return runtime.NewResponseError(resp)
}

type fakeSignClient struct {
	key   *rsa.PrivateKey
	err   error
	empty bool

	name, version string
	alg           azkeys.SignatureAlgorithm
	value         []byte
}

func (f *fakeSignClient) Sign(_ context.Context, name, version string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.name, f.version, f.value = name, version, params.Value
	if params.Algorithm != nil {
		f.alg = *params.Algorithm
	}
	if f.err != nil {
		return azkeys.SignResponse{}, f.err
	}
	if f.empty {
		return azkeys.SignResponse{}, nil
	}
	sig, err := signer.NewLocal(f.key).SignRS256(context.Background(), params.Value)
	if err != nil {
		return azkeys.SignResponse{}, err
	}
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: sig}}, nil
}

type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "unused", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type recordingCredential struct {
	token string

	mu     sync.Mutex
	scopes []string
}

func (c *recordingCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = append(c.scopes, opts.Scopes...)
	return azcore.AccessToken{Token: c.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeEntra answers like Microsoft Entra ID for one client credentials
// exchange: the tenant's OpenID configuration, then the token endpoint, whose
// tenant and form it records.
type fakeEntra struct {
	t    *testing.T
	base string // the server's URL, set once it listens

	mu        sync.Mutex
	exchanges int
	tenant    string
	form      url.Values
}

func (e *fakeEntra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 4 && parts[1] == "v2.0" && parts[3] == "openid-configuration":
		tenantURL := e.base + "/" + parts[0]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": tenantURL + "/oauth2/v2.0/authorize",
			"token_endpoint":         tenantURL + "/oauth2/v2.0/token",
			"issuer":                 tenantURL + "/v2.0",
		})
	case len(parts) == 4 && parts[1] == "oauth2" && parts[3] == "token" && r.Method == http.MethodPost:
		if err := r.ParseForm(); err != nil {
			e.t.Errorf("fake Entra ID: parsing the token request: %v", err)
		}
		e.mu.Lock()
		e.exchanges++
		e.tenant = parts[0]
		e.form = r.PostForm
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"expires_in":   3600,
			"access_token": "test-access-token",
		})
	default:
		e.t.Errorf("fake Entra ID: unexpected %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// fakeVault answers like Key Vault: an unauthenticated request gets the
// bearer challenge, and an authenticated sign request gets a signature.
type fakeVault struct {
	t   *testing.T
	key *rsa.PrivateKey

	mu        sync.Mutex
	signs     int
	sawBearer bool
}

func (v *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate",
			`Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/keys/github-app/v1/sign" {
		v.t.Errorf("request = %s %s, want POST /keys/github-app/v1/sign", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		v.t.Error("sign request has no api-version")
	}
	v.sawBearer = r.Header.Get("Authorization") == "Bearer test-access-token"

	var body struct {
		Alg   string `json:"alg"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		v.t.Errorf("decoding sign request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body.Alg != "RS256" {
		v.t.Errorf("alg = %q, want RS256", body.Alg)
	}
	digest, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body.Value, "="))
	if err != nil {
		v.t.Errorf("decoding digest: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sig, err := signer.NewLocal(v.key).SignRS256(r.Context(), digest)
	if err != nil {
		v.t.Errorf("signing: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	v.signs++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"kid":   "https://" + r.Host + "/keys/github-app/v1",
		"value": base64.RawURLEncoding.EncodeToString(sig),
	})
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
