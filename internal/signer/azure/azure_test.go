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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
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

func TestCheckCredentialType(t *testing.T) {
	tests := []struct {
		name    string
		value   *string
		wantErr string
	}{
		{name: "unset", value: nil, wantErr: "must name the credential type"},
		{name: "empty", value: ptr(""), wantErr: "must name the credential type"},
		{name: "workload identity", value: ptr("WorkloadIdentityCredential")},
		{name: "managed identity", value: ptr("ManagedIdentityCredential")},
		{name: "client secret or certificate", value: ptr("EnvironmentCredential")},
		{name: "case does not matter", value: ptr("workloadidentitycredential")},
		{name: "dev group", value: ptr("dev"), wantErr: `(got "dev")`},
		{name: "prod group", value: ptr("prod"), wantErr: `(got "prod")`},
		{name: "az login", value: ptr("AzureCLICredential"), wantErr: `(got "AzureCLICredential")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setCredentialType(t, tt.value)
			err := CheckCredentialType()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCredentialType: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), TokenCredentialsEnv) {
				t.Fatalf("error = %v, want it to name %s", err, TokenCredentialsEnv)
			}
		})
	}
}

func TestNewProvider_RefusesAnUnnamedCredential(t *testing.T) {
	setCredentialType(t, nil)
	if _, err := NewProvider(); err == nil {
		t.Fatal("NewProvider succeeded without " + TokenCredentialsEnv)
	}
}

func TestProvider_OneClientPerVault(t *testing.T) {
	p := newProvider(staticCredential{}, azkeys.ClientOptions{})
	for _, keyID := range []string{
		"https://one.vault.azure.net/keys/dev",
		"https://one.vault.azure.net/keys/production",
		"https://two.vault.azure.net/keys/dev",
	} {
		if _, err := p.Key(keyID); err != nil {
			t.Fatalf("Key(%q): %v", keyID, err)
		}
	}
	if got := len(p.clients); got != 2 {
		t.Fatalf("clients = %d, want 2 (one per vault)", got)
	}
}

func TestProvider_KeyRejectsAnInvalidIdentifier(t *testing.T) {
	p := newProvider(staticCredential{}, azkeys.ClientOptions{})
	if _, err := p.Key("https://example.vault.azure.net/secrets/github-app"); err == nil {
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
	p := newProvider(cred, azkeys.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: srv.Client()},
		DisableChallengeResourceVerification: true,
	})
	k, err := p.Key(srv.URL + "/keys/github-app/v1")
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

func setCredentialType(t *testing.T, value *string) {
	t.Helper()
	t.Setenv(TokenCredentialsEnv, "")
	if value == nil {
		if err := os.Unsetenv(TokenCredentialsEnv); err != nil {
			t.Fatalf("unsetting %s: %v", TokenCredentialsEnv, err)
		}
		return
	}
	t.Setenv(TokenCredentialsEnv, *value)
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
