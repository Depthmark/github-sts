// Package azure signs GitHub App JWTs with a key held in Azure Key Vault or
// Managed HSM. The private key never leaves the vault: github-sts sends a
// SHA-256 digest and receives a signature, and its identity needs the
// keys/sign permission on that one key and nothing else
// (ADR github-sts/0018, point 5).
//
// The broker authenticates with exactly one credential type, named by the
// operator in AZURE_TOKEN_CREDENTIALS, and there is no chain to fall back
// through (ADR github-sts/0019). That variable belongs to the Azure SDK and is
// read here rather than through a GITHUBSTS_ setting: ADR 0019 records the
// exception to configuration/1.
//
// This package is the only importer of the Azure SDK in github-sts.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/depthmark/github-sts/internal/signer"
)

// TokenCredentialsEnv is the Azure SDK variable that names the one credential
// type the broker authenticates with.
const TokenCredentialsEnv = "AZURE_TOKEN_CREDENTIALS"

// allowedCredentialTypes are the values of TokenCredentialsEnv that ADR 0019
// accepts. Federation (workload identity, managed identity) is preferred; a
// client secret or certificate (EnvironmentCredential) is accepted for a
// cluster that cannot publish its issuer yet. The SDK's "dev" and "prod"
// groups, az login and the full default chain are refused, because each
// leaves the credential in use to whatever happens to be present.
var allowedCredentialTypes = []string{
	"WorkloadIdentityCredential",
	"ManagedIdentityCredential",
	"EnvironmentCredential",
}

const (
	// signTryTimeout bounds one HTTP attempt. A Key Vault sign normally
	// answers in tens of milliseconds; a stalled connection must not hold
	// the App JWT hostage for the whole retry budget.
	signTryTimeout = 3 * time.Second

	// signMaxRetries and the delays below keep the worst case of one call
	// (three tries) inside the caller's own sign timeout, so throttling or a
	// 5xx is retried a little rather than not at all.
	signMaxRetries    = 2
	signRetryDelay    = 200 * time.Millisecond
	signMaxRetryDelay = time.Second

	// maxServiceMessageLen caps how much of Key Vault's error message is
	// kept. The message names the caller and the action denied, which is what
	// an operator needs to fix a role assignment; the rest is noise in a log
	// line and an audit record.
	maxServiceMessageLen = 300
)

var (
	keyNamePattern    = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	keyVersionPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
)

// KeyID identifies one key in a vault, as the Azure portal and CLI print it:
// https://<vault>.vault.azure.net/keys/<name>[/<version>].
type KeyID struct {
	// VaultURL is the vault's scheme and host, for example
	// https://example.vault.azure.net.
	VaultURL string
	// Name is the key's name in the vault.
	Name string
	// Version pins one version of the key. Empty signs with the key's
	// current version, so a new version imported into the vault is picked up
	// without a configuration change.
	Version string
}

// String returns the identifier in the form ParseKeyID accepts.
func (k KeyID) String() string {
	s := k.VaultURL + "/keys/" + k.Name
	if k.Version != "" {
		s += "/" + k.Version
	}
	return s
}

// ParseKeyID parses a Key Vault key identifier. It accepts an https URL with
// no user information, query or fragment, whose path is /keys/<name> or
// /keys/<name>/<version>. It does not restrict the host to Azure's domains:
// the identifier comes from the operator, and the SDK's challenge
// verification already refuses to send a token to a host that does not
// belong to the resource it was issued for.
func ParseKeyID(raw string) (KeyID, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return KeyID{}, fmt.Errorf("key_id %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return KeyID{}, fmt.Errorf("key_id %q must be an https Key Vault key URL", raw)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return KeyID{}, fmt.Errorf("key_id %q must be a Key Vault key URL with a host and no credentials, query or fragment", raw)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "keys" {
		return KeyID{}, fmt.Errorf("key_id %q must have the path /keys/<name> or /keys/<name>/<version>", raw)
	}
	id := KeyID{VaultURL: "https://" + u.Host, Name: parts[1]}
	if !keyNamePattern.MatchString(id.Name) {
		return KeyID{}, fmt.Errorf("key_id %q has an invalid key name", raw)
	}
	if len(parts) == 3 {
		id.Version = parts[2]
		if !keyVersionPattern.MatchString(id.Version) {
			return KeyID{}, fmt.Errorf("key_id %q has an invalid key version", raw)
		}
	}
	return id, nil
}

// CheckCredentialType verifies that TokenCredentialsEnv names one of the
// credential types ADR 0019 accepts.
func CheckCredentialType() error {
	value, ok := os.LookupEnv(TokenCredentialsEnv)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return fmt.Errorf("%s must name the credential type the broker authenticates to Azure with: one of %s",
			TokenCredentialsEnv, strings.Join(allowedCredentialTypes, ", "))
	}
	for _, allowed := range allowedCredentialTypes {
		if strings.EqualFold(value, allowed) {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s (got %q)",
		TokenCredentialsEnv, strings.Join(allowedCredentialTypes, ", "), value)
}

// signClient is the one Key Vault operation this package uses, so tests can
// replace the vault.
type signClient interface {
	Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// Provider opens Keys in any vault the broker's Azure identity can reach. It
// holds one credential, so every key shares one token cache, and one client
// per vault.
type Provider struct {
	cred    azcore.TokenCredential
	options azkeys.ClientOptions

	mu      sync.Mutex
	clients map[string]signClient // by vault URL, guarded by mu
}

// NewProvider builds a Provider that authenticates with the credential type
// named in TokenCredentialsEnv. Nothing is sent to Azure yet: a missing
// federated token file or a wrong client ID surfaces at the first signature,
// which the server makes at startup.
func NewProvider() (*Provider, error) {
	if err := CheckCredentialType(); err != nil {
		return nil, err
	}
	// RequireAzureTokenCredentials makes the SDK refuse to build its default
	// chain, so the value checked above is the only credential tried.
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		RequireAzureTokenCredentials: true,
	})
	if err != nil {
		return nil, fmt.Errorf("building the Azure credential: %w", err)
	}
	return newProvider(cred, azkeys.ClientOptions{}), nil
}

func newProvider(cred azcore.TokenCredential, options azkeys.ClientOptions) *Provider {
	options.Retry = policy.RetryOptions{
		MaxRetries:    signMaxRetries,
		TryTimeout:    signTryTimeout,
		RetryDelay:    signRetryDelay,
		MaxRetryDelay: signMaxRetryDelay,
	}
	return &Provider{cred: cred, options: options, clients: make(map[string]signClient)}
}

// Key returns the Key that keyID names. It validates the identifier and
// builds the vault client, but does not contact the vault.
func (p *Provider) Key(keyID string) (*Key, error) {
	id, err := ParseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	client, err := p.client(id.VaultURL)
	if err != nil {
		return nil, err
	}
	return &Key{id: id, client: client}, nil
}

func (p *Provider) client(vaultURL string) (signClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[vaultURL]; ok {
		return c, nil
	}
	options := p.options
	c, err := azkeys.NewClient(vaultURL, p.cred, &options)
	if err != nil {
		return nil, fmt.Errorf("building the Key Vault client for %s: %w", vaultURL, err)
	}
	p.clients[vaultURL] = c
	return c, nil
}

// Key signs with one key in a vault.
type Key struct {
	id     KeyID
	client signClient
}

var _ signer.Key = (*Key)(nil)

// ID returns the key's identifier, for logs. It is not a secret.
func (k *Key) ID() KeyID {
	return k.id
}

// SignRS256 implements signer.Key with the vault's sign operation.
func (k *Key) SignRS256(ctx context.Context, digest []byte) ([]byte, error) {
	if err := signer.CheckDigest(digest); err != nil {
		return nil, err
	}
	alg := azkeys.SignatureAlgorithmRS256
	resp, err := k.client.Sign(ctx, k.id.Name, k.id.Version, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, newSignError(k.id, err)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("azure key vault: signing with %s returned no signature", k.id)
	}
	return resp.Result, nil
}

// signError is a signature Key Vault refused or could not produce. Its
// message is one line naming the key, the HTTP status, Key Vault's error code
// and message, and what usually causes it. It never carries a token or the
// digest. Unwrap keeps the SDK's error for errors.As.
type signError struct {
	keyID   KeyID
	status  int
	code    string
	message string
	err     error
}

func newSignError(id KeyID, err error) error {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		// No response: a network failure, a timeout, or a credential that
		// could not get a token. The SDK's message says which.
		return fmt.Errorf("azure key vault: signing with %s: %w", id, err)
	}
	return &signError{
		keyID:   id,
		status:  respErr.StatusCode,
		code:    respErr.ErrorCode,
		message: serviceMessage(respErr),
		err:     err,
	}
}

func (e *signError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "azure key vault: signing with %s: HTTP %d", e.keyID, e.status)
	if e.code != "" {
		fmt.Fprintf(&b, " %s", e.code)
	}
	if e.message != "" {
		fmt.Fprintf(&b, ": %s", e.message)
	}
	if hint := statusHint(e.status); hint != "" {
		fmt.Fprintf(&b, " (%s)", hint)
	}
	return b.String()
}

func (e *signError) Unwrap() error { return e.err }

func statusHint(status int) string {
	switch status {
	case 400:
		return "the key cannot sign RS256: it is not an RSA key, it is disabled, or sign is not among its operations"
	case 401:
		return "Azure did not accept the broker's credential"
	case 403:
		return "the broker's identity lacks the sign permission on this key, or the vault firewall refuses its address"
	case 404:
		return "the key or the key version does not exist"
	case 429:
		return "Key Vault is throttling this vault"
	}
	return ""
}

// serviceMessage extracts Key Vault's own error message, on one line and
// capped at maxServiceMessageLen. The SDK keeps the response body readable
// after building the error.
func serviceMessage(respErr *azcore.ResponseError) string {
	if respErr.RawResponse == nil {
		return ""
	}
	body, err := runtime.Payload(respErr.RawResponse)
	if err != nil || len(body) == 0 {
		return ""
	}
	var payload struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	msg := strings.Join(strings.Fields(payload.Error.Message), " ")
	if len(msg) > maxServiceMessageLen {
		msg = msg[:maxServiceMessageLen] + "..."
	}
	return msg
}
