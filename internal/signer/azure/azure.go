// Package azure signs GitHub App JWTs with a key held in Azure Key Vault or
// Managed HSM. The private key never leaves the vault: github-sts sends a
// SHA-256 digest and receives a signature, and its identity needs the
// keys/sign permission on that one key and nothing else
// (ADR github-sts/0018, point 5).
//
// The broker authenticates by workload identity and nothing else
// (ADR github-sts/0020). Every key names the identity it signs as, a client
// ID and the tenant that identity lives in, and there is no default identity.
// The pod has one federated token, a projected Kubernetes service account
// token whose path is in AZURE_FEDERATED_TOKEN_FILE, and Microsoft Entra ID
// exchanges it for any identity whose federated credential trusts the pod's
// service account: the client ID and tenant sent with the exchange decide
// which one. That variable belongs to the Azure SDK and the workload identity
// webhook, and is read here rather than through a GITHUBSTS_ setting: ADR 0020
// records the exception to configuration/1.
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

// FederatedTokenFileEnv is the Azure SDK variable that holds the path of the
// projected service account token the broker exchanges for each identity.
// The github-sts chart sets it, and so does the Azure workload identity
// webhook.
const FederatedTokenFileEnv = "AZURE_FEDERATED_TOKEN_FILE"

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
	guidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Identity is the Microsoft Entra identity a key signs as: a user-assigned
// managed identity whose federated credential trusts the broker's service
// account.
type Identity struct {
	// ClientID is the identity's client ID.
	ClientID string
	// TenantID is the tenant the identity lives in.
	TenantID string
}

// String names the identity for logs and errors.
func (id Identity) String() string {
	return id.ClientID + " in tenant " + id.TenantID
}

// ParseIdentity checks the identity a key signs as. Both values are required
// GUIDs, compared without regard to case, so the result is lower case: two
// spellings of one identity share one credential.
func ParseIdentity(clientID, tenantID string) (Identity, error) {
	id := Identity{ClientID: strings.ToLower(clientID), TenantID: strings.ToLower(tenantID)}
	if !guidPattern.MatchString(id.ClientID) {
		return Identity{}, fmt.Errorf("azure.client_id %q must be the client ID of a user-assigned managed identity, a GUID", clientID)
	}
	if !guidPattern.MatchString(id.TenantID) {
		return Identity{}, fmt.Errorf("azure.tenant_id %q must be a Microsoft Entra tenant ID, a GUID", tenantID)
	}
	return id, nil
}

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

// signClient is the one Key Vault operation this package uses, so tests can
// replace the vault.
type signClient interface {
	Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// credentialFunc builds the credential for one identity.
type credentialFunc func(id Identity) (azcore.TokenCredential, error)

// clientFunc builds the Key Vault client of one vault, authenticated by cred.
type clientFunc func(vaultURL string, cred azcore.TokenCredential, options *azkeys.ClientOptions) (signClient, error)

// newKeyVaultClient is the clientFunc of a running broker.
func newKeyVaultClient(vaultURL string, cred azcore.TokenCredential, options *azkeys.ClientOptions) (signClient, error) {
	c, err := azkeys.NewClient(vaultURL, cred, options)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Provider opens Keys in any vault the broker's Azure identities can reach.
// It holds one credential per identity, so the keys of one identity share one
// token cache, and one client per vault and identity.
type Provider struct {
	newCredential credentialFunc
	newClient     clientFunc
	options       azkeys.ClientOptions

	mu      sync.Mutex
	creds   map[Identity]azcore.TokenCredential // guarded by mu
	clients map[clientKey]signClient            // guarded by mu
}

type clientKey struct {
	vaultURL string
	identity Identity
}

// NewProvider builds a Provider that exchanges the token in
// FederatedTokenFileEnv for each identity a key names. It builds no
// credential yet: each is built when the first key of its identity is opened.
// Nothing is sent to Azure either: an unreadable token file or an identity
// whose federated credential does not trust the pod surfaces at the first
// signature, which the server makes at startup.
func NewProvider() (*Provider, error) {
	tokenFile := strings.TrimSpace(os.Getenv(FederatedTokenFileEnv))
	if tokenFile == "" {
		return nil, fmt.Errorf("%s must hold the path of a service account token projected for audience api://AzureADTokenExchange: the github-sts chart sets it, and so does the Azure workload identity webhook",
			FederatedTokenFileEnv)
	}
	return newProvider(workloadIdentity(azidentity.WorkloadIdentityCredentialOptions{TokenFilePath: tokenFile}), azkeys.ClientOptions{}), nil
}

// workloadIdentity builds, for each identity, a workload identity credential
// from base that exchanges the token in base.TokenFilePath for that identity
// in its tenant. The client ID, the tenant and the token file are all set, so
// no AZURE_CLIENT_ID, AZURE_TENANT_ID or AZURE_FEDERATED_TOKEN_FILE the
// webhook injects can stand in for the identity the key names. base carries
// nothing else in a running broker; tests point it at a fake Entra ID.
func workloadIdentity(base azidentity.WorkloadIdentityCredentialOptions) credentialFunc {
	return func(id Identity) (azcore.TokenCredential, error) {
		options := base
		options.ClientID = id.ClientID
		options.TenantID = id.TenantID
		return azidentity.NewWorkloadIdentityCredential(&options)
	}
}

func newProvider(newCredential credentialFunc, options azkeys.ClientOptions) *Provider {
	options.Retry = policy.RetryOptions{
		MaxRetries:    signMaxRetries,
		TryTimeout:    signTryTimeout,
		RetryDelay:    signRetryDelay,
		MaxRetryDelay: signMaxRetryDelay,
	}
	return &Provider{
		newCredential: newCredential,
		newClient:     newKeyVaultClient,
		options:       options,
		creds:         make(map[Identity]azcore.TokenCredential),
		clients:       make(map[clientKey]signClient),
	}
}

// Key returns the Key that keyID names, signing as the identity that clientID
// and tenantID name. It validates all three, builds the credential and the
// vault client, but does not contact Azure.
func (p *Provider) Key(keyID, clientID, tenantID string) (*Key, error) {
	id, err := ParseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	identity, err := ParseIdentity(clientID, tenantID)
	if err != nil {
		return nil, err
	}
	client, err := p.client(id.VaultURL, identity)
	if err != nil {
		return nil, err
	}
	return &Key{id: id, identity: identity, client: client}, nil
}

func (p *Provider) client(vaultURL string, identity Identity) (signClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := clientKey{vaultURL: vaultURL, identity: identity}
	if c, ok := p.clients[key]; ok {
		return c, nil
	}
	cred, cached := p.creds[identity]
	if !cached {
		var err error
		cred, err = p.newCredential(identity)
		if err != nil {
			return nil, fmt.Errorf("building the Azure credential for identity %s: %w", identity, err)
		}
	}
	options := p.options
	c, err := p.newClient(vaultURL, cred, &options)
	if err != nil {
		return nil, fmt.Errorf("building the Key Vault client for %s: %w", vaultURL, err)
	}
	// Both are kept only once both exist, so every cached credential has a
	// client and a failed Key leaves nothing behind.
	if !cached {
		p.creds[identity] = cred
	}
	p.clients[key] = c
	return c, nil
}

// Key signs with one key in a vault, as one identity.
type Key struct {
	id       KeyID
	identity Identity
	client   signClient
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
		return nil, newSignError(k.subject(), k.identity.TenantID, err)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("azure key vault: signing with %s returned no signature", k.subject())
	}
	return resp.Result, nil
}

// subject names the key and the identity it signs as, for error messages.
func (k *Key) subject() string {
	return fmt.Sprintf("%s as identity %s", k.id, k.identity)
}

// tenantRefusal is how azidentity words its refusal of a token in a tenant the
// credential is not configured for. Key Vault's challenge asks for a token in
// the vault's own tenant, and each identity's credential is pinned to its
// tenant_id, so a vault in another tenant fails this way, before any request
// reaches Microsoft Entra ID. azidentity exports no error type for it;
// TestKey_SignRS256_ExplainsAVaultInAnotherTenant drives a real credential
// into this refusal and fails if the wording changes.
const tenantRefusal = "isn't configured to acquire tokens for tenant"

// signError is a signature Key Vault refused or could not produce. Its
// message is one line naming the key, the HTTP status, Key Vault's error code
// and message, and what usually causes it. It never carries a token or the
// digest. Unwrap keeps the SDK's error for errors.As.
type signError struct {
	subject string
	status  int
	code    string
	message string
	err     error
}

func newSignError(subject, tenantID string, err error) error {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		// No response: a network failure, a timeout, or a credential that
		// could not get a token. The SDK's message says which.
		if strings.Contains(err.Error(), tenantRefusal) {
			return fmt.Errorf("azure key vault: signing with %s: %w (Key Vault asked for a token in another tenant than the identity's tenant_id %s: the vault must be in its identity's tenant)",
				subject, err, tenantID)
		}
		return fmt.Errorf("azure key vault: signing with %s: %w", subject, err)
	}
	return &signError{
		subject: subject,
		status:  respErr.StatusCode,
		code:    respErr.ErrorCode,
		message: serviceMessage(respErr),
		err:     err,
	}
}

func (e *signError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "azure key vault: signing with %s: HTTP %d", e.subject, e.status)
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
		return "Key Vault did not accept the identity's token"
	case 403:
		return "the identity lacks the sign permission on this key, or the vault firewall refuses the broker's address"
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
