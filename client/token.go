// Package client provides GitHub App and STS token acquisition with
// per-workflow lifecycle management (acquire, use, revoke).
//
// This package is designed to be imported by other Go services that
// need authenticated access to the GitHub API via GitHub App installations
// or a github-sts token exchange service.
package client

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultSATokenPath is the standard path for a Kubernetes projected
// service account token.
const DefaultSATokenPath = "/var/run/secrets/tokens/github-sts-token"

// TokenProvider acquires a GitHub installation token. Each call returns a
// fresh token — implementations must not cache tokens.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// Option configures optional behavior for providers.
type Option func(*options)

type options struct {
	httpClient *http.Client
}

// WithHTTPClient injects a custom HTTP client. If not provided, a default
// client with a 15-second timeout is used.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// AppTokenProvider acquires a GitHub installation token directly from the
// GitHub App JWT flow.
type AppTokenProvider struct {
	appID          int64
	privateKey     *rsa.PrivateKey
	owner          string
	apiURL         string
	installationID int64
	httpClient     *http.Client
}

// NewAppTokenProvider constructs an AppTokenProvider from PEM-encoded
// private key bytes.
func NewAppTokenProvider(appID int64, pemData []byte, owner, apiURL string, opts ...Option) (*AppTokenProvider, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}

	return &AppTokenProvider{
		appID:      appID,
		privateKey: key,
		owner:      owner,
		apiURL:     apiURL,
		httpClient: httpClient,
	}, nil
}

// Token returns a fresh GitHub installation token.
func (p *AppTokenProvider) Token(ctx context.Context) (string, error) {
	appJWT, err := p.signJWT()
	if err != nil {
		return "", fmt.Errorf("signing app JWT: %w", err)
	}

	if p.installationID == 0 {
		id, err := p.resolveInstallationID(ctx, appJWT)
		if err != nil {
			return "", fmt.Errorf("resolving installation ID: %w", err)
		}
		p.installationID = id
	}

	token, err := p.createInstallationToken(ctx, appJWT)
	if err == errInstallationNotFound {
		// Cached installation ID is stale — clear and retry once.
		p.installationID = 0
		id, err := p.resolveInstallationID(ctx, appJWT)
		if err != nil {
			return "", fmt.Errorf("resolving installation ID (retry): %w", err)
		}
		p.installationID = id

		token, err = p.createInstallationToken(ctx, appJWT)
		if err != nil {
			return "", fmt.Errorf("creating installation token: %w", err)
		}
		return token, nil
	}
	if err != nil {
		return "", fmt.Errorf("creating installation token: %w", err)
	}
	return token, nil
}

// errInstallationNotFound is a sentinel error indicating the cached
// installation ID is stale (GitHub returned 404).
var errInstallationNotFound = fmt.Errorf("installation not found")

func (p *AppTokenProvider) signJWT() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": fmt.Sprintf("%d", p.appID),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(p.privateKey)
}

func (p *AppTokenProvider) resolveInstallationID(ctx context.Context, appJWT string) (int64, error) {
	url := fmt.Sprintf("%s/orgs/%s/installation", p.apiURL, p.owner)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}

	var install struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&install); err != nil {
		return 0, err
	}
	return install.ID, nil
}

func (p *AppTokenProvider) createInstallationToken(ctx context.Context, appJWT string) (string, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiURL, p.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", errInstallationNotFound
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST %s returned %d", url, resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

// STSTokenProvider exchanges a Kubernetes service account token for a GitHub
// installation token via the github-sts service.
type STSTokenProvider struct {
	STSURL      string
	Identity    string
	App         string
	Scope       string
	Audience    string
	SATokenPath string
	httpClient  *http.Client
}

// Token reads the projected SA token and exchanges it via github-sts.
func (p *STSTokenProvider) Token(ctx context.Context) (string, error) {
	if p.httpClient == nil {
		p.httpClient = defaultHTTPClient()
	}

	saToken, err := os.ReadFile(p.SATokenPath)
	if err != nil {
		return "", fmt.Errorf("reading service account token: %w", err)
	}

	app := p.App
	if app == "" {
		app = "default"
	}

	params := url.Values{}
	params.Set("scope", p.Scope)
	params.Set("identity", p.Identity)
	params.Set("app", app)
	if p.Audience != "" {
		params.Set("audience", p.Audience)
	}

	reqURL := fmt.Sprintf("%s/sts/exchange?%s", p.STSURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+string(saToken))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling github-sts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github-sts returned %d for scope %q", resp.StatusCode, p.Scope)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

// SetHTTPClient sets a custom HTTP client on the STSTokenProvider.
func (p *STSTokenProvider) SetHTTPClient(c *http.Client) {
	p.httpClient = c
}
