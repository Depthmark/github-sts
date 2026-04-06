// Package oidc validates OIDC bearer tokens against their issuer's JWKS endpoint.
//
// JWKS keys are cached per issuer for 1 hour. Multi-issuer validation is
// supported via an optional allowlist.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

const (
	jwksCacheTTL = 1 * time.Hour

	// maxJWKSCacheEntries limits the number of issuers cached to prevent
	// memory exhaustion from tokens with many distinct issuers.
	maxJWKSCacheEntries = 100

	// maxDiscoveryResponseBytes limits the OIDC discovery response size (1 MB).
	maxDiscoveryResponseBytes = 1 << 20

	// maxJWKSResponseBytes limits the JWKS response size (5 MB).
	maxJWKSResponseBytes = 5 << 20
)

// oidcHTTPClient is a dedicated client for OIDC/JWKS fetches with a
// reasonable timeout, avoiding use of http.DefaultClient.
var oidcHTTPClient = &http.Client{Timeout: 15 * time.Second}

// Claims is a map of decoded JWT claims.
type Claims map[string]any

type jwksEntry struct {
	keys      map[string]*rsa.PublicKey // kid → public key
	fetchedAt time.Time
}

var (
	jwksCache = make(map[string]*jwksEntry)
	jwksMu    sync.RWMutex
	jwksSF    singleflight.Group
)

// Validate verifies an OIDC bearer token's signature and standard claims
// against the issuer's JWKS endpoint. If allowedIssuers is non-empty, the
// token's issuer must be in the list.
func Validate(ctx context.Context, tokenString string, allowedIssuers []string) (Claims, error) {
	// Parse without verification to extract issuer and header.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		metrics.OIDCValidationErrors.WithLabelValues("unknown", "malformed").Inc()
		return nil, fmt.Errorf("malformed token: %w", err)
	}

	mapClaims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		metrics.OIDCValidationErrors.WithLabelValues("unknown", "malformed").Inc()
		return nil, fmt.Errorf("malformed token claims")
	}

	issuer, _ := mapClaims["iss"].(string)
	if issuer == "" {
		metrics.OIDCValidationErrors.WithLabelValues("unknown", "malformed").Inc()
		return nil, fmt.Errorf("token missing issuer claim")
	}

	// Check issuer allowlist.
	if len(allowedIssuers) > 0 {
		allowed := false
		for _, a := range allowedIssuers {
			if a == issuer {
				allowed = true
				break
			}
		}
		if !allowed {
			metrics.OIDCValidationErrors.WithLabelValues(issuer, "issuer_not_allowed").Inc()
			return nil, fmt.Errorf("issuer %q not in allowed list", issuer)
		}
	} else {
		metrics.OIDCValidationErrors.WithLabelValues(issuer, "no_issuers_configured").Inc()
		return nil, fmt.Errorf("no allowed issuers configured")
	}

	// Fetch JWKS for this issuer.
	keys, err := getJWKS(ctx, issuer)
	if err != nil {
		metrics.OIDCValidationErrors.WithLabelValues(issuer, "jwks_fetch_failed").Inc()
		return nil, fmt.Errorf("fetching JWKS for issuer %q: %w", issuer, err)
	}

	// Build keyfunc for verification.
	keyfunc := func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != "" {
			if key, ok := keys[kid]; ok {
				return key, nil
			}
			return nil, fmt.Errorf("key %q not found in JWKS", kid)
		}
		// No kid — use first available key (single-key providers).
		for _, key := range keys {
			return key, nil
		}
		return nil, fmt.Errorf("no keys in JWKS for issuer %q", issuer)
	}

	// Parse and verify with explicit algorithm enforcement.
	verified, err := jwt.Parse(tokenString, keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		reason := classifyError(err)
		metrics.OIDCValidationErrors.WithLabelValues(issuer, reason).Inc()
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	result, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return Claims(result), nil
}

// classifyError maps JWT verification errors to metric labels.
func classifyError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "expired"):
		return "expired"
	case strings.Contains(msg, "signature"):
		return "signature"
	case strings.Contains(msg, "signing method"):
		return "algorithm"
	default:
		return "claims"
	}
}

// getJWKS returns cached JWKS keys for the given issuer, fetching if needed.
// Concurrent requests for the same issuer are deduplicated via singleflight,
// so the write lock is only held for the brief cache update — not during the
// HTTP fetch.
func getJWKS(ctx context.Context, issuer string) (map[string]*rsa.PublicKey, error) {
	jwksMu.RLock()
	if entry, ok := jwksCache[issuer]; ok && time.Since(entry.fetchedAt) < jwksCacheTTL {
		jwksMu.RUnlock()
		return entry.keys, nil
	}
	jwksMu.RUnlock()

	// Singleflight: only one goroutine fetches; others wait and share the result.
	v, err, _ := jwksSF.Do(issuer, func() (any, error) {
		// Double-check cache after winning the singleflight race.
		jwksMu.RLock()
		if entry, ok := jwksCache[issuer]; ok && time.Since(entry.fetchedAt) < jwksCacheTTL {
			jwksMu.RUnlock()
			return entry.keys, nil
		}
		jwksMu.RUnlock()

		keys, err := fetchJWKS(ctx, issuer)
		if err != nil {
			return nil, err
		}

		// Brief write lock for cache update only.
		jwksMu.Lock()
		jwksCache[issuer] = &jwksEntry{
			keys:      keys,
			fetchedAt: time.Now(),
		}

		// Evict oldest entry if cache is full to prevent unbounded growth.
		if len(jwksCache) > maxJWKSCacheEntries {
			var oldestKey string
			oldest := time.Now()
			for k, v := range jwksCache {
				if k != issuer && v.fetchedAt.Before(oldest) {
					oldest = v.fetchedAt
					oldestKey = k
				}
			}
			if oldestKey != "" {
				delete(jwksCache, oldestKey)
			}
		}
		jwksMu.Unlock()

		return keys, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]*rsa.PublicKey), nil
}

// fetchJWKS discovers and fetches JWKS from the issuer's OIDC discovery endpoint.
func fetchJWKS(ctx context.Context, issuer string) (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Discover JWKS URI.
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}

	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryResponseBytes)).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("parsing OIDC discovery: %w", err)
	}
	if discovery.JWKSURI == "" {
		return nil, fmt.Errorf("OIDC discovery missing jwks_uri")
	}

	// Fetch JWKS.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSURI, nil)
	if err != nil {
		return nil, err
	}

	resp2, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp2.StatusCode)
	}

	var jwks struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp2.Body, maxJWKSResponseBytes)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := k.toRSAPublicKey()
		if err != nil {
			slog.Warn("skipping invalid JWKS key", "kid", k.Kid, "error", err)
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = "_default"
		}
		keys[kid] = pub
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA keys in JWKS for issuer %q", issuer)
	}

	return keys, nil
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k *jwkKey) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// ResetCacheForTesting clears the JWKS cache. Only for use in tests.
func ResetCacheForTesting() {
	jwksMu.Lock()
	defer jwksMu.Unlock()
	jwksCache = make(map[string]*jwksEntry)
}
