package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testSetup creates a mock OIDC provider with discovery and JWKS endpoints.
func testSetup(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Build JWKS URI from the request's host.
		scheme := "http"
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": fmt.Sprintf("%s://%s/jwks", scheme, r.Host),
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": "test-kid-1",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return key, srv
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid-1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestValidate_HappyPath(t *testing.T) {
	key, srv := testSetup(t)

	now := time.Now()
	token := signTestToken(t, key, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "repo:myorg/myrepo:ref:refs/heads/main",
		"aud": "github-sts",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "test-jti-1",
	})

	claims, err := Validate(context.Background(), token, []string{srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["sub"] != "repo:myorg/myrepo:ref:refs/heads/main" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	key, srv := testSetup(t)

	now := time.Now()
	token := signTestToken(t, key, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(-5 * time.Minute).Unix(),
		"iat": now.Add(-10 * time.Minute).Unix(),
	})

	_, err := Validate(context.Background(), token, []string{srv.URL})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_IssuerNotAllowed(t *testing.T) {
	key, srv := testSetup(t)

	now := time.Now()
	token := signTestToken(t, key, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})

	_, err := Validate(context.Background(), token, []string{"https://other-issuer.example.com"})
	if err == nil {
		t.Fatal("expected error for disallowed issuer")
	}
	if !strings.Contains(err.Error(), "not in allowed list") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MalformedToken(t *testing.T) {
	ResetCacheForTesting()
	_, err := Validate(context.Background(), "not.a.jwt", nil)
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_JWKSCaching(t *testing.T) {
	key, srv := testSetup(t)
	fetchCount := 0

	// Wrap the server to count JWKS fetches.
	countMux := http.NewServeMux()
	countMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": fmt.Sprintf("http://%s/jwks", r.Host),
		})
	})
	countMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		jwks := map[string]any{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": "test-kid-1",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv.Close()
	srv2 := httptest.NewServer(countMux)
	defer srv2.Close()
	ResetCacheForTesting()

	now := time.Now()
	for i := 0; i < 3; i++ {
		token := signTestToken(t, key, jwt.MapClaims{
			"iss": srv2.URL,
			"sub": "test",
			"exp": now.Add(10 * time.Minute).Unix(),
			"iat": now.Unix(),
			"jti": fmt.Sprintf("jti-%d", i),
		})
		_, err := Validate(context.Background(), token, []string{srv2.URL})
		if err != nil {
			t.Fatalf("validation %d: %v", i, err)
		}
	}

	if fetchCount != 1 {
		t.Fatalf("expected 1 JWKS fetch (cached), got %d", fetchCount)
	}
}

func TestValidate_NoKid(t *testing.T) {
	ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Server that serves a key without kid.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": fmt.Sprintf("http://%s/jwks", r.Host),
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Token also without kid.
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	// Explicitly remove kid from header.
	delete(tok.Header, "kid")
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := Validate(context.Background(), signed, []string{srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["sub"] != "test" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
}

func TestValidate_EmptyAllowedIssuers(t *testing.T) {
	key, srv := testSetup(t)

	now := time.Now()
	token := signTestToken(t, key, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})

	_, err := Validate(context.Background(), token, nil)
	if err == nil {
		t.Fatal("expected error for empty allowed issuers")
	}
	if !strings.Contains(err.Error(), "no allowed issuers configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}
