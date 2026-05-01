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

func TestValidate_NoKid_Rejected(t *testing.T) {
	key, srv := testSetup(t)

	// Sign a token but strip kid from the header.
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	delete(tok.Header, "kid")
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(context.Background(), signed, []string{srv.URL}); err == nil {
		t.Fatal("expected error for token without kid")
	}
}

func TestValidate_KidNotInJWKS_Rejected(t *testing.T) {
	key, srv := testSetup(t)

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	tok.Header["kid"] = "some-other-kid"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(context.Background(), signed, []string{srv.URL}); err == nil {
		t.Fatal("expected error for kid not in JWKS")
	}
}

func TestValidate_RejectsMismatchedJWKSHost(t *testing.T) {
	ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Two distinct httptest servers — different ports → different hosts.
	jwksMux := http.NewServeMux()
	jwksMux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	jwksSrv := httptest.NewServer(jwksMux)
	defer jwksSrv.Close()

	issMux := http.NewServeMux()
	issMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		// Discovery doc points jwks_uri at the *other* host.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": jwksSrv.URL + "/jwks",
		})
	})
	issSrv := httptest.NewServer(issMux)
	defer issSrv.Close()

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issSrv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Validate(context.Background(), signed, []string{issSrv.URL})
	if err == nil {
		t.Fatal("expected error: jwks_uri host should not match issuer host")
	}
	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_TrustedJWKSHostOverride(t *testing.T) {
	ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwksMux := http.NewServeMux()
	jwksMux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	jwksSrv := httptest.NewServer(jwksMux)
	defer jwksSrv.Close()

	issMux := http.NewServeMux()
	issMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": jwksSrv.URL + "/jwks",
		})
	})
	issSrv := httptest.NewServer(issMux)
	defer issSrv.Close()

	jwksHost := strings.TrimPrefix(jwksSrv.URL, "http://")
	SetTrustedJWKSHosts(map[string][]string{
		issSrv.URL: {jwksHost},
	})
	defer SetTrustedJWKSHosts(nil)

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issSrv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(context.Background(), signed, []string{issSrv.URL}); err != nil {
		t.Fatalf("expected validation to succeed with override: %v", err)
	}
}

func TestValidate_RefusesRedirect(t *testing.T) {
	ResetCacheForTesting()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker-controlled JWKS server — would serve attacker keys if reached.
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "evil",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))
	defer attacker.Close()

	// Issuer's discovery handler 302's the JWKS fetch to the attacker host.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": fmt.Sprintf("http://%s/jwks-redirect", r.Host),
		})
	})
	mux.HandleFunc("/jwks-redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/jwks", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": srv.URL,
		"sub": "test",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
	})
	tok.Header["kid"] = "evil"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(context.Background(), signed, []string{srv.URL}); err == nil {
		t.Fatal("expected error: JWKS redirect must not be followed")
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
