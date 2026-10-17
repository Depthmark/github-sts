package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/signer"
	ststracing "github.com/depthmark/github-sts/internal/tracing"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
)

const (
	// appJWTLifetime is how far in the future the App JWT expires. GitHub
	// rejects an exp more than 10 minutes out.
	appJWTLifetime = 10 * time.Minute

	// appJWTBackdate moves iat into the past to absorb clock drift between
	// this host and GitHub, as GitHub's documentation recommends.
	appJWTBackdate = 60 * time.Second

	// appJWTCacheTTL controls how long the signed App JWT is reused. The JWT
	// itself is valid for 10 minutes; we cache for 9 minutes to leave a
	// 1-minute safety margin. With a key in a vault, this is also what bounds
	// the vault to one signature per App instance every 9 minutes, whoever
	// asks.
	appJWTCacheTTL = 9 * time.Minute

	// appJWTSignTimeout bounds one signature, whoever is waiting for it. A
	// vault normally answers in tens of milliseconds; this only matters when
	// it does not, and keeps every waiting request from hanging with it.
	appJWTSignTimeout = 10 * time.Second
)

// ErrAppCredential marks a failure to obtain the credential that
// authenticates as the GitHub App itself. Nothing was sent to GitHub: the key
// could not sign, or its vault could not be reached.
var ErrAppCredential = errors.New("github app credential unavailable")

type cachedJWT struct {
	token     string
	expiresAt time.Time
}

// AppCredentialSource hands out the credential that authenticates as one
// physical GitHub App, and is the only code in this package that knows how it
// is produced. Today that is an App JWT signed by a signer.Key, whether the
// private key is in this process or in a vault. GitHub's planned federated
// credentials for Apps (github/roadmap#1288) would replace the signer here and
// nowhere else (ADR github-sts/0018, point 1).
//
// One source is shared by an instance's AppTokenProvider and by both
// background pollers, so a vault-held key is asked for one signature per cache
// period, whichever of them needs the JWT first.
type AppCredentialSource struct {
	appName  string
	instance string
	appID    int64
	key      signer.Key
	now      func() time.Time

	mu     sync.Mutex
	cached cachedJWT // guarded by mu

	flight singleflight.Group
}

// NewAppCredentialSource returns the credential source for one physical
// GitHub App. appName and instance label its spans, as on AppTokenProvider.
func NewAppCredentialSource(appName, instance string, appID int64, key signer.Key) *AppCredentialSource {
	return &AppCredentialSource{
		appName:  appName,
		instance: instance,
		appID:    appID,
		key:      key,
		now:      time.Now,
	}
}

// AppID returns the GitHub App ID this source authenticates as.
func (s *AppCredentialSource) AppID() int64 {
	return s.appID
}

// Prime signs and caches a first App JWT. The server calls it at startup so
// that a key which cannot sign (a wrong key identifier, a missing role, an
// unreachable vault) stops the broker before it takes traffic, rather than
// failing every exchange later.
func (s *AppCredentialSource) Prime(ctx context.Context) error {
	_, _, err := s.appJWT(ctx)
	return err
}

// appJWT returns a valid App JWT and says how it was obtained: "hit" from
// the cache, "miss" when this call waited for a new signature alone, and
// "shared" when other callers waited for the same one.
func (s *AppCredentialSource) appJWT(ctx context.Context) (string, string, error) {
	if token, ok := s.cachedToken(); ok {
		return token, "hit", nil
	}

	// One signature serves every caller that arrives while it is in flight,
	// so a vault sees one request however many exchanges need the JWT. It
	// runs detached from the first caller's cancellation: a client that
	// disconnects must not fail everyone else waiting on the same signature.
	// The timeout bounds it instead, and each caller still stops waiting when
	// its own context ends.
	ch := s.flight.DoChan("app_jwt", func() (any, error) {
		if token, ok := s.cachedToken(); ok {
			return token, nil
		}
		signCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appJWTSignTimeout)
		defer cancel()
		return s.sign(signCtx)
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return "", "miss", res.Err
		}
		result := "miss"
		if res.Shared {
			result = "shared"
		}
		return res.Val.(string), result, nil
	case <-ctx.Done():
		return "", "miss", ctx.Err()
	}
}

func (s *AppCredentialSource) cachedToken() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached.token != "" && s.now().Before(s.cached.expiresAt) {
		return s.cached.token, true
	}
	return "", false
}

// sign builds the App JWT and has the key sign it. The signing input is
// built exactly as golang-jwt builds it, so a PEM-backed instance sends
// GitHub the same token it did before signing moved behind signer.Key.
func (s *AppCredentialSource) sign(ctx context.Context) (string, error) {
	ctx, span := ststracing.Tracer().Start(ctx, "github.app_jwt.sign",
		trace.WithAttributes(ststracing.GitHubOperationAttributes(s.appName, s.instance, "sign_app_jwt", "")...),
	)
	defer span.End()

	now := s.now()
	claims := jwt.MapClaims{
		"iat": now.Add(-appJWTBackdate).Unix(),
		"exp": now.Add(appJWTLifetime).Unix(),
		"iss": strconv.FormatInt(s.appID, 10),
	}
	signingInput, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SigningString()
	if err != nil {
		ststracing.MarkError(span, "github_app_jwt_sign_failed")
		return "", fmt.Errorf("%w: encoding the App JWT for app %q instance %q: %w", ErrAppCredential, s.appName, s.instance, err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := s.key.SignRS256(ctx, digest[:])
	if err != nil {
		ststracing.MarkError(span, "github_app_jwt_sign_failed")
		return "", fmt.Errorf("%w: signing the App JWT for app %q instance %q: %w", ErrAppCredential, s.appName, s.instance, err)
	}
	span.SetAttributes(ststracing.StageResult("success"))

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	s.mu.Lock()
	s.cached = cachedJWT{token: token, expiresAt: now.Add(appJWTCacheTTL)}
	s.mu.Unlock()
	return token, nil
}
