package github

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/depthmark/github-sts/internal/signer"
	"github.com/golang-jwt/jwt/v5"
)

// countingKey is a signer.Key that signs in process and records each call.
// release, when set, holds every signature until it is closed.
type countingKey struct {
	key     *rsa.PrivateKey
	err     error
	release chan struct{}

	calls         atomic.Int32
	mu            sync.Mutex
	ctxErrAtStart error
}

func (k *countingKey) SignRS256(ctx context.Context, digest []byte) ([]byte, error) {
	k.calls.Add(1)
	if k.release != nil {
		<-k.release
	}
	k.mu.Lock()
	k.ctxErrAtStart = ctx.Err()
	k.mu.Unlock()
	if k.err != nil {
		return nil, k.err
	}
	return signer.NewLocal(k.key).SignRS256(ctx, digest)
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestAppCredentialSource_TokenIsTheJWTGitHubGotBefore(t *testing.T) {
	key := generateTestKey(t)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	src := newTestCredential(t, "checkout", "checkout-1", 12345, key)
	src.now = fixedClock(now)

	got, _, err := src.appJWT(context.Background())
	if err != nil {
		t.Fatalf("appJWT: %v", err)
	}

	// The token golang-jwt produced from the PEM before signing moved behind
	// signer.Key. PKCS #1 v1.5 is deterministic, so the two must be equal.
	want, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": "12345",
	}).SignedString(key)
	if err != nil {
		t.Fatalf("signing the reference token: %v", err)
	}
	if got != want {
		t.Fatalf("App JWT differs from the PEM-signed reference\n got: %s\nwant: %s", got, want)
	}

	parsed, err := jwt.Parse(got, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(fixedClock(now)))
	if err != nil {
		t.Fatalf("App JWT does not verify against the public key: %v", err)
	}
	if iss, _ := parsed.Claims.GetIssuer(); iss != "12345" {
		t.Errorf("iss = %q, want 12345", iss)
	}
}

func TestAppCredentialSource_OneSignaturePerCachePeriodWhoeverAsks(t *testing.T) {
	key := &countingKey{key: generateTestKey(t)}
	src := NewAppCredentialSource("checkout", "checkout-1", 1, key)
	now := time.Now()
	src.now = func() time.Time { return now }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := NewAppTokenProvider(src, srv.URL, nil)
	pi := PoolInstanceConfig{LogicalApp: "checkout", Instance: "checkout-1", AppConfig: AppConfig{Credential: src}}
	poller := NewRateLimitPoller([]PoolInstanceConfig{pi}, srv.URL, time.Hour, nil, time.Hour)
	prober := NewReachabilityProber([]PoolInstanceConfig{pi}, srv.URL, time.Hour)

	ctx := context.Background()
	if _, err := provider.GenerateAppJWT(ctx); err != nil {
		t.Fatalf("exchange path: %v", err)
	}
	if _, err := poller.signJWT(ctx, pi.AppConfig); err != nil {
		t.Fatalf("rate limit poller: %v", err)
	}
	prober.probeInstance(ctx, pi)
	if !prober.IsReachable("checkout", "checkout-1") {
		t.Fatal("reachability prober could not use the shared JWT")
	}
	if got := key.calls.Load(); got != 1 {
		t.Fatalf("signatures = %d, want 1 for three consumers within the cache period", got)
	}

	now = now.Add(appJWTCacheTTL)
	if _, err := provider.GenerateAppJWT(ctx); err != nil {
		t.Fatalf("after the cache period: %v", err)
	}
	if got := key.calls.Load(); got != 2 {
		t.Fatalf("signatures = %d, want 2 once the cached JWT has aged out", got)
	}
}

func TestAppCredentialSource_ConcurrentCallersShareOneSignature(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := &countingKey{key: generateTestKey(t), release: make(chan struct{})}
		src := NewAppCredentialSource("checkout", "checkout-1", 1, key)

		const callers = 20
		tokens := make([]string, callers)
		errs := make([]error, callers)
		var wg sync.WaitGroup
		for i := range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tokens[i], _, errs[i] = src.appJWT(context.Background())
			}()
		}
		// Every caller is now waiting on the one signature in flight.
		synctest.Wait()
		close(key.release)
		wg.Wait()

		for i := range callers {
			if errs[i] != nil {
				t.Fatalf("caller %d: %v", i, errs[i])
			}
			if tokens[i] != tokens[0] {
				t.Fatalf("caller %d got a different token", i)
			}
		}
		if got := key.calls.Load(); got != 1 {
			t.Fatalf("signatures = %d, want 1 for %d concurrent callers", got, callers)
		}
	})
}

func TestAppCredentialSource_CallerCancellationDoesNotAbortTheSignature(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := &countingKey{key: generateTestKey(t), release: make(chan struct{})}
		src := NewAppCredentialSource("checkout", "checkout-1", 1, key)

		ctx, cancel := context.WithCancel(context.Background())
		first := make(chan error, 1)
		go func() {
			_, _, err := src.appJWT(ctx)
			first <- err
		}()
		second := make(chan error, 1)
		go func() {
			_, _, err := src.appJWT(context.Background())
			second <- err
		}()
		// Both callers wait on the same signature, which the key holds.
		synctest.Wait()

		cancel()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled caller: error = %v, want context.Canceled", err)
		}

		close(key.release)
		if err := <-second; err != nil {
			t.Fatalf("the other caller failed with the first caller's cancellation: %v", err)
		}
		if got := key.calls.Load(); got != 1 {
			t.Fatalf("signatures = %d, want 1 shared by both callers", got)
		}
		key.mu.Lock()
		defer key.mu.Unlock()
		if key.ctxErrAtStart != nil {
			t.Fatalf("the signature ran on a cancelled context: %v", key.ctxErrAtStart)
		}
	})
}

func TestAppCredentialSource_FailureIsMarkedAndNotCached(t *testing.T) {
	key := &countingKey{key: generateTestKey(t), err: errors.New("vault unreachable")}
	src := NewAppCredentialSource("checkout", "checkout-1", 1, key)

	_, _, err := src.appJWT(context.Background())
	if !errors.Is(err, ErrAppCredential) {
		t.Fatalf("error = %v, want ErrAppCredential", err)
	}
	for _, want := range []string{`"checkout"`, `"checkout-1"`, "vault unreachable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}

	key.err = nil
	if _, _, err := src.appJWT(context.Background()); err != nil {
		t.Fatalf("after the key recovered: %v", err)
	}
	if got := key.calls.Load(); got != 2 {
		t.Fatalf("signatures = %d, want 2: a failure must not be cached", got)
	}
}

func TestAppCredentialSource_PrimeReportsAKeyThatCannotSign(t *testing.T) {
	key := &countingKey{key: generateTestKey(t), err: errors.New("forbidden")}
	src := NewAppCredentialSource("checkout", "checkout-1", 1, key)
	if err := src.Prime(context.Background()); !errors.Is(err, ErrAppCredential) {
		t.Fatalf("Prime: error = %v, want ErrAppCredential", err)
	}
}

func TestAppTokenProvider_SignFailureIsRetryableAndClassified(t *testing.T) {
	srv := newMockGitHubServer(42, succeedHandler("ghs_unused"))
	defer srv.Close()
	key := &countingKey{key: generateTestKey(t), err: errors.New("vault unreachable")}
	p := NewAppTokenProvider(NewAppCredentialSource("checkout", "checkout-1", 1, key), srv.URL, nil)

	_, err := p.GetInstallationID(context.Background(), "myorg")
	var mintErr *TokenMintError
	if !errors.As(err, &mintErr) || !mintErr.Retryable {
		t.Fatalf("error = %v, want a retryable *TokenMintError", err)
	}
	if !errors.Is(err, ErrAppCredential) {
		t.Fatalf("error = %v, want ErrAppCredential in the chain", err)
	}
	if got := tokenMintErrorType(err); got != "github_app_jwt_sign_failed" {
		t.Fatalf("span error type = %q, want github_app_jwt_sign_failed", got)
	}
}

func TestAppPool_FailsOverWhenOneMembersKeyCannotSign(t *testing.T) {
	srv := newMockGitHubServer(42, succeedHandler("ghs_from_signing_member"))
	defer srv.Close()

	broken := &countingKey{key: generateTestKey(t), err: errors.New("vault unreachable")}
	healthy := &countingKey{key: generateTestKey(t)}
	pool := NewAppPool("checkout", []PoolMember{
		{Instance: "checkout-2", Provider: NewAppTokenProvider(NewAppCredentialSource("checkout", "checkout-2", 2, healthy), srv.URL, nil)},
		// A fresh pool starts on ring index 1, so the broken member is tried
		// first and the call has to fail over.
		{Instance: "checkout-1", Provider: NewAppTokenProvider(NewAppCredentialSource("checkout", "checkout-1", 1, broken), srv.URL, nil)},
	}, "round_robin", 0, 2, nil)

	token, instance, err := pool.GetInstallationToken(context.Background(), "myorg/myrepo",
		map[string]string{"contents": "read"}, nil, "test")
	if err != nil {
		t.Fatalf("GetInstallationToken: %v", err)
	}
	if token != "ghs_from_signing_member" || instance != "checkout-2" {
		t.Fatalf("got token %q from %q, want the healthy member's token", token, instance)
	}
	if broken.calls.Load() == 0 {
		t.Fatal("the member whose key cannot sign was never tried; the test did not exercise failover")
	}
}
