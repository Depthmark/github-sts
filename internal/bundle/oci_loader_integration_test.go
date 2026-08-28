package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestOCILoader_CosignCompatibility runs the producer/consumer compatibility
// matrix against a real registry holding fixtures that real cosign binaries
// produced. Building those fixtures needs Docker, a throwaway registry, and two
// pinned cosign binaries, so the producer half lives outside this repository:
// Depthmark-Lab/test-github-sts/scripts/local-oci-cosign-test.sh builds them,
// exports the two variables below, and runs this test against them.
//
// Skipping without those variables is the point. This repository's own CI never
// builds the fixtures; release-candidate validation is what exercises the
// producer side end to end.
//
// The unit tests in cosign_verifier_test.go prove the rules in isolation. This
// proves they hold against signatures cosign v2.6.5 and v3.1.3 actually wrote,
// which is where storage-format assumptions break.
//
// Half these cases assert a rejection. Only the standardized Sigstore bundle
// format is supported, so a bundle carrying a perfectly valid legacy signature
// is an unsigned bundle here, and that has to stay deliberate rather than drift
// back in.
//
// Discovery failures are covered hermetically by
// TestCosignVerifier_DiscoveryFailureIsNotReportedAsMissing: getting a real
// registry to return a 500 on cue would mean depending on it misbehaving.
func TestOCILoader_CosignCompatibility(t *testing.T) {
	registryHost := os.Getenv("GITHUBSTS_OCI_COMPAT_REGISTRY")
	publicKeyRef := os.Getenv("GITHUBSTS_OCI_COMPAT_PUBLIC_KEY")
	if registryHost == "" || publicKeyRef == "" {
		t.Skip("set GITHUBSTS_OCI_COMPAT_REGISTRY and GITHUBSTS_OCI_COMPAT_PUBLIC_KEY, or run Depthmark-Lab/test-github-sts/scripts/local-oci-cosign-test.sh")
	}

	tests := []struct {
		id         string
		repository string
		producer   string
		state      string
		wantCode   string // empty means the bundle must be accepted
	}{
		{
			id:         "C1",
			repository: "compat/c1",
			producer:   "cosign v2.6.5 defaults",
			state:      "legacy digest tag only",
			// cosign v2 wrote this shape by default. It is no longer a
			// supported format, so a publisher still on v2 defaults is
			// publishing an unsigned bundle as far as this broker is concerned.
			wantCode: codeSignatureNotFound,
		},
		{
			id:         "C2",
			repository: "compat/c2",
			producer:   "cosign v2.6.5 --new-bundle-format=true",
			state:      "standardized referrer only",
		},
		{
			id:         "C3",
			repository: "compat/c3",
			producer:   "cosign v3.1.3 --new-bundle-format=true with a no-service signing config",
			state:      "standardized referrer only",
		},
		{
			id:         "C4",
			repository: "compat/c4",
			producer:   "cosign v3.1.3 --registry-referrers-mode=legacy",
			state:      "legacy digest tag only",
			wantCode:   codeSignatureNotFound,
		},
		{
			id:         "C5",
			repository: "compat/c5",
			producer:   "cosign v3.1.3",
			state:      "valid standardized signature plus an untrusted legacy signature",
			// The legacy signature is simply not looked at, so its being
			// untrusted changes nothing.
		},
		{
			id:         "C6",
			repository: "compat/c6",
			producer:   "cosign v3.1.3",
			state:      "untrusted standardized signature plus a valid legacy signature",
			// A correctly signed legacy signature sits right there. Accepting it
			// would mean a broken modern signature can be papered over by
			// publishing an old-format one, which is the whole reason the legacy
			// path is gone.
			wantCode: codeCryptographicFailed,
		},
		{
			id:         "C9",
			repository: "compat/c9",
			producer:   "none",
			state:      "no signature at all",
			wantCode:   codeSignatureNotFound,
		},
		{
			id:         "C10",
			repository: "compat/c10",
			producer:   "cosign v3.1.3 COSIGN_EXPERIMENTAL=1 --registry-referrers-mode=oci-1-1",
			state:      "transitional OCI 1.1 signature referrer",
			wantCode:   codeUnsupportedFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.id+"_"+strings.ReplaceAll(tt.state, " ", "_"), func(t *testing.T) {
			source := Source{Raw: fmt.Sprintf("oci://%s/%s:latest", registryHost, tt.repository)}
			fetch, err := compatLoader().Fetch(context.Background(), source, VerifyConfig{PublicKeyRef: publicKeyRef})

			if tt.wantCode != "" {
				if err == nil {
					t.Fatalf("%s (%s, %s): accepted the bundle, want %s", tt.id, tt.producer, tt.state, tt.wantCode)
				}
				var sigErr *signatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("%s: error is not a *signatureError: %v", tt.id, err)
				}
				if sigErr.Code != tt.wantCode {
					t.Fatalf("%s (%s): code = %s, want %s: %v", tt.id, tt.state, sigErr.Code, tt.wantCode, err)
				}
				t.Logf("%s ok: %s -> %s", tt.id, tt.state, sigErr.Code)
				return
			}

			if err != nil {
				t.Fatalf("%s (%s, %s): %v", tt.id, tt.producer, tt.state, err)
			}
			if len(fetch.Tarball) == 0 || fetch.Digest == "" {
				t.Fatalf("%s: verified but returned an empty bundle", tt.id)
			}
			t.Logf("%s ok: %s -> accepted", tt.id, tt.state)
		})
	}
}

// TestOCILoader_CompatibilityBundleCompiles closes the loop: a bundle that
// passed verification has to be a bundle OPA can actually run, otherwise the
// matrix could pass on well-signed rubbish.
func TestOCILoader_CompatibilityBundleCompiles(t *testing.T) {
	registryHost := os.Getenv("GITHUBSTS_OCI_COMPAT_REGISTRY")
	publicKeyRef := os.Getenv("GITHUBSTS_OCI_COMPAT_PUBLIC_KEY")
	if registryHost == "" || publicKeyRef == "" {
		t.Skip("set GITHUBSTS_OCI_COMPAT_REGISTRY and GITHUBSTS_OCI_COMPAT_PUBLIC_KEY, or run Depthmark-Lab/test-github-sts/scripts/local-oci-cosign-test.sh")
	}

	source := Source{Raw: fmt.Sprintf("oci://%s/compat/c3:latest", registryHost)}
	fetch, err := compatLoader().Fetch(context.Background(), source, VerifyConfig{PublicKeyRef: publicKeyRef})
	if err != nil {
		t.Fatalf("fetch signed bundle: %v", err)
	}
	engine, err := NewEngine(context.Background(), fetch.Tarball)
	if err != nil {
		t.Fatalf("compile fetched bundle: %v", err)
	}
	decision, err := engine.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("eval fetched bundle: %v", err)
	}
	if !decision.Allow {
		t.Fatalf("local fixture decision denied: %#v", decision)
	}
}

// compatLoader builds a loader wired to the production verifier with the
// package-private transparency seam enabled.
//
// The fixtures are signed with --tlog-upload=false so the matrix can run with
// no route to Fulcio, Rekor, or a TSA, which is what makes it hermetic and
// deterministic. Everything else is the production path: the same discovery,
// the same routing, the same claim verifiers, the same predicate check.
//
// Transparency verification is the one thing this does not cover, and nothing
// in CI covers it either. TestOCILoader_LiveKeyless below is a manual
// procedure, so treat SCT, Rekor, and timestamp behaviour as verified only as
// recently as someone last ran it.
func compatLoader() OCILoader {
	return OCILoader{operations: &ociLoaderOperations{
		verifySignature: func(ctx context.Context, ref name.Reference, verify VerifyConfig, opts []remote.Option) error {
			return cosignVerifier{testOnlyIgnoreTlog: true}.verify(ctx, ref, verify, opts)
		},
	}}
}

// TestOCILoader_LiveKeyless verifies a real keyless signature through the
// unmodified production constructor: real Fulcio certificate, real SCT, real
// Rekor inclusion proof, real trusted root. It is the only check that exercises
// the production trust policy end to end.
//
// It is deliberately manual and deliberately absent from CI. Signing keyless
// from a Depthmark workflow would mint a certificate for that workflow identity
// and write a permanent, public Rekor entry on every run. Transparency-log
// entries cannot be withdrawn, so a routine CI job would leave an unbounded
// trail of throwaway signatures attributed to the organisation. Run it against
// a scratch registry in a lab account instead.
//
// Run it after any change to the verifier, the cosign dependency, or the trust
// policy:
//
//	# 1. Publish a bundle to a scratch repository you control.
//	opa build -b policy -o bundle.tar.gz
//	crane append --oci-empty-base --new_layer bundle.tar.gz \
//	  --new_tag ghcr.io/<lab-account>/live-keyless-smoke:$(date +%s)
//	REF=ghcr.io/<lab-account>/live-keyless-smoke@$(crane digest ...)
//
//	# 2. Sign it keyless. This writes to the public Rekor log.
//	cosign sign --yes "$REF"
//
//	# 3. Verify through the production path. The identity regexp must match the
//	#    signer exactly; a permissive one would accept anything Fulcio issues.
//	GITHUBSTS_LIVE_KEYLESS_REF="oci://$REF" \
//	GITHUBSTS_LIVE_KEYLESS_ISSUER=https://token.actions.githubusercontent.com \
//	GITHUBSTS_LIVE_KEYLESS_IDENTITY_REGEXP='^<exact signer identity>$' \
//	  go test ./internal/bundle -run TestOCILoader_LiveKeyless -count=1 -v
//
// For a signature made with `cosign sign` from a laptop rather than a workflow,
// the issuer is the OIDC provider used at the login prompt and the identity is
// the email address on the certificate.
//
// An automated version of this belongs in depthmark-lab, where a throwaway
// identity and its transparency-log trail carry no organisational meaning.
func TestOCILoader_LiveKeyless(t *testing.T) {
	ref := os.Getenv("GITHUBSTS_LIVE_KEYLESS_REF")
	identityRegexp := os.Getenv("GITHUBSTS_LIVE_KEYLESS_IDENTITY_REGEXP")
	issuer := os.Getenv("GITHUBSTS_LIVE_KEYLESS_ISSUER")
	if ref == "" || identityRegexp == "" || issuer == "" {
		t.Skip("manual procedure: see the recipe on this test for how to run it against a scratch registry")
	}

	verify := VerifyConfig{
		CertificateIdentityRegexp: identityRegexp,
		CertificateOIDCIssuer:     issuer,
	}
	if username := os.Getenv("GITHUBSTS_LIVE_KEYLESS_REGISTRY_USERNAME"); username != "" {
		verify.RegistryAuth = RegistryAuthConfig{
			Mode:        "basic",
			Username:    username,
			PasswordEnv: "GITHUBSTS_LIVE_KEYLESS_REGISTRY_PASSWORD",
		}
	}

	// OCILoader{} with no operations override: the real resolver, the real
	// verifier, the real trusted root, transparency enabled.
	fetch, err := OCILoader{}.Fetch(context.Background(), Source{Raw: ref}, verify)
	if err != nil {
		t.Fatalf("production verification of a live keyless signature failed: %v", err)
	}
	if len(fetch.Tarball) == 0 {
		t.Fatal("verified but returned an empty bundle")
	}
	t.Logf("live keyless ok: %s", fetch.Digest)
}
