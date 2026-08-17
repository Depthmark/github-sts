package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const testOCIRepository = "registry.example.com/depthmark/policy"

func TestOCILoader_MovingTagUsesResolvedDigestForVerifyAndPull(t *testing.T) {
	imageA := newTestOCIImage(t, []byte("bundle A"))
	imageB := newTestOCIImage(t, []byte("bundle B"))
	digestA := imageDigest(t, imageA)
	digestB := imageDigest(t, imageB)
	tagRef := testOCIRepository + ":moving"
	digestRefA := testOCIRepository + "@" + digestA.String()

	tags := map[string]v1.Hash{tagRef: digestA}
	images := map[string]v1.Image{
		digestA.String(): imageA,
		digestB.String(): imageB,
	}
	var verifiedRef, pulledRef string
	loader := OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(ref name.Reference, _ []remote.Option) (v1.Hash, error) {
			return tags[ref.String()], nil
		},
		verifySignature: func(_ context.Context, ref name.Reference, _ VerifyConfig, _ []remote.Option) error {
			// The loader has completed resolution before invoking this callback. Move
			// the tag before accepting the verification reference; a later tag lookup
			// would now select image B.
			tags[tagRef] = digestB
			verifiedRef = ref.String()
			return nil
		},
		pullImage: func(ref name.Reference, _ []remote.Option) (v1.Image, error) {
			pulledRef = ref.String()
			if tag, ok := ref.(name.Tag); ok {
				return images[tags[tag.String()].String()], nil
			}
			digest, ok := ref.(name.Digest)
			if !ok {
				return nil, fmt.Errorf("unexpected reference type %T", ref)
			}
			return images[digest.DigestStr()], nil
		},
	}}

	fetch, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + tagRef}, VerifyConfig{PublicKeyRef: "unused-by-fake.pub"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if verifiedRef != digestRefA {
		t.Fatalf("verified reference = %q, want %q", verifiedRef, digestRefA)
	}
	if pulledRef != digestRefA {
		t.Fatalf("pulled reference = %q, want %q", pulledRef, digestRefA)
	}
	if fetch.Digest != digestA.String() {
		t.Fatalf("fetch digest = %q, want %q", fetch.Digest, digestA.String())
	}
	if !bytes.Equal(fetch.Tarball, []byte("bundle A")) {
		t.Fatalf("fetch tarball = %q, want image A bytes", fetch.Tarball)
	}
}

func TestOCILoader_InProcessRegistryMovingTagUsesResolvedDigest(t *testing.T) {
	server := httptest.NewServer(quietTestRegistry())
	defer server.Close()
	repository := localRegistryRepository(t, server, "depthmark/policy")
	tag, err := name.NewTag(repository+":moving", name.StrictValidation)
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	imageA := newTestOCIImage(t, []byte("registry bundle A"))
	imageB := newTestOCIImage(t, []byte("registry bundle B"))
	digestA := imageDigest(t, imageA)
	digestB := imageDigest(t, imageB)
	if err := remote.Write(tag, imageA); err != nil {
		t.Fatalf("publish image A: %v", err)
	}

	var verifiedRef string
	loader := OCILoader{operations: &ociLoaderOperations{
		verifySignature: func(_ context.Context, ref name.Reference, _ VerifyConfig, _ []remote.Option) error {
			verifiedRef = ref.String()
			return remote.Write(tag, imageB)
		},
	}}
	fetch, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + tag.String()}, VerifyConfig{PublicKeyRef: "unused-by-fake.pub"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if verifiedRef != tag.Context().Digest(digestA.String()).String() {
		t.Fatalf("verified reference = %q, want digest A", verifiedRef)
	}
	if fetch.Digest != digestA.String() || !bytes.Equal(fetch.Tarball, []byte("registry bundle A")) {
		t.Fatalf("fetch = digest %q bytes %q, want image A", fetch.Digest, fetch.Tarball)
	}
	descriptor, err := remote.Get(tag)
	if err != nil {
		t.Fatalf("resolve moved tag: %v", err)
	}
	if descriptor.Digest != digestB {
		t.Fatalf("moved tag digest = %s, want %s", descriptor.Digest, digestB)
	}
}

func TestOCILoader_BasicAuthOptionsReachResolveVerifyAndPull(t *testing.T) {
	const username = "policy-reader"
	const password = "test-secret"
	var authorized atomic.Int64
	registryHandler := quietTestRegistry()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsername, gotPassword, ok := r.BasicAuth()
		if !ok || gotUsername != username || gotPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authorized.Add(1)
		registryHandler.ServeHTTP(w, r)
	}))
	defer server.Close()
	repository := localRegistryRepository(t, server, "depthmark/private-policy")
	tag, err := name.NewTag(repository+":v1", name.StrictValidation)
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	image := newTestOCIImage(t, []byte("private bundle"))
	auth := &authn.Basic{Username: username, Password: password}
	if err := remote.Write(tag, image, remote.WithAuth(auth)); err != nil {
		t.Fatalf("publish private image: %v", err)
	}
	beforeFetch := authorized.Load()
	t.Setenv("GITHUBSTS_TEST_REGISTRY_PASSWORD", password)
	verificationCalls := 0
	loader := OCILoader{operations: &ociLoaderOperations{
		verifySignature: func(_ context.Context, ref name.Reference, _ VerifyConfig, opts []remote.Option) error {
			verificationCalls++
			_, err := remote.Get(ref, opts...)
			return err
		},
	}}
	fetch, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + tag.String()}, VerifyConfig{
		PublicKeyRef: "unused-by-fake.pub",
		RegistryAuth: RegistryAuthConfig{
			Mode: "basic", Username: username, PasswordEnv: "GITHUBSTS_TEST_REGISTRY_PASSWORD",
		},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if verificationCalls != 1 || fetch.Digest == "" || !bytes.Equal(fetch.Tarball, []byte("private bundle")) {
		t.Fatalf("fetch = %+v, verification calls = %d", fetch, verificationCalls)
	}
	if authorized.Load() <= beforeFetch {
		t.Fatal("fetch made no authenticated registry requests")
	}
}

func TestOCILoader_DigestReferenceBypassesTagResolution(t *testing.T) {
	image := newTestOCIImage(t, []byte("pinned bundle"))
	digest := imageDigest(t, image)
	digestRef := testOCIRepository + "@" + digest.String()
	resolveCalls := 0
	loader := OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			resolveCalls++
			return v1.Hash{}, errors.New("tag resolver must not be called")
		},
		pullImage: func(ref name.Reference, _ []remote.Option) (v1.Image, error) {
			if ref.String() != digestRef {
				return nil, fmt.Errorf("pull reference = %q, want %q", ref.String(), digestRef)
			}
			return image, nil
		},
	}}

	fetch, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + digestRef}, VerifyConfig{SkipVerification: true})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("tag resolver calls = %d, want 0", resolveCalls)
	}
	if fetch.Digest != digest.String() {
		t.Fatalf("fetch digest = %q, want %q", fetch.Digest, digest.String())
	}
}

func TestOCILoader_VerificationFailureIsTypedAndPreventsPull(t *testing.T) {
	image := newTestOCIImage(t, []byte("untrusted bundle"))
	digest := imageDigest(t, image)
	verifyErr := errors.New("signature rejected")
	pullCalls := 0
	loader := OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			return digest, nil
		},
		verifySignature: func(context.Context, name.Reference, VerifyConfig, []remote.Option) error {
			return verifyErr
		},
		pullImage: func(name.Reference, []remote.Option) (v1.Image, error) {
			pullCalls++
			return image, nil
		},
	}}

	_, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + testOCIRepository + ":untrusted"}, VerifyConfig{PublicKeyRef: "unused-by-fake.pub"})
	if err == nil {
		t.Fatal("Fetch returned nil error, want verification failure")
	}
	var typedErr *verificationError
	if !errors.As(err, &typedErr) {
		t.Fatalf("Fetch error type = %T, want *verificationError", err)
	}
	if !errors.Is(err, verifyErr) {
		t.Fatalf("Fetch error does not unwrap verifier error: %v", err)
	}
	if pullCalls != 0 {
		t.Fatalf("pull calls = %d, want 0", pullCalls)
	}
}

func TestOCILoader_RejectsPulledImageDigestMismatch(t *testing.T) {
	imageA := newTestOCIImage(t, []byte("resolved bundle"))
	imageB := newTestOCIImage(t, []byte("pulled bundle"))
	digestA := imageDigest(t, imageA)
	digestB := imageDigest(t, imageB)
	loader := OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			return digestA, nil
		},
		pullImage: func(name.Reference, []remote.Option) (v1.Image, error) {
			return imageB, nil
		},
	}}

	_, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + testOCIRepository + ":mismatch"}, VerifyConfig{SkipVerification: true})
	if err == nil {
		t.Fatal("Fetch returned nil error, want digest mismatch")
	}
	var typedErr *digestMismatchError
	if !errors.As(err, &typedErr) {
		t.Fatalf("Fetch error type = %T, want *digestMismatchError", err)
	}
	if !strings.Contains(err.Error(), "expected "+digestA.String()+", got "+digestB.String()) {
		t.Fatalf("Fetch error = %q, want both resolved and pulled digests", err)
	}
}

func TestOCILoader_VerifierReceivesResolvedDigestForEachVerificationMode(t *testing.T) {
	image := newTestOCIImage(t, []byte("verified bundle"))
	digest := imageDigest(t, image)
	wantRef := testOCIRepository + "@" + digest.String()
	tests := []struct {
		name   string
		verify VerifyConfig
	}{
		{
			name: "keyless",
			verify: VerifyConfig{
				CertificateIdentityRegexp: "^https://github.com/depthmark/.+$",
				CertificateOIDCIssuer:     "https://token.actions.githubusercontent.com",
			},
		},
		{
			name:   "public key",
			verify: VerifyConfig{PublicKeyRef: "unused-by-fake.pub"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotRef string
			var gotVerify VerifyConfig
			loader := OCILoader{operations: &ociLoaderOperations{
				resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
					return digest, nil
				},
				verifySignature: func(_ context.Context, ref name.Reference, verify VerifyConfig, _ []remote.Option) error {
					gotRef = ref.String()
					gotVerify = verify
					return nil
				},
				pullImage: func(name.Reference, []remote.Option) (v1.Image, error) {
					return image, nil
				},
			}}

			if _, err := loader.Fetch(context.Background(), Source{Raw: "oci://" + testOCIRepository + ":verified"}, tt.verify); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if gotRef != wantRef {
				t.Fatalf("verifier reference = %q, want %q", gotRef, wantRef)
			}
			if gotVerify != tt.verify {
				t.Fatalf("verifier config = %#v, want %#v", gotVerify, tt.verify)
			}
		})
	}
}

func TestOCILoader_OperationalFailuresRemainTyped(t *testing.T) {
	image := newTestOCIImage(t, []byte("bundle"))
	digest := imageDigest(t, image)
	tagSource := Source{Raw: "oci://" + testOCIRepository + ":failure"}
	tests := []struct {
		name   string
		loader OCILoader
		assert func(error) bool
		cause  error
	}{
		{
			name:  "resolve",
			cause: errors.New("resolve failed"),
			assert: func(err error) bool {
				var target *resolveError
				return errors.As(err, &target)
			},
		},
		{
			name:  "pull",
			cause: errors.New("pull failed"),
			assert: func(err error) bool {
				var target *pullError
				return errors.As(err, &target)
			},
		},
		{
			name: "layer",
			assert: func(err error) bool {
				var target *layerError
				return errors.As(err, &target)
			},
		},
	}

	tests[0].loader = OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			return v1.Hash{}, tests[0].cause
		},
	}}
	tests[1].loader = OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			return digest, nil
		},
		pullImage: func(name.Reference, []remote.Option) (v1.Image, error) {
			return nil, tests[1].cause
		},
	}}
	emptyDigest := imageDigest(t, empty.Image)
	tests[2].loader = OCILoader{operations: &ociLoaderOperations{
		resolveTag: func(name.Reference, []remote.Option) (v1.Hash, error) {
			return emptyDigest, nil
		},
		pullImage: func(name.Reference, []remote.Option) (v1.Image, error) {
			return empty.Image, nil
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.loader.Fetch(context.Background(), tagSource, VerifyConfig{SkipVerification: true})
			if err == nil {
				t.Fatal("Fetch returned nil error")
			}
			if !tt.assert(err) {
				t.Fatalf("Fetch error type = %T, want typed %s error", err, tt.name)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Fatalf("Fetch error does not unwrap cause: %v", err)
			}
		})
	}
}

func newTestOCIImage(t *testing.T, bundle []byte) v1.Image {
	t.Helper()
	layer := static.NewLayer(bundle, types.OCILayer)
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("create in-memory image: %v", err)
	}
	return image
}

func imageDigest(t *testing.T, image v1.Image) v1.Hash {
	t.Helper()
	digest, err := image.Digest()
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	return digest
}

func localRegistryRepository(t *testing.T, server *httptest.Server, path string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("parse registry address: %v", err)
	}
	if host != "127.0.0.1" && host != "::1" {
		t.Fatalf("unexpected registry host %q", host)
	}
	return "localhost:" + port + "/" + path
}

func quietTestRegistry() http.Handler {
	return registry.New(registry.Logger(log.New(io.Discard, "", 0)))
}
