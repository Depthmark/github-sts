package bundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
)

const (
	mediaTypeOCIEmpty     = "application/vnd.oci.empty.v1+json"
	mediaTypeSPDXSBOM     = "application/spdx+json"
	mediaTypeOldSigstoreB = "application/vnd.dev.sigstore.bundle+json;version=0.1"
)

// TestRequireVerifiableCandidate covers every discovery outcome. Only one of
// them may proceed to verification; the rest have to produce an error specific
// enough to tell an operator what to do next.
func TestRequireVerifiableCandidate(t *testing.T) {
	digestRef := testDigestRef(t)
	candidate := referrerCandidate{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("ab", 32)}, Evidence: "evidence"}

	tests := []struct {
		name     string
		found    discoveredReferrers
		wantCode string
	}{
		{
			name:  "a standardized candidate proceeds",
			found: discoveredReferrers{standardized: referrerCandidates{candidate}},
		},
		{
			name: "a standardized candidate proceeds even beside an unsupported one",
			found: discoveredReferrers{
				standardized: referrerCandidates{candidate},
				unsupported:  referrerCandidates{candidate},
			},
		},
		{
			name:     "nothing attached at all",
			found:    discoveredReferrers{},
			wantCode: codeSignatureNotFound,
		},
		{
			name:     "an unreadable signature referrer is not a missing one",
			found:    discoveredReferrers{malformed: referrerCandidates{candidate}},
			wantCode: codeMalformedSignature,
		},
		{
			name:     "a transitional or unknown-version referrer names the format problem",
			found:    discoveredReferrers{unsupported: referrerCandidates{candidate}},
			wantCode: codeUnsupportedFormat,
		},
		{
			name: "malformed is reported ahead of unsupported",
			found: discoveredReferrers{
				malformed:   referrerCandidates{candidate},
				unsupported: referrerCandidates{candidate},
			},
			wantCode: codeMalformedSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireVerifiableCandidate(digestRef, tt.found)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("requireVerifiableCandidate rejected a verifiable candidate: %v", err)
				}
				return
			}
			assertSignatureErrorCode(t, err, tt.wantCode)
		})
	}
}

// TestCosignVerifier_ClassifyReferrers covers the evidence chain. Producers and
// registries populate different fields, so a referrer has to be recognized from
// whichever one is actually present.
func TestCosignVerifier_ClassifyReferrers(t *testing.T) {
	tests := []struct {
		name        string
		referrer    referrerFixture
		wantClass   referrerClass
		description string
	}{
		{
			name: "standardized bundle referrer as cosign v3.1.3 writes it",
			referrer: referrerFixture{
				artifactType:    mediaTypeSigstoreBundleV03,
				configMediaType: mediaTypeOCIEmpty,
				layerMediaType:  mediaTypeSigstoreBundleV03,
			},
			wantClass: referrerStandardized,
		},
		{
			name: "standardized bundle with no top-level artifactType is still recognized",
			referrer: referrerFixture{
				artifactType:    "",
				configMediaType: mediaTypeOCIEmpty,
				layerMediaType:  mediaTypeSigstoreBundleV03,
			},
			wantClass:   referrerStandardized,
			description: "layer evidence alone must be enough",
		},
		{
			name: "cosign v3.0.5 transitional referrer omits artifactType entirely",
			referrer: referrerFixture{
				artifactType:    "",
				configMediaType: mediaTypeCosignArtifactSig,
				layerMediaType:  mediaTypeCosignSimpleSigning,
			},
			wantClass:   referrerUnsupported,
			description: "must never read as modern absence, which would allow a downgrade",
		},
		{
			name: "cosign v3.1.3 transitional referrer declares its artifactType",
			referrer: referrerFixture{
				artifactType:    mediaTypeCosignArtifactSig,
				configMediaType: mediaTypeCosignArtifactSig,
				layerMediaType:  mediaTypeCosignSimpleSigning,
			},
			wantClass: referrerUnsupported,
		},
		{
			name: "sigstore bundle version this build cannot verify",
			referrer: referrerFixture{
				artifactType:    mediaTypeOldSigstoreB,
				configMediaType: mediaTypeOCIEmpty,
				layerMediaType:  mediaTypeOldSigstoreB,
			},
			wantClass:   referrerUnsupported,
			description: "recognized but unsupported, not absent",
		},
		{
			name: "an SBOM attached to the same digest is unrelated",
			referrer: referrerFixture{
				artifactType:    mediaTypeSPDXSBOM,
				configMediaType: mediaTypeOCIEmpty,
				layerMediaType:  mediaTypeSPDXSBOM,
			},
			wantClass:   referrerUnrelated,
			description: "must not block the legacy path",
		},
		{
			name: "standardized referrer bound to a different subject",
			referrer: referrerFixture{
				artifactType:    mediaTypeSigstoreBundleV03,
				configMediaType: mediaTypeOCIEmpty,
				layerMediaType:  mediaTypeSigstoreBundleV03,
				wrongSubject:    true,
			},
			wantClass:   referrerMalformed,
			description: "a signature for other content must not authorize this digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness := newRegistryHarness(t, true)
			subject := harness.publishSubject(t)
			descriptor := harness.publishReferrer(t, subject, tt.referrer)
			if tt.referrer.wrongSubject {
				harness.forgeReferrers(t, []v1.Descriptor{descriptor})
			}

			found, err := cosignVerifier{}.discover(subject, harness.options())
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			gotClass := soleClass(t, found)
			if gotClass != tt.wantClass {
				t.Fatalf("class = %v, want %v (%s)", gotClass, tt.wantClass, tt.description)
			}
		})
	}
}

// TestCosignVerifier_DiscoveryWorksWithoutReferrersAPI covers registries that
// predate the Referrers API. go-containerregistry falls back to the referrers
// tag scheme by default, and that default must not be turned off: without it
// every such registry would hard-fail discovery and no bundle stored there
// could ever be verified.
//
// The tell is which error comes back. signature_not_found means discovery
// worked and found nothing; discovery_failed would mean the fallback broke.
func TestCosignVerifier_DiscoveryWorksWithoutReferrersAPI(t *testing.T) {
	harness := newRegistryHarness(t, false)
	subject := harness.publishSubject(t)

	err := cosignVerifier{}.verify(context.Background(), subject, VerifyConfig{PublicKeyRef: "unused.pub"}, harness.options())
	assertSignatureErrorCode(t, err, codeSignatureNotFound)
}

// TestCosignVerifier_DiscoveryFailureIsNotReportedAsMissing keeps a registry
// problem distinguishable from an unsigned bundle. A 500 says nothing about
// what is attached to the digest, and telling an operator to go sign a bundle
// that is already signed sends them down the wrong path entirely.
func TestCosignVerifier_DiscoveryFailureIsNotReportedAsMissing(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			harness := newRegistryHarness(t, true)
			subject := harness.publishSubject(t)
			harness.failReferrers(status)

			err := cosignVerifier{}.verify(context.Background(), subject, VerifyConfig{PublicKeyRef: "unused.pub"}, harness.options())
			assertSignatureErrorCode(t, err, codeDiscoveryFailed)
		})
	}
}

// TestCosignVerifier_RejectsTransitionalFormat covers a bundle signed with
// COSIGN_EXPERIMENTAL=1 --registry-referrers-mode=oci-1-1. The signature is
// really there, so reporting it as missing would send the publisher off to
// re-sign a bundle they already signed. The error has to name the format.
func TestCosignVerifier_RejectsTransitionalFormat(t *testing.T) {
	harness := newRegistryHarness(t, true)
	subject := harness.publishSubject(t)
	harness.publishReferrer(t, subject, referrerFixture{
		configMediaType: mediaTypeCosignArtifactSig,
		layerMediaType:  mediaTypeCosignSimpleSigning,
	})

	err := cosignVerifier{}.verify(context.Background(), subject, VerifyConfig{PublicKeyRef: "unused.pub"}, harness.options())
	assertSignatureErrorCode(t, err, codeUnsupportedFormat)
	if !strings.Contains(err.Error(), mediaTypeCosignArtifactSig) &&
		!strings.Contains(err.Error(), mediaTypeCosignSimpleSigning) {
		t.Fatalf("error does not name the format that was found: %v", err)
	}
}

// TestCosignVerifier_UnrelatedReferrersDoNotLookLikeSignatures makes sure an
// SBOM attached to the same digest is not mistaken for one. It is not a
// signature, so the bundle is unsigned and must say so.
func TestCosignVerifier_UnrelatedReferrersDoNotLookLikeSignatures(t *testing.T) {
	harness := newRegistryHarness(t, true)
	subject := harness.publishSubject(t)
	harness.publishReferrer(t, subject, referrerFixture{
		artifactType:    mediaTypeSPDXSBOM,
		configMediaType: mediaTypeOCIEmpty,
		layerMediaType:  mediaTypeSPDXSBOM,
	})

	err := cosignVerifier{}.verify(context.Background(), subject, VerifyConfig{PublicKeyRef: "unused.pub"}, harness.options())
	assertSignatureErrorCode(t, err, codeSignatureNotFound)
}

// TestCosignVerifier_NeverReadsTheLegacySignatureTag pins the decision to drop
// the old format. The legacy sha256-<digest>.sig tag is not a fallback, not a
// last resort, and not consulted at all: the verifier must never issue a
// request for it, whatever state the registry is in.
func TestCosignVerifier_NeverReadsTheLegacySignatureTag(t *testing.T) {
	harness := newRegistryHarness(t, true)
	subject := harness.publishSubject(t)

	// A bundle carrying only a legacy signature is an unsigned bundle now.
	err := cosignVerifier{}.verify(context.Background(), subject, VerifyConfig{PublicKeyRef: "unused.pub"}, harness.options())
	assertSignatureErrorCode(t, err, codeSignatureNotFound)
	harness.assertLegacyTagNeverRequested(t, subject)
}

// TestRequireCosignSignPredicate is the check cosign does not do for us.
// IntotoSubjectClaimVerifier only matches the subject digest, so without this an
// SBOM or provenance attestation signed by the trusted identity for the same
// digest would authorize the bundle.
func TestRequireCosignSignPredicate(t *testing.T) {
	tests := []struct {
		name         string
		predicates   []string
		wantAccepted bool
	}{
		{
			name:         "cosign image signature is accepted",
			predicates:   []string{cosigntypes.CosignSignPredicateType},
			wantAccepted: true,
		},
		{
			name:       "SPDX SBOM attestation is rejected",
			predicates: []string{"https://spdx.dev/Document"},
		},
		{
			name:       "SLSA provenance attestation is rejected",
			predicates: []string{"https://slsa.dev/provenance/v1"},
		},
		{
			name:         "a cosign signature alongside other attestations is accepted",
			predicates:   []string{"https://slsa.dev/provenance/v1", cosigntypes.CosignSignPredicateType},
			wantAccepted: true,
		},
		{
			name:       "no attestations at all is rejected",
			predicates: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestations := make([]ociSignatureStub, 0, len(tt.predicates))
			for _, predicate := range tt.predicates {
				attestations = append(attestations, newAttestationStub(t, predicate))
			}
			err := requireCosignSignPredicate(attestations)
			if tt.wantAccepted && err != nil {
				t.Fatalf("requireCosignSignPredicate rejected a valid cosign signature: %v", err)
			}
			if !tt.wantAccepted && err == nil {
				t.Fatal("requireCosignSignPredicate accepted an attestation that is not a cosign image signature")
			}
		})
	}
}

// TestCosignVerifier_ProductionConfigCannotDisableTransparency locks the
// test-only seam shut. If a future change ever routes a config value into these
// fields, this fails.
func TestCosignVerifier_ProductionConfigCannotDisableTransparency(t *testing.T) {
	production := cosignVerifier{}
	if production.testOnlyIgnoreTlog {
		t.Fatal("production verifier has transparency verification disabled")
	}
	if production.testOnlyTrustedMaterial != nil {
		t.Fatal("production verifier has a substituted trusted root")
	}

	// Every field an operator can actually set, including the ones a hostile
	// config could try to abuse. None may reach the seam.
	for _, verify := range []VerifyConfig{
		{CertificateIdentityRegexp: ".*", CertificateOIDCIssuer: "https://token.actions.githubusercontent.com"},
		{PublicKeyRef: "cosign.pub"},
		{SkipVerification: true},
		{PublicKeyRef: "cosign.pub", RegistryAuth: RegistryAuthConfig{Mode: "basic", Username: "u", PasswordEnv: "P"}},
	} {
		checkOpts, err := cosignVerifier{}.checkOpts(verify, nil)
		if err != nil {
			// Loading the real trusted root needs network access, which this
			// test does not require and must not depend on. The seam assertions
			// below are what matter.
			continue
		}
		if checkOpts.IgnoreTlog {
			t.Fatalf("VerifyConfig %+v produced IgnoreTlog=true", verify)
		}
		if checkOpts.IgnoreSCT {
			t.Fatalf("VerifyConfig %+v produced IgnoreSCT=true", verify)
		}
		if checkOpts.ExperimentalOCI11 {
			t.Fatalf("VerifyConfig %+v enabled the transitional OCI 1.1 path", verify)
		}
	}
}

// TestCosignVerifier_RequiresImmutableDigest guards the invariant that makes
// resolve-verify-pull safe: a tag can move between the resolve and the
// verification, so the verifier only ever accepts a digest.
func TestCosignVerifier_RequiresImmutableDigest(t *testing.T) {
	tag, err := name.NewTag(testOCIRepository+":latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	err = cosignVerifier{}.verify(context.Background(), tag, VerifyConfig{PublicKeyRef: "unused.pub"}, nil)
	assertSignatureErrorCode(t, err, codeMalformedSignature)
}

// TestSignatureError_ExposesTypedFields makes sure the manager can report the
// failure phase without parsing a message, and that the cause stays unwrappable.
func TestSignatureError_ExposesTypedFields(t *testing.T) {
	cause := errors.New("registry said no")
	err := error(&signatureError{
		Code:      codeDiscoveryFailed,
		Operation: "referrer_discovery",
		Err:       cause,
	})
	if !errors.Is(err, cause) {
		t.Fatal("signatureError does not unwrap to its cause")
	}
	var typed *signatureError
	if !errors.As(err, &typed) || typed.Code != codeDiscoveryFailed {
		t.Fatalf("errors.As did not recover the code, got %+v", typed)
	}
	if !strings.Contains(err.Error(), codeDiscoveryFailed) || !strings.Contains(err.Error(), "referrer_discovery") {
		t.Fatalf("error message %q omits the code or operation", err.Error())
	}
}

// --- helpers ---

// registryHarness runs an in-process OCI registry and records every request
// path, so a test can prove the legacy signature tag was never even asked for.
type registryHarness struct {
	server     *httptest.Server
	repository name.Repository

	mu       sync.Mutex
	paths    []string
	failCode int
	forged   []byte
}

func newRegistryHarness(t *testing.T, referrersAPI bool) *registryHarness {
	t.Helper()
	h := &registryHarness{}
	inner := registry.New(
		registry.Logger(log.New(io.Discard, "", 0)),
		registry.WithReferrersSupport(referrersAPI),
	)
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.paths = append(h.paths, r.URL.Path)
		failCode, forged := h.failCode, h.forged
		isReferrers := strings.Contains(r.URL.Path, "/referrers/")
		h.mu.Unlock()
		if isReferrers && failCode != 0 {
			w.WriteHeader(failCode)
			return
		}
		if isReferrers && forged != nil {
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(forged)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(h.server.Close)

	repository, err := name.NewRepository(localRegistryRepository(t, h.server, "depthmark/policy"), name.StrictValidation)
	if err != nil {
		t.Fatalf("parse repository: %v", err)
	}
	h.repository = repository
	return h
}

func (h *registryHarness) options() []remote.Option {
	return []remote.Option{remote.WithContext(context.Background())}
}

// failReferrers makes the referrers endpoint return status, modelling an
// authentication, rate-limit, or server failure during discovery.
func (h *registryHarness) failReferrers(status int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failCode = status
}

// forgeReferrers makes the referrers endpoint list descriptors the registry
// would not normally return for this subject. A conforming registry filters
// referrers by subject, so this models a compromised or buggy one attempting a
// confused-deputy hand-off: offering a signature that is really bound to other
// content.
func (h *registryHarness) forgeReferrers(t *testing.T, descriptors []v1.Descriptor) {
	t.Helper()
	index := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     descriptors,
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal forged referrers index: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.forged = raw
}

// publishSubject writes a bundle image and returns its immutable reference.
func (h *registryHarness) publishSubject(t *testing.T) name.Digest {
	t.Helper()
	image := newTestOCIImage(t, []byte("policy bundle"))
	tag := h.repository.Tag("bundle")
	if err := remote.Write(tag, image); err != nil {
		t.Fatalf("publish subject: %v", err)
	}
	return h.repository.Digest(imageDigest(t, image).String())
}

// referrerFixture describes one referrer manifest to publish. The fields map
// onto the places cosign puts the media type, so a test can reproduce what a
// specific producer version actually wrote.
type referrerFixture struct {
	artifactType    string
	configMediaType string
	layerMediaType  string
	wrongSubject    bool
}

func (h *registryHarness) publishReferrer(t *testing.T, subject name.Digest, fixture referrerFixture) v1.Descriptor {
	t.Helper()

	configLayer := static.NewLayer([]byte("{}"), types.MediaType(fixture.configMediaType))
	payloadLayer := static.NewLayer([]byte(`{"fixture":"referrer"}`), types.MediaType(fixture.layerMediaType))
	for _, layer := range []v1.Layer{configLayer, payloadLayer} {
		if err := remote.WriteLayer(h.repository, layer); err != nil {
			t.Fatalf("write referrer blob: %v", err)
		}
	}

	subjectDigest := subject.DigestStr()
	if fixture.wrongSubject {
		subjectDigest = "sha256:" + strings.Repeat("cd", 32)
	}
	subjectHash, err := v1.NewHash(subjectDigest)
	if err != nil {
		t.Fatalf("parse subject digest: %v", err)
	}

	manifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  fixture.artifactType,
		Config:        descriptorFor(t, configLayer),
		Layers:        []v1.Descriptor{descriptorFor(t, payloadLayer)},
		Subject: &v1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    subjectHash,
			Size:      1,
		},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal referrer manifest: %v", err)
	}
	digest, _, err := v1.SHA256(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("digest referrer manifest: %v", err)
	}
	target := h.repository.Digest(digest.String())
	if err := remote.Put(target, rawManifest{raw: raw, mediaType: types.OCIManifestSchema1}); err != nil {
		t.Fatalf("publish referrer manifest: %v", err)
	}
	return v1.Descriptor{
		MediaType:    types.OCIManifestSchema1,
		Digest:       digest,
		Size:         int64(len(raw)),
		ArtifactType: fixture.artifactType,
	}
}

// assertLegacyTagNeverRequested proves the no-downgrade rule at the wire level:
// stronger than counting calls, because it shows the legacy signature was never
// even looked up.
func (h *registryHarness) assertLegacyTagNeverRequested(t *testing.T, subject name.Digest) {
	t.Helper()
	// The tag cosign v2 wrote and this build deliberately ignores.
	legacyTag := strings.Replace(subject.DigestStr(), ":", "-", 1) + ".sig"
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, path := range h.paths {
		if strings.Contains(path, legacyTag) {
			t.Fatalf("legacy signature tag %s was requested at %s; the legacy format is not supported and must never be consulted", legacyTag, path)
		}
	}
}

type rawManifest struct {
	raw       []byte
	mediaType types.MediaType
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.raw, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }
func (m rawManifest) Size() (int64, error)                { return int64(len(m.raw)), nil }

func (m rawManifest) Digest() (v1.Hash, error) {
	digest, _, err := v1.SHA256(strings.NewReader(string(m.raw)))
	return digest, err
}

func descriptorFor(t *testing.T, layer v1.Layer) v1.Descriptor {
	t.Helper()
	mediaType, err := layer.MediaType()
	if err != nil {
		t.Fatalf("layer media type: %v", err)
	}
	digest, err := layer.Digest()
	if err != nil {
		t.Fatalf("layer digest: %v", err)
	}
	size, err := layer.Size()
	if err != nil {
		t.Fatalf("layer size: %v", err)
	}
	return v1.Descriptor{MediaType: mediaType, Digest: digest, Size: size}
}

// soleClass asserts exactly one referrer was classified and returns its class.
func soleClass(t *testing.T, found discoveredReferrers) referrerClass {
	t.Helper()
	total := len(found.standardized) + len(found.unsupported) + len(found.malformed)
	switch {
	case total == 0:
		return referrerUnrelated
	case total > 1:
		t.Fatalf("expected one classified referrer, got standardized=%d unsupported=%d malformed=%d",
			len(found.standardized), len(found.unsupported), len(found.malformed))
	case len(found.standardized) == 1:
		return referrerStandardized
	case len(found.unsupported) == 1:
		return referrerUnsupported
	}
	return referrerMalformed
}

func assertSignatureErrorCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", wantCode)
	}
	var typed *signatureError
	if !errors.As(err, &typed) {
		t.Fatalf("error %v is not a *signatureError", err)
	}
	if typed.Code != wantCode {
		t.Fatalf("error code = %s, want %s (%v)", typed.Code, wantCode, err)
	}
}

func testDigestRef(t *testing.T) name.Digest {
	t.Helper()
	digestRef, err := name.NewDigest(testOCIRepository+"@sha256:"+strings.Repeat("ef", 32), name.StrictValidation)
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	return digestRef
}

// ociSignatureStub carries a DSSE envelope the way cosign returns one from
// VerifyImageAttestations, which is the only part requireCosignSignPredicate
// reads.
type ociSignatureStub struct {
	payload []byte
}

func (s ociSignatureStub) Payload() ([]byte, error) { return s.payload, nil }

func newAttestationStub(t *testing.T, predicateType string) ociSignatureStub {
	t.Helper()
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"subject":       []map[string]any{{"name": "bundle", "digest": map[string]string{"sha256": strings.Repeat("ef", 32)}}},
		"predicate":     map[string]any{},
	}
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statementJSON),
		"signatures":  []map[string]string{{"sig": "unused-by-this-check"}},
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return ociSignatureStub{payload: envelopeJSON}
}
