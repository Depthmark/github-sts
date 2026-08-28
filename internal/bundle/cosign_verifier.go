package bundle

// Cosign OCI signature verification.
//
// Only one storage format is accepted: a standardized Sigstore bundle published
// as an OCI 1.1 referrer, which is what cosign v3 writes by default. The older
// simple-signing payload on a mutable sha256-<digest>.sig tag is not verified,
// and neither is the transitional OCI 1.1 signature referrer.
//
// Supporting a second format would mean the broker could be steered onto the
// weaker one by anyone able to suppress or corrupt the modern signature. There
// is nothing to migrate, so there is no reason to carry that risk.
//
// Cosign reaches the standardized format only through VerifyImageAttestations:
// VerifyImageSignatures rejects NewBundleFormat outright, and a Sigstore bundle
// is carried as a DSSE envelope whatever it attests to.
//
// Referrers are classified before cosign is called. That is a diagnostic
// control, not a trust one. Cosign's GetBundles skips candidates it cannot
// parse and then reports one ErrNoMatchingAttestations whether there were no
// candidates at all, one malformed candidate, or a bundle version it considers
// too old. Collapsing those into "no signatures found" is exactly the unhelpful
// error this package exists to stop producing.

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Media types used to classify referrers.
const (
	// mediaTypeSigstoreBundlePrefix covers every standardized Sigstore bundle
	// version, including the v0.1 and v0.2 shapes that carry the version in a
	// parameter rather than the type itself. Matching the prefix but not the
	// exact supported version below means "recognized, not supported", which
	// must never be reported as absence.
	mediaTypeSigstoreBundlePrefix = "application/vnd.dev.sigstore.bundle"
	mediaTypeSigstoreBundleV03    = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// mediaTypeCosignArtifactSig and mediaTypeCosignSimpleSigning identify the
	// transitional cosign OCI 1.1 signature referrer, written by
	// --registry-referrers-mode=oci-1-1. It is recognized and explicitly
	// unsupported. Cosign v3.0.5 wrote this referrer with no top-level
	// artifactType, so the layer type is often the only usable evidence.
	mediaTypeCosignArtifactSig   = "application/vnd.dev.cosign.artifact.sig.v1+json"
	mediaTypeCosignSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// Error codes reported to operators. Each one names a distinct failure phase so
// a missing signature can be told apart from a discovery, trust, or
// cryptographic failure.
//
// Identity and transparency failures are not separate codes. Cosign and
// sigstore-go report both as unexported error strings with no stable type to
// match on, and guessing at them by string comparison would be a fragile basis
// for a security decision. They surface as codeCryptographicFailed with the
// underlying cause wrapped, which preserves the diagnostic without inventing a
// classification the dependency does not actually support.
const (
	codeDiscoveryFailed     = "discovery_failed"
	codeUnsupportedFormat   = "unsupported_signature_format"
	codeMalformedSignature  = "malformed_signature"
	codePredicateMismatch   = "predicate_mismatch"
	codeCryptographicFailed = "cryptographic_verification_failed"
	codeSignatureNotFound   = "signature_not_found"
	codeTrustRootFailed     = "trust_root_unavailable"
)

// signatureError carries the failure phase and, where one was selected, the
// storage format. It stays inside the package; callers read its fields for
// structured logging rather than parsing the message.
type signatureError struct {
	Code      string
	Operation string
	Err       error
}

func (e *signatureError) Error() string {
	return fmt.Sprintf("bundle cosign verifier: %s during %s: %v", e.Code, e.Operation, e.Err)
}

func (e *signatureError) Unwrap() error { return e.Err }

// cosignVerifier verifies one resolved digest against a VerifyConfig.
//
// The two testOnly fields exist so package tests can run against fixtures
// signed with --tlog-upload=false in a network-isolated job. Nothing outside a
// _test.go file in this package can set them: the struct and its fields are
// unexported, VerifyConfig has no corresponding field, and neither the YAML
// config nor any environment variable reaches them. TestCosignVerifier_
// ProductionConfigCannotDisableTransparency locks that in.
type cosignVerifier struct {
	// testOnlyIgnoreTlog sets CheckOpts.IgnoreTlog. Without it a fixture that
	// was never published to Rekor cannot verify at all, because
	// CheckOpts.verificationOptions requires a transparency log entry whenever
	// IgnoreTlog is false, public key or not.
	testOnlyIgnoreTlog bool

	// testOnlyTrustedMaterial replaces the live Sigstore trusted root.
	// cosign.TrustedRoot refreshes from the Sigstore TUF mirror over the
	// network, which the hermetic compatibility job denies, and it runs before
	// any registry call so it would fail the test before verification starts.
	testOnlyTrustedMaterial root.TrustedMaterial
}

// verifyCosignSignature is the production entry point wired into
// ociLoaderOperations.
func verifyCosignSignature(ctx context.Context, ref name.Reference, verify VerifyConfig, opts []remote.Option) error {
	return cosignVerifier{}.verify(ctx, ref, verify, opts)
}

func (v cosignVerifier) verify(ctx context.Context, ref name.Reference, verify VerifyConfig, opts []remote.Option) error {
	// Everything below binds to one immutable digest. OCILoader.Fetch resolves
	// the tag exactly once and hands us the result, so discovery, verification,
	// and the later pull all agree on the same content even if the tag moves.
	digestRef, ok := ref.(name.Digest)
	if !ok {
		return &signatureError{
			Code:      codeMalformedSignature,
			Operation: "resolve",
			Err:       fmt.Errorf("verification requires an immutable digest reference, got %q", ref.String()),
		}
	}

	found, err := v.discover(digestRef, opts)
	if err != nil {
		return err
	}
	if err := requireVerifiableCandidate(digestRef, found); err != nil {
		return err
	}
	return v.verifyStandardized(ctx, digestRef, verify, opts)
}

// requireVerifiableCandidate turns what discovery found into either a decision
// to proceed or the most specific error available.
//
// Everything except "at least one standardized candidate" is a rejection. The
// distinctions exist so an operator knows whether to publish a signature,
// re-sign in a supported format, or fix registry access.
func requireVerifiableCandidate(digestRef name.Digest, found discoveredReferrers) error {
	switch {
	case len(found.standardized) > 0:
		return nil
	case len(found.malformed) > 0:
		return &signatureError{
			Code:      codeMalformedSignature,
			Operation: "classify_referrer",
			Err: fmt.Errorf("%s carries %d unreadable signature referrer(s): %s",
				digestRef.String(), len(found.malformed), found.malformed.summary()),
		}
	case len(found.unsupported) > 0:
		return &signatureError{
			Code:      codeUnsupportedFormat,
			Operation: "classify_referrer",
			Err: fmt.Errorf("%s is signed in an unsupported format: %s; re-sign with cosign v3 defaults, which produce %s",
				digestRef.String(), found.unsupported.summary(), mediaTypeSigstoreBundleV03),
		}
	default:
		return &signatureError{
			Code:      codeSignatureNotFound,
			Operation: "classify_referrer",
			Err: fmt.Errorf("%s has no %s signature referrer; sign it with cosign v3",
				digestRef.String(), mediaTypeSigstoreBundleV03),
		}
	}
}

// referrerCandidate records one classified referrer and the media type that
// drove the decision, so error messages can name what was actually found.
type referrerCandidate struct {
	Digest   v1.Hash
	Evidence string
}

type referrerCandidates []referrerCandidate

func (c referrerCandidates) summary() string {
	parts := make([]string, 0, len(c))
	for _, candidate := range c {
		parts = append(parts, fmt.Sprintf("%s (%s)", candidate.Digest.String(), candidate.Evidence))
	}
	return strings.Join(parts, ", ")
}

type discoveredReferrers struct {
	standardized referrerCandidates
	unsupported  referrerCandidates
	malformed    referrerCandidates
}

// discover lists referrers for the resolved digest and sorts them into the
// classes that drive routing.
//
// This runs before any cosign verification call on purpose. Cosign's GetBundles
// skips candidates it cannot parse and then reports the same
// ErrNoMatchingAttestations whether there were no candidates at all, one
// malformed candidate, or a bundle version it considers too old. Those three
// states need different answers here, and only one of them may reach the legacy
// path, so absence has to be established before cosign is asked anything.
func (v cosignVerifier) discover(digestRef name.Digest, opts []remote.Option) (discoveredReferrers, error) {
	// ociremote.Referrers rather than remote.Referrers: it applies the same
	// target-repository rule that GetBundles uses inside
	// VerifyImageAttestations, so the classifier can never end up proving
	// absence in one repository while cosign verifies in another.
	// WithRemoteOptions replaces the default option set outright, so this call
	// carries exactly the context and registry auth the loader resolved with.
	//
	// The empty artifactType argument asks for an unfiltered listing.
	// Server-side filtering is advisory and would hide the unsupported and
	// malformed candidates that must block legacy fallback.
	index, err := ociremote.Referrers(digestRef, "", ociremote.WithRemoteOptions(opts...))
	if err != nil {
		// Auth, rate-limit, server, and timeout errors all land here. None of
		// them prove absence, so none of them may fall back.
		return discoveredReferrers{}, &signatureError{
			Code:      codeDiscoveryFailed,
			Operation: "referrer_discovery",
			Err:       fmt.Errorf("discovering signature referrers for %s: %w", digestRef.String(), err),
		}
	}

	var found discoveredReferrers
	for _, descriptor := range index.Manifests {
		class, evidence, err := v.classify(digestRef, descriptor, opts)
		if err != nil {
			return discoveredReferrers{}, err
		}
		candidate := referrerCandidate{Digest: descriptor.Digest, Evidence: evidence}
		switch class {
		case referrerStandardized:
			found.standardized = append(found.standardized, candidate)
		case referrerUnsupported:
			found.unsupported = append(found.unsupported, candidate)
		case referrerMalformed:
			found.malformed = append(found.malformed, candidate)
		case referrerUnrelated:
			// SBOMs, provenance attestations, and anything else attached to the
			// same digest. They say nothing about signature presence and must
			// not block the legacy path.
		}
	}
	return found, nil
}

type referrerClass int

const (
	referrerUnrelated referrerClass = iota
	referrerStandardized
	referrerUnsupported
	referrerMalformed
)

// classify decides what one referrer is, reading evidence in descending order
// of authority and stopping at the first conclusive signal.
func (v cosignVerifier) classify(subject name.Digest, descriptor v1.Descriptor, opts []remote.Option) (referrerClass, string, error) {
	// Every referrer is fetched, including ones whose descriptor names a type
	// that is plainly not a signature.
	//
	// Skipping the fetch would be cheaper but is not safe. The descriptor's
	// artifactType in a referrers listing is whatever the registry chose to put
	// there, and registries disagree: the OCI spec lets one fall back to
	// config.mediaType, which for a standardized cosign bundle referrer is the
	// OCI empty type rather than the bundle type. Trusting that value would
	// classify a real standardized signature as unrelated and hand the digest
	// to the legacy path, which is precisely the downgrade this routing exists
	// to prevent. Cosign v3.0.5 also wrote transitional referrers with no
	// artifactType at all.
	//
	// A policy bundle carries a handful of referrers, so the extra request per
	// referrer costs one round trip per reload.
	manifest, err := fetchReferrerManifest(subject, descriptor, opts)
	if err != nil {
		if isSignatureCandidateType(descriptor.ArtifactType) {
			// The descriptor already told us this is a signature, so failing to
			// read it is a broken signature, not an absent one.
			return referrerUnrelated, "", &signatureError{
				Code:      codeMalformedSignature,
				Operation: "fetch_referrer_manifest",
				Err:       fmt.Errorf("fetching signature referrer %s: %w", descriptor.Digest.String(), err),
			}
		}
		// The descriptor carried no type, so we cannot say whether a
		// standardized signature exists. Indeterminate discovery is not
		// absence.
		return referrerUnrelated, "", &signatureError{
			Code:      codeDiscoveryFailed,
			Operation: "fetch_referrer_manifest",
			Err:       fmt.Errorf("fetching referrer %s to classify it: %w", descriptor.Digest.String(), err),
		}
	}

	class, evidence := classifyManifest(descriptor, manifest)
	if class == referrerUnrelated {
		return class, evidence, nil
	}

	// A signature referrer must bind to the digest we resolved. The referrers
	// API is supposed to guarantee this, but a compromised or buggy registry
	// could return a signature for different content, and accepting it would be
	// a confused-deputy hand-off.
	if manifest.Subject == nil || manifest.Subject.Digest.String() != subject.DigestStr() {
		return referrerMalformed, evidence, nil
	}
	return class, evidence, nil
}

// classifyManifest reads the evidence chain. Cosign writes the type into
// several places and different producers and registries populate different
// ones, so all of them are consulted before concluding a referrer is unrelated.
//
// For a standardized bundle referrer, cosign sets the manifest artifactType,
// the config artifactType, and the layer media type to the bundle media type,
// while config.mediaType is the OCI empty type. For a transitional referrer it
// sets config.mediaType to the cosign artifact type and the layer to
// simple-signing, and before v3.1.2 it wrote no top-level artifactType at all.
func classifyManifest(descriptor v1.Descriptor, manifest *v1.Manifest) (referrerClass, string) {
	evidence := []string{
		descriptor.ArtifactType,
		manifest.ArtifactType,
		manifest.Config.ArtifactType,
		string(manifest.Config.MediaType),
	}
	for _, layer := range manifest.Layers {
		evidence = append(evidence, string(layer.MediaType))
	}

	for _, mediaType := range evidence {
		switch {
		case mediaType == "":
			continue
		case mediaType == mediaTypeSigstoreBundleV03:
			return referrerStandardized, mediaType
		case strings.HasPrefix(mediaType, mediaTypeSigstoreBundlePrefix):
			// A Sigstore bundle version this build cannot verify. Calling it
			// absent would let a downgrade through, so it is reported as
			// unsupported instead.
			return referrerUnsupported, mediaType
		case mediaType == mediaTypeCosignArtifactSig, mediaType == mediaTypeCosignSimpleSigning:
			return referrerUnsupported, mediaType
		}
	}
	return referrerUnrelated, descriptor.ArtifactType
}

func isSignatureCandidateType(mediaType string) bool {
	return strings.HasPrefix(mediaType, mediaTypeSigstoreBundlePrefix) ||
		mediaType == mediaTypeCosignArtifactSig ||
		mediaType == mediaTypeCosignSimpleSigning
}

// fetchReferrerManifest reads one referrer manifest by digest from the same
// repository and with the same auth options as everything else in this flow.
func fetchReferrerManifest(subject name.Digest, descriptor v1.Descriptor, opts []remote.Option) (*v1.Manifest, error) {
	ref := subject.Context().Digest(descriptor.Digest.String())
	fetched, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, err
	}
	return v1.ParseManifest(bytes.NewReader(fetched.Manifest))
}

// verifyStandardized verifies a Sigstore bundle referrer.
//
// VerifyImageAttestations is the only route to this format.
// VerifyImageSignatures rejects NewBundleFormat with "bundle support for image
// signatures is not yet implemented", so the modern signature has to be
// verified through the attestation API even though it is a signature.
func (v cosignVerifier) verifyStandardized(ctx context.Context, digestRef name.Digest, verify VerifyConfig, opts []remote.Option) error {
	checkOpts, err := v.checkOpts(verify, opts)
	if err != nil {
		return err
	}
	checkOpts.NewBundleFormat = true
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	attestations, _, err := cosign.VerifyImageAttestations(ctx, digestRef, checkOpts)
	if err != nil {
		// Identity, transparency, and signature failures are not separable
		// through the dependency's error types, so the wrapped cause carries
		// the detail rather than a guessed-at code.
		return &signatureError{
			Code:      codeCryptographicFailed,
			Operation: "verify_standardized",
			Err:       err,
		}
	}

	// Cosign has now checked the signature, the certificate identity, the
	// transparency evidence, and that an in-toto subject matches our digest.
	// It has not checked what the attestation claims to be:
	// IntotoSubjectClaimVerifier only compares subject digests, and no
	// CheckOpts field constrains the predicate. Without the check below, an
	// SBOM or provenance attestation signed by the same trusted identity for
	// the same digest would authorize the bundle.
	if err := requireCosignSignPredicate(attestations); err != nil {
		return &signatureError{
			Code:      codePredicateMismatch,
			Operation: "verify_standardized",
			Err:       err,
		}
	}
	return nil
}

// checkOpts builds the trust policy.
func (v cosignVerifier) checkOpts(verify VerifyConfig, opts []remote.Option) (*cosign.CheckOpts, error) {
	checkOpts := &cosign.CheckOpts{
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
	}

	if verify.PublicKeyRef != "" {
		verifier, err := loadPublicKeyVerifier(verify.PublicKeyRef)
		if err != nil {
			return nil, &signatureError{
				Code:      codeTrustRootFailed,
				Operation: "load_public_key",
				Err:       fmt.Errorf("loading cosign public key %q: %w", verify.PublicKeyRef, err),
			}
		}
		checkOpts.SigVerifier = verifier
	} else {
		checkOpts.Identities = []cosign.Identity{{
			Issuer:        verify.CertificateOIDCIssuer,
			SubjectRegExp: verify.CertificateIdentityRegexp,
		}}
	}

	// Transparency verification stays on in production. IgnoreSCT and the
	// timestamp bypasses are never set at all, so certificate transparency and
	// timestamp requirements keep their cosign defaults. ExperimentalOCI11 is
	// likewise never set: it would make cosign accept the transitional format
	// that classification exists to reject.
	checkOpts.IgnoreTlog = v.testOnlyIgnoreTlog

	trustedMaterial, err := v.trustedMaterial(verify)
	if err != nil {
		return nil, err
	}
	checkOpts.TrustedMaterial = trustedMaterial
	return checkOpts, nil
}

// trustedMaterial loads the Sigstore trusted root.
//
// cosign.TrustedRoot refreshes from the Sigstore TUF mirror over the network.
// The one configuration that genuinely does not need it is public-key
// verification with transparency disabled, since there are no Fulcio roots or
// Rekor keys to consult, and that combination is reachable only from package
// tests. Production keyless and production public-key verification both load
// the real root, the latter because Rekor inclusion still has to be checked.
func (v cosignVerifier) trustedMaterial(verify VerifyConfig) (root.TrustedMaterial, error) {
	if v.testOnlyTrustedMaterial != nil {
		return v.testOnlyTrustedMaterial, nil
	}
	if v.testOnlyIgnoreTlog && verify.PublicKeyRef != "" {
		return nil, nil
	}
	material, err := cosign.TrustedRoot()
	if err != nil {
		return nil, &signatureError{
			Code:      codeTrustRootFailed,
			Operation: "load_trusted_root",
			Err:       fmt.Errorf("loading sigstore trust root: %w", err),
		}
	}
	return material, nil
}

// attestationPayload is the only part of an oci.Signature the predicate check
// reads. Narrowing to it keeps the check testable without standing up the whole
// signature interface.
type attestationPayload interface {
	Payload() ([]byte, error)
}

// requireCosignSignPredicate accepts only an attestation that declares itself a
// cosign image signature. At least one verified attestation must qualify.
func requireCosignSignPredicate[T attestationPayload](attestations []T) error {
	if len(attestations) == 0 {
		return errors.New("cosign reported success with no verified attestation")
	}
	reasons := make([]error, 0, len(attestations))
	for _, att := range attestations {
		predicateType, err := attestationPredicateType(att)
		if err != nil {
			reasons = append(reasons, err)
			continue
		}
		if predicateType == cosigntypes.CosignSignPredicateType {
			return nil
		}
		reasons = append(reasons, fmt.Errorf("predicate %q", predicateType))
	}
	return fmt.Errorf("no verified attestation declares predicate %s, found: %w",
		cosigntypes.CosignSignPredicateType, errors.Join(reasons...))
}

// attestationPredicateType reads the predicate out of the DSSE envelope cosign
// returns. The envelope has already been cryptographically verified by the time
// this runs; this only inspects what it claims.
func attestationPredicateType(att attestationPayload) (string, error) {
	payload, err := att.Payload()
	if err != nil {
		return "", fmt.Errorf("reading attestation payload: %w", err)
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", fmt.Errorf("decoding attestation envelope: %w", err)
	}
	statement, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return "", fmt.Errorf("decoding attestation statement: %w", err)
	}
	parsed := &attestation.Statement{}
	if err := parsed.UnmarshalJSON(statement); err != nil {
		return "", fmt.Errorf("parsing in-toto statement: %w", err)
	}
	return parsed.PredicateType, nil
}

// loadPublicKeyVerifier builds a signature verifier from a PEM public key on
// disk, for explicitly managed keys and local testing.
func loadPublicKeyVerifier(path string) (signature.Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pem to public key: %w", err)
	}
	return signature.LoadVerifier(pub, crypto.SHA256)
}
