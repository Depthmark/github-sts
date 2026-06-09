package bundle

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// OCILoader pulls an OPA bundle stored as an OCI image/artifact and verifies
// its cosign signature before returning the bundle bytes. Production bundles
// should use keyless identity/issuer verification; public-key verification is
// supported for local/offline testing and explicitly managed keys. The returned
// tarball is the compressed OPA bundle layer as produced by `opa build`.
type OCILoader struct{}

func (OCILoader) Fetch(ctx context.Context, src Source, verify VerifyConfig) (Fetch, error) {
	if src.Scheme() != "oci" {
		return Fetch{}, fmt.Errorf("bundle oci loader: unsupported source scheme %q", src.Scheme())
	}
	if err := validateVerifyConfig(verify); err != nil {
		return Fetch{}, err
	}

	ref, err := name.ParseReference(src.Path(), name.StrictValidation)
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: parsing %q: %w", src.Raw, err)
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}

	if err := verifyCosignSignature(ctx, ref, verify, opts); err != nil {
		return Fetch{}, err
	}

	img, err := remote.Image(ref, opts...)
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: pulling %q: %w", src.Raw, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: resolving digest for %q: %w", src.Raw, err)
	}
	layer, err := selectBundleLayer(img)
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: selecting bundle layer for %q: %w", src.Raw, err)
	}
	r, err := layer.Compressed()
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: opening compressed bundle layer: %w", err)
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle oci loader: reading compressed bundle layer: %w", err)
	}
	if len(data) == 0 {
		return Fetch{}, fmt.Errorf("bundle oci loader: selected bundle layer is empty")
	}
	return Fetch{Tarball: data, Digest: digest.String()}, nil
}

func verifyCosignSignature(ctx context.Context, ref name.Reference, verify VerifyConfig, opts []remote.Option) error {
	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return fmt.Errorf("bundle oci loader: loading sigstore trust root: %w", err)
	}
	co := &cosign.CheckOpts{
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
		TrustedMaterial:    trustedRoot,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
	}
	if verify.PublicKeyRef != "" {
		verifier, err := loadPublicKeyVerifier(verify.PublicKeyRef)
		if err != nil {
			return fmt.Errorf("bundle oci loader: loading cosign public key %q: %w", verify.PublicKeyRef, err)
		}
		co.SigVerifier = verifier
	} else {
		co.Identities = []cosign.Identity{{
			Issuer:        verify.CertificateOIDCIssuer,
			SubjectRegExp: verify.CertificateIdentityRegexp,
		}}
	}
	if _, _, err := cosign.VerifyImageSignatures(ctx, ref, co); err != nil {
		return fmt.Errorf("bundle oci loader: cosign verification failed for %q: %w", ref.String(), err)
	}
	return nil
}

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

func validateVerifyConfig(verify VerifyConfig) error {
	hasKeyless := verify.CertificateIdentityRegexp != "" || verify.CertificateOIDCIssuer != ""
	hasPublicKey := verify.PublicKeyRef != ""
	if hasKeyless && hasPublicKey {
		return fmt.Errorf("bundle oci loader: use either keyless certificate identity/issuer or public key ref, not both")
	}
	if !hasKeyless && !hasPublicKey {
		return fmt.Errorf("bundle oci loader: cosign verification requires certificate identity regexp and OIDC issuer, or public key ref")
	}
	if hasKeyless && verify.CertificateIdentityRegexp == "" {
		return fmt.Errorf("bundle oci loader: certificate identity regexp is required")
	}
	if hasKeyless && verify.CertificateOIDCIssuer == "" {
		return fmt.Errorf("bundle oci loader: certificate OIDC issuer is required")
	}
	return nil
}

func selectBundleLayer(img v1.Image) (v1.Layer, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("image has no layers")
	}
	if len(layers) == 1 {
		return layers[0], nil
	}
	for _, layer := range layers {
		mt, err := layer.MediaType()
		if err != nil {
			return nil, err
		}
		mediaType := strings.ToLower(string(mt))
		if strings.Contains(mediaType, "openpolicyagent") || strings.Contains(mediaType, "bundle") || strings.Contains(mediaType, "tar+gzip") || strings.Contains(mediaType, "gzip") {
			return layer, nil
		}
	}
	return nil, fmt.Errorf("image has %d layers but none look like an OPA bundle", len(layers))
}
