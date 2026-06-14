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
	opts, err := registryRemoteOptions(ctx, verify.RegistryAuth)
	if err != nil {
		return Fetch{}, err
	}

	if !verify.SkipVerification {
		if err := verifyCosignSignature(ctx, ref, verify, opts); err != nil {
			return Fetch{}, err
		}
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

func registryRemoteOptions(ctx context.Context, auth RegistryAuthConfig) ([]remote.Option, error) {
	opts := []remote.Option{remote.WithContext(ctx)}
	if auth.Mode == "" {
		return append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain)), nil
	}
	if auth.Mode != "basic" {
		return nil, fmt.Errorf("bundle oci loader: unsupported registry auth mode %q", auth.Mode)
	}
	password, err := resolveBasicPassword(auth)
	if err != nil {
		return nil, err
	}
	return append(opts, remote.WithAuth(&authn.Basic{Username: auth.Username, Password: password})), nil
}

func resolveBasicPassword(auth RegistryAuthConfig) (string, error) {
	if auth.Username == "" {
		return "", fmt.Errorf("bundle oci loader: registry basic auth username is required")
	}
	if auth.PasswordFile != "" && auth.PasswordEnv != "" {
		return "", fmt.Errorf("bundle oci loader: registry basic auth must use password file or env, not both")
	}
	if auth.PasswordFile != "" {
		data, err := os.ReadFile(auth.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("bundle oci loader: reading registry basic auth password file: %w", err)
		}
		password := strings.TrimRight(string(data), "\r\n")
		if password == "" {
			return "", fmt.Errorf("bundle oci loader: registry basic auth password file is empty")
		}
		return password, nil
	}
	if auth.PasswordEnv != "" {
		password := os.Getenv(auth.PasswordEnv)
		if password == "" {
			return "", fmt.Errorf("bundle oci loader: registry basic auth password env %q is empty or unset", auth.PasswordEnv)
		}
		return password, nil
	}
	return "", fmt.Errorf("bundle oci loader: registry basic auth requires password file or env")
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
	if verify.SkipVerification && (hasKeyless || hasPublicKey) {
		return fmt.Errorf("bundle oci loader: skip verification cannot be combined with certificate identity/issuer or public key ref")
	}
	if verify.SkipVerification {
		return nil
	}
	if hasKeyless && hasPublicKey {
		return fmt.Errorf("bundle oci loader: use either keyless certificate identity/issuer or public key ref, not both")
	}
	if !hasKeyless && !hasPublicKey {
		return fmt.Errorf("bundle oci loader: cosign verification requires certificate identity regexp and OIDC issuer, public key ref, or skip verification")
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
