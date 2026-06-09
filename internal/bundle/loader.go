package bundle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// Source identifies a bundle to fetch. The broker supports two source types:
//
//   - oci://host/path:tag — the production path. Pulled and cosign-verified
//     by OCILoader.
//   - file:///abs/path/bundle.tar.gz — local file. Used for local
//     development, the dev container, and CI tests. No signature
//     verification — only acceptable when the operator has already
//     vetted the file out of band.
type Source struct {
	Raw string
}

// Scheme returns the URI scheme of the source ("oci", "file", or empty).
func (s Source) Scheme() string {
	if i := strings.Index(s.Raw, "://"); i > 0 {
		return s.Raw[:i]
	}
	return ""
}

// Path returns the source minus its scheme prefix.
func (s Source) Path() string {
	if i := strings.Index(s.Raw, "://"); i > 0 {
		return s.Raw[i+3:]
	}
	return s.Raw
}

// VerifyConfig is the cosign verification policy. OCI sources can use keyless
// certificate identity/issuer verification or public-key verification. It is
// ignored when the source is file://.
type VerifyConfig struct {
	CertificateIdentityRegexp string
	CertificateOIDCIssuer     string
	PublicKeyRef              string
}

// Fetch is the result of a successful pull-and-verify cycle. Tarball is
// the raw bundle bytes ready for engine compilation; Digest is the
// canonical OCI digest ("sha256:...") used as the audit fingerprint
// that proves which bundle gated which decision.
type Fetch struct {
	Tarball []byte
	Digest  string
}

// Loader pulls a bundle from a source and (when applicable) verifies
// its cosign signature. Implementations must fail closed: any pull
// error, any signature error, any digest-mismatch causes a non-nil
// error return. Never return a Fetch with empty Tarball alongside a
// nil error.
type Loader interface {
	Fetch(ctx context.Context, src Source, verify VerifyConfig) (Fetch, error)
}

// FilesystemLoader reads a bundle from a local file. No signature
// verification — VerifyConfig is ignored. Suitable for local
// development and tests; never wire this in production.
//
// The digest returned is the sha256 of the file contents, prefixed
// with "sha256:" to mirror the OCI convention. Operators looking at
// the audit log can therefore tell at a glance whether the broker is
// running on a filesystem fixture (digest of the file bytes) or a
// pulled OCI image (digest of the OCI manifest).
type FilesystemLoader struct{}

func (FilesystemLoader) Fetch(_ context.Context, src Source, _ VerifyConfig) (Fetch, error) {
	path := src.Path()
	if path == "" {
		return Fetch{}, fmt.Errorf("bundle filesystem loader: empty path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Fetch{}, fmt.Errorf("bundle filesystem loader: reading %s: %w", path, err)
	}
	if len(data) == 0 {
		return Fetch{}, fmt.Errorf("bundle filesystem loader: %s is empty", path)
	}
	sum := sha256.Sum256(data)
	return Fetch{
		Tarball: data,
		Digest:  fmt.Sprintf("sha256:%x", sum),
	}, nil
}

// NewLoader picks a Loader implementation based on the source scheme.
// file:// works for local development and tests; oci:// is the production
// path and requires cosign keyless verification during Fetch.
func NewLoader(src Source) (Loader, error) {
	switch src.Scheme() {
	case "oci":
		return OCILoader{}, nil
	case "file", "":
		return FilesystemLoader{}, nil
	default:
		return nil, fmt.Errorf("bundle: unsupported source scheme %q", src.Scheme())
	}
}
