// Package signer signs GitHub App JWTs without its callers knowing where the
// App private key lives. A Key produces RS256 signatures over a digest and
// nothing else, so when a key management service holds the key, the key never
// enters github-sts: only digests go out and signatures come back
// (ADR github-sts/0018).
//
// The in-process Key wraps a PEM loaded from configuration. Each key
// management service is a sub-package of its own, the only importer of that
// cloud's SDK; the composition root (internal/server) opens one by provider
// name.
package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ProviderAzure names Azure Key Vault (and Managed HSM) in
// apps.<name>.signer.provider.
const ProviderAzure = "azure"

// Providers returns every provider name apps.<name>.signer.provider accepts.
func Providers() []string {
	return []string{ProviderAzure}
}

// Key signs with a GitHub App private key that its holder may not be able to
// read. GitHub accepts only RS256 for an App JWT, so that is the one
// operation: RSASSA-PKCS1-v1_5 over a SHA-256 digest.
type Key interface {
	// SignRS256 returns the signature of digest, which must be the SHA-256
	// hash of the message.
	SignRS256(ctx context.Context, digest []byte) ([]byte, error)
}

// ErrDigestSize is returned for a digest that is not a SHA-256 hash.
var ErrDigestSize = errors.New("digest is not a SHA-256 hash")

// CheckDigest rejects a digest of the wrong length before it reaches a
// provider, which would otherwise answer with a less specific error after a
// network round trip.
func CheckDigest(digest []byte) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrDigestSize, len(digest), sha256.Size)
	}
	return nil
}

// Local is a Key whose private key is in this process, loaded from
// private_key or private_key_path.
type Local struct {
	key *rsa.PrivateKey
}

// NewLocal returns a Key that signs with key in process.
func NewLocal(key *rsa.PrivateKey) *Local {
	return &Local{key: key}
}

// SignRS256 implements Key.
func (l *Local) SignRS256(_ context.Context, digest []byte) ([]byte, error) {
	if err := CheckDigest(digest); err != nil {
		return nil, err
	}
	// crypto/rand blinds the private-key operation against timing attacks;
	// the PKCS #1 v1.5 signature itself is deterministic.
	return rsa.SignPKCS1v15(rand.Reader, l.key, crypto.SHA256, digest)
}
