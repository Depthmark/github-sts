package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestLocal_SignRS256_VerifiesAgainstPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	digest := sha256.Sum256([]byte("header.claims"))

	sig, err := NewLocal(key).SignRS256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestLocal_SignRS256_RejectsWrongDigestSize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tests := []struct {
		name   string
		digest []byte
	}{
		{name: "empty", digest: nil},
		{name: "SHA-1 sized", digest: make([]byte, 20)},
		{name: "SHA-512 sized", digest: make([]byte, 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLocal(key).SignRS256(context.Background(), tt.digest)
			if !errors.Is(err, ErrDigestSize) {
				t.Fatalf("error = %v, want ErrDigestSize", err)
			}
		})
	}
}

func TestProviders_ListsAzure(t *testing.T) {
	got := Providers()
	if len(got) != 1 || got[0] != ProviderAzure {
		t.Fatalf("Providers() = %v, want [%s]", got, ProviderAzure)
	}
}
