package bundle

import (
	"context"
	"os"
	"testing"
)

func TestOCILoader_LocalRegistrySignedBundle(t *testing.T) {
	ref := os.Getenv("GITHUBSTS_OCI_TEST_REF")
	publicKeyRef := os.Getenv("GITHUBSTS_OCI_TEST_PUBLIC_KEY_REF")
	if ref == "" || publicKeyRef == "" {
		t.Skip("set GITHUBSTS_OCI_TEST_REF and GITHUBSTS_OCI_TEST_PUBLIC_KEY_REF to run local OCI/cosign integration test")
	}

	fetch, err := OCILoader{}.Fetch(context.Background(), Source{Raw: ref}, VerifyConfig{
		PublicKeyRef: publicKeyRef,
		IgnoreTlog:   os.Getenv("GITHUBSTS_OCI_TEST_IGNORE_TLOG") == "true",
	})
	if err != nil {
		t.Fatalf("OCI fetch: %v", err)
	}
	if fetch.Digest == "" {
		t.Fatalf("OCI fetch returned empty digest")
	}
	if len(fetch.Tarball) == 0 {
		t.Fatalf("OCI fetch returned empty tarball")
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
