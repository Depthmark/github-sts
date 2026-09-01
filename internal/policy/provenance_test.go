package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitBlobSHA_MatchesGitHashObject is the whole justification for using
// git's hash rather than a plain sha256: the audit record must be verifiable
// offline with stock git. If this ever diverges, the value in the log stops
// being checkable against a clone and the provenance claim is hollow.
func TestGitBlobSHA_MatchesGitHashObject(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}

	contents := [][]byte{
		[]byte("issuer: https://token.actions.githubusercontent.com\npermissions:\n  contents: read\n"),
		[]byte(""),
		[]byte("no trailing newline"),
		[]byte("unicode: héllo wörld ✓\n"),
		make([]byte, 4096), // NUL bytes: length prefix must not be confused by them
	}

	dir := t.TempDir()
	for i, content := range contents {
		path := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(git, "hash-object", path).Output()
		if err != nil {
			t.Fatalf("git hash-object: %v", err)
		}
		want := strings.TrimSpace(string(out))
		if got := GitBlobSHA(content); got != want {
			t.Errorf("case %d: GitBlobSHA = %s, git hash-object = %s", i, got, want)
		}
	}
}

// Provenance must distinguish the two resolution outcomes, because under
// repo_first a repo owner can override the centralized policy and the audit
// trail is the only place that difference is visible after the fact.
func TestProvenance_Source(t *testing.T) {
	if got := (Provenance{Centralized: true}).Source(); got != "centralized" {
		t.Errorf("centralized source = %q", got)
	}
	if got := (Provenance{Centralized: false}).Source(); got != "repository" {
		t.Errorf("repo-local source = %q", got)
	}
}

func TestTrustPolicy_ProvenanceRoundTrip(t *testing.T) {
	pol := &TrustPolicy{}
	pol.SetSource("myorg/.github-private", ".github/sts/default/ci.sts.yaml", "58970eea")
	pol.SetCentralized(true)

	got := pol.Provenance()
	if got.Repository != "myorg/.github-private" || got.Path != ".github/sts/default/ci.sts.yaml" {
		t.Fatalf("provenance = %+v", got)
	}
	if got.BlobSHA != "58970eea" {
		t.Fatalf("blob sha = %q", got.BlobSHA)
	}
	// The pre-existing accessor must keep working: internal/bundle reads it
	// to build the Rego input.
	if !pol.Centralized() {
		t.Fatal("Centralized() lost its value after folding into Provenance")
	}
}

// A policy that never came from a fetch (in-memory loader, tests) must
// report an empty blob SHA rather than a hash of nothing: absent provenance
// and provenance-of-empty-content are different claims.
func TestTrustPolicy_UnfetchedPolicyHasNoBlobSHA(t *testing.T) {
	pol := &TrustPolicy{}
	if got := pol.Provenance().BlobSHA; got != "" {
		t.Fatalf("blob sha = %q, want empty for a policy that was never fetched", got)
	}
	if got := GitBlobSHA([]byte("")); got == "" {
		t.Fatal("GitBlobSHA of empty content should still hash, only the unset field stays empty")
	}
}
