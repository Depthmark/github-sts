package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
)

// logAndCapture runs one event through a FileLogger and returns both
// outputs: the JSON audit file line and the slog stream. They are separate
// consumers with separate needs, and this package must serve both.
func logAndCapture(t *testing.T, event Event) (fileLine []byte, slogLine string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.json")
	var buf bytes.Buffer
	fl, err := NewFileLogger(path, 10, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	fl.Log(event)
	if err := fl.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data, buf.String()
}

func provenanceEvent(result ExchangeResult) Event {
	return Event{
		TraceID:           "trace-1",
		Scope:             "myorg/myrepo",
		AppName:           "default",
		Identity:          "ci",
		BundleEnforcement: bundle.EnforcementOptional,
		Result:            result,
		PolicyRepository:  "myorg/.github-private",
		PolicyPath:        ".github/sts/default/ci.sts.yaml",
		PolicyBlobSHA:     "58970eea7611182acab5675ba8f56451ca607cda",
		PolicySource:      "centralized",
	}
}

// The slog attributes are hand-picked, so a field added to Event reaches the
// JSON audit file automatically but reaches container logs only if it is
// listed there. A deployment without a mounted audit file -- the common
// Kubernetes case -- sees only the slog stream.
func TestAuditSlog_CarriesPolicyProvenance(t *testing.T) {
	_, logged := logAndCapture(t, provenanceEvent(ResultSuccess))

	for _, want := range []string{
		"policy_repository=myorg/.github-private",
		"policy_path=.github/sts/default/ci.sts.yaml",
		"policy_blob_sha=58970eea7611182acab5675ba8f56451ca607cda",
		"policy_source=centralized",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("slog output missing %q\ngot: %s", want, logged)
		}
	}
}

// A denied exchange still needs to name the policy that denied it, otherwise
// the record cannot be reproduced against the repo.
func TestAuditSlog_ProvenancePresentOnDenial(t *testing.T) {
	event := provenanceEvent(ResultPolicyDenied)
	event.ErrorReason = "subject mismatch"

	_, logged := logAndCapture(t, event)

	if !strings.Contains(logged, "policy_blob_sha=58970eea") {
		t.Errorf("denied exchange lost policy provenance\ngot: %s", logged)
	}
}

// repo_first resolution lets a repository owner override the centralized org
// policy. Which side won is an authorization fact, and the audit trail is
// the only place it stays visible after the fact.
func TestAuditSlog_DistinguishesPolicySource(t *testing.T) {
	event := provenanceEvent(ResultSuccess)
	event.PolicySource = "repository"
	event.PolicyRepository = "myorg/myrepo"

	_, logged := logAndCapture(t, event)

	if !strings.Contains(logged, "policy_source=repository") {
		t.Errorf("repo-local policy not distinguishable\ngot: %s", logged)
	}
}

// An event that never resolved a policy must omit the fields rather than
// emit empty ones: "no policy was reached" and "a policy with no identity"
// are different claims.
func TestAuditSlog_OmitsAbsentProvenance(t *testing.T) {
	event := Event{
		TraceID: "trace-1", Scope: "myorg/myrepo", Result: ResultOIDCInvalid,
		BundleEnforcement: bundle.EnforcementOptional,
	}
	fileLine, logged := logAndCapture(t, event)

	if strings.Contains(logged, "policy_blob_sha") || strings.Contains(logged, "policy_source") {
		t.Errorf("provenance emitted for an exchange that never loaded a policy\ngot: %s", logged)
	}
	if strings.Contains(string(fileLine), "policy_blob_sha") {
		t.Errorf("absent provenance serialized into the audit file\ngot: %s", fileLine)
	}
}

// The JSON audit file must carry the same facts, since it is the sink an
// auditor reads.
func TestAuditFile_CarriesPolicyProvenance(t *testing.T) {
	fileLine, _ := logAndCapture(t, provenanceEvent(ResultSuccess))

	var decoded Event
	if err := json.Unmarshal(fileLine, &decoded); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, fileLine)
	}
	if decoded.PolicyBlobSHA != "58970eea7611182acab5675ba8f56451ca607cda" {
		t.Errorf("policy_blob_sha = %q", decoded.PolicyBlobSHA)
	}
	if decoded.PolicySource != "centralized" {
		t.Errorf("policy_source = %q", decoded.PolicySource)
	}
}
