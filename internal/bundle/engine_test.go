package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

// buildTarball builds an OPA-style bundle tarball in memory from a map
// of file paths to contents. No signing, no manifest — the engine
// constructor uses WithSkipBundleVerification(true) so an unsigned
// fixture is acceptable for tests.
func buildTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar write header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

// TestEngine_DefaultDenyOnEmptyBundle counter-validates that a bundle
// with the producer's v0.1.0 shape (default-deny, no allow rules)
// produces Decision{Allow: false}. This is the v0.1.0 reality — when
// operators flip bundle.enabled=true against the upstream bundle,
// every request should deny.
func TestEngine_DefaultDenyOnEmptyBundle(t *testing.T) {
	// Mirrors policies/org/00_defaults.rego + 99_decision_assembly.rego
	// from github-sts-policy v0.1.0.
	rego := `# METADATA
# scope: package
package sts.org

import rego.v1

default decision := {
	"allow": false,
	"reasons": ["sts.org: default deny (no org policy granted access)"],
}

default allow_reasons := set()

default deny_reasons := set()
`
	tarball := buildTarball(t, map[string]string{
		"/policies/org/00_defaults.rego": rego,
	})

	eng, err := NewEngine(context.Background(), tarball)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := eng.Eval(context.Background(), Input{
		Mode: ModeExchange,
		Request: InputRequest{
			Scope: "depthmark/example", App: "default", Identity: "ci",
		},
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected deny on empty bundle, got allow with reasons %v", d.Reasons)
	}
	if len(d.Reasons) == 0 {
		t.Fatalf("expected at least one reason on default-deny, got none")
	}
}

// TestEngine_DenyWinsOverAllow counter-validates the producer's
// 99_decision_assembly.rego semantics: any deny_reasons → deny, even
// if allow_reasons is also non-empty. The broker must mirror this.
func TestEngine_DenyWinsOverAllow(t *testing.T) {
	rego := `package sts.org

import rego.v1

default decision := {
	"allow": false,
	"reasons": ["default"],
}

allow_reasons contains "always-allow" if { true }

deny_reasons contains "always-deny" if { true }

decision := {
	"allow": false,
	"reasons": [r | some r in deny_reasons],
} if {
	count(deny_reasons) > 0
}

decision := {
	"allow": true,
	"reasons": [r | some r in allow_reasons],
} if {
	count(deny_reasons) == 0
	count(allow_reasons) > 0
}
`
	tarball := buildTarball(t, map[string]string{
		"/policies/org/policy.rego": rego,
	})

	eng, err := NewEngine(context.Background(), tarball)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := eng.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected deny when both allow_reasons and deny_reasons are non-empty (deny wins), got allow")
	}
	found := false
	for _, r := range d.Reasons {
		if r == "always-deny" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected deny reason %q in %v", "always-deny", d.Reasons)
	}
}

// TestEngine_RejectsEmptyTarball counter-validates that the engine
// constructor refuses an empty input. A misconfigured pull producing
// zero bytes must not silently produce an allow-everything engine.
func TestEngine_RejectsEmptyTarball(t *testing.T) {
	if _, err := NewEngine(context.Background(), nil); err == nil {
		t.Fatalf("expected error on nil tarball, got nil")
	}
	if _, err := NewEngine(context.Background(), []byte{}); err == nil {
		t.Fatalf("expected error on empty tarball, got nil")
	}
}

func TestEngine_MultiplePackages_DenyWins(t *testing.T) {
	tarball := buildTarball(t, map[string]string{
		"/policies/a.rego": `package sts.enterprise.allow

import rego.v1

default decision := {"allow": true, "reasons": ["allow package"]}
`,
		"/policies/b.rego": `package sts.enterprise.deny

import rego.v1

decision := {
  "allow": false,
  "reasons": ["denied by package"],
  "rule_id": "ENT-001",
  "rule_name": "deny package"
}
`,
	})

	eng, err := NewEngine(context.Background(), tarball)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d, err := eng.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected final deny when one package denies")
	}
	if len(d.Packages) != 2 {
		t.Fatalf("package decisions len = %d, want 2", len(d.Packages))
	}
	found := false
	for _, pd := range d.Packages {
		if pd.RuleID == "ENT-001" && !pd.Allow {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected package decision with rule_id ENT-001, got %+v", d.Packages)
	}
}

func TestEngine_ExceptionInventory(t *testing.T) {
	tarball := buildTarball(t, map[string]string{
		"/policies/exceptions.rego": `package sts.enterprise.exceptions

import rego.v1

default decision := {"allow": true, "reasons": []}

inventory contains {
  "exception_id": "EXC-001",
  "rule_id": "ENT-001",
  "owner": "platform-team",
  "reason": "release automation",
  "approved_by": "security-team",
  "created_at": "2026-06-01T00:00:00Z",
  "expires_at": "2099-12-31T23:59:59Z"
}
`,
	})

	eng, err := NewEngine(context.Background(), tarball)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	exceptions, err := eng.Exceptions(context.Background())
	if err != nil {
		t.Fatalf("Exceptions: %v", err)
	}
	if len(exceptions) != 1 {
		t.Fatalf("exceptions len = %d, want 1: %+v", len(exceptions), exceptions)
	}
	ex := exceptions[0]
	if ex.ExceptionID != "EXC-001" || ex.RuleID != "ENT-001" || ex.Owner != "platform-team" {
		t.Fatalf("unexpected exception metadata: %+v", ex)
	}
	if ex.Status != "active" {
		t.Fatalf("exception status = %q, want active", ex.Status)
	}
}
