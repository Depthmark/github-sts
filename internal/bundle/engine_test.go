package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	trustpolicy "github.com/depthmark/github-sts/internal/policy"
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

func exampleBaselineTarball(t *testing.T) []byte {
	t.Helper()
	regoSource, err := os.ReadFile("../../policies/example_enterprise_baseline.rego")
	if err != nil {
		t.Fatalf("read example baseline: %v", err)
	}
	data, err := os.ReadFile("../../policies/example_data.json")
	if err != nil {
		t.Fatalf("read example baseline data: %v", err)
	}
	return buildTarball(t, map[string]string{
		"/policies/example_enterprise_baseline.rego": string(regoSource),
		"/data.json": string(data),
	})
}

func loadExampleTrustPolicy(t *testing.T, name string) *trustpolicy.TrustPolicy {
	t.Helper()
	raw, err := os.ReadFile("../../config/examples/" + name + ".sts.yaml")
	if err != nil {
		t.Fatalf("read example trust policy %q: %v", name, err)
	}
	parsed, err := trustpolicy.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse example trust policy %q: %v", name, err)
	}
	return parsed
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

func TestEngine_MalformedDecisionIsEvaluationError(t *testing.T) {
	tests := []struct {
		name     string
		decision string
		wantErr  string
	}{
		{name: "undefined", decision: `decision := {"allow": true} if { false }`, wantErr: "exactly one document"},
		{name: "not object", decision: `decision := true`, wantErr: "must be an object"},
		{name: "missing allow", decision: `decision := {"reasons": ["no allow"]}`, wantErr: "allow must be a boolean"},
		{name: "wrong allow type", decision: `decision := {"allow": "yes"}`, wantErr: "allow must be a boolean"},
		{name: "wrong reasons type", decision: `decision := {"allow": false, "reasons": "deny"}`, wantErr: "reasons must be an array"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regoSource := "package sts.enterprise.malformed\nimport rego.v1\n" + tt.decision + "\n"
			eng, err := NewEngine(context.Background(), buildTarball(t, map[string]string{
				"/policies/malformed.rego": regoSource,
			}))
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			_, err = eng.Eval(context.Background(), Input{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Eval error = %v, want substring %q", err, tt.wantErr)
			}
		})
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
  "reason": "example automation",
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

func TestEngine_ExampleTrustPoliciesConformToBaseline(t *testing.T) {
	eng, err := NewEngine(context.Background(), exampleBaselineTarball(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		policy   string
		scope    string
		identity string
		source   string
		target   string
	}{
		{policy: "ci", scope: "example-org/example-repo", identity: "ci", source: "example-org/example-repo", target: "example-repo"},
		{policy: "deploy", scope: "example-org/example-repo", identity: "deploy", source: "example-org/example-repo", target: "example-repo"},
		{policy: "cross-repo-ci", scope: "example-org/backend", identity: "cross-repo-ci", source: "example-org/example-repo", target: "backend"},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			input := examplePolicyInput(loadExampleTrustPolicy(t, tt.policy), tt.scope, tt.identity, tt.source, tt.target)
			decision, err := eng.Eval(context.Background(), input)
			if err != nil {
				t.Fatalf("Eval example policy: %v", err)
			}
			if !decision.Allow {
				t.Fatalf("baseline denied %s example: %+v", tt.policy, decision)
			}
		})
	}

	input := examplePolicyInput(loadExampleTrustPolicy(t, "ci"), "example-org/example-repo", "ci", "example-org/example-repo", "example-repo")
	input.Requested.Permissions = map[string]string{"contents": "admin"}
	decision, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval deny fixture: %v", err)
	}
	if decision.Allow {
		t.Fatalf("baseline allowed permission above ceiling: %+v", decision)
	}
}

func examplePolicyInput(p *trustpolicy.TrustPolicy, scope, identity, sourceRepository, targetRepository string) Input {
	source := p.GitHub.Sources[0]
	target := p.GitHub.Target
	return Input{
		Mode:    ModeExchange,
		Request: InputRequest{Scope: scope, App: "default", Identity: identity},
		SourceIdentity: &InputSourceIdentity{
			Version: SourceIdentityVersionV1, Issuer: "https://token.actions.githubusercontent.com",
			RepositoryOwner: "example-org", RepositoryOwnerID: string(source.OwnerID),
			Repository: sourceRepository, RepositoryID: string(source.RepositoryID),
			ImmutableSubject: true, ImmutableSubjectRequired: true,
		},
		TargetIdentity: &InputTargetIdentity{
			Version: TargetIdentityVersionV1, Scope: scope,
			RepositoryOwner: "example-org", RepositoryOwnerID: string(target.OwnerID),
			Repository: scope, RepositoryID: string(target.RepositoryID),
		},
		YAMLPolicy: FromPolicy(p),
		Requested: &InputRequested{
			Permissions: p.Permissions, Repositories: []string{targetRepository},
			RepositoryIDs: []string{string(target.RepositoryID)},
		},
	}
}

func TestMandatoryEngine_ExampleBaselineAdmission(t *testing.T) {
	eng, err := NewMandatoryEngine(context.Background(), exampleBaselineTarball(t))
	if err != nil {
		t.Fatalf("NewMandatoryEngine: %v", err)
	}
	metadata := eng.Metadata()
	if metadata.ContractVersion != "v1" || metadata.PolicyRevision != "example-v1" {
		t.Fatalf("mandatory metadata = %+v", metadata)
	}
	if len(eng.decisions) != 1 || eng.decisions[0].Query != mandatoryEntrypoint {
		t.Fatalf("mandatory decisions = %+v, want only %s", eng.decisions, mandatoryEntrypoint)
	}
}

func TestMandatoryEngine_AdmissionRejectsIncompleteBundles(t *testing.T) {
	metadata := `metadata := {
  "contract_version": "v1",
  "policy_revision": "test-1",
  "controls": ["immutable_identity", "permission_boundary"],
	"admission": {
	  "app": "default",
	  "identity": "ci",
	  "source": {"owner_id": "123456", "repository_id": "456789"},
	  "target": {"owner_id": "123456", "repository_id": "456789"},
	  "permissions": {"contents": "read"},
	},
}`
	tests := []struct {
		name    string
		rego    string
		wantErr string
	}{
		{
			name: "missing fixed entrypoint",
			rego: `package sts.enterprise.other
import rego.v1
decision := {"allow": false, "reasons": ["deny"]}
`,
			wantErr: "unsupported decision entrypoint",
		},
		{
			name: "missing metadata",
			rego: `package sts.enterprise.v1
import rego.v1
decision := {"allow": false, "reasons": ["deny"]}
`,
			wantErr: "mandatory metadata",
		},
		{
			name: "allow all",
			rego: `package sts.enterprise.v1
import rego.v1
decision := {"allow": true, "reasons": ["allow all"]}
` + metadata,
			wantErr: "allowed a broker-generated negative probe",
		},
		{
			name: "app allow ignores identity and permissions",
			rego: `package sts.enterprise.v1
import rego.v1
default decision := {"allow": false, "reasons": ["deny"]}
decision := {"allow": true, "reasons": ["app only"]} if {
  input.request.app == "default"
}
` + metadata,
			wantErr: "allowed a broker-generated negative probe",
		},
		{
			name: "allow ignores malformed mode",
			rego: `package sts.enterprise.v1
import rego.v1
default decision := {"allow": false, "reasons": ["deny"]}
decision := {"allow": true, "reasons": ["incomplete contract"]} if {
  input.request.app == "default"
  input.source_identity.repository_owner_id == "123456"
  input.source_identity.repository_id == "456789"
  input.requested.permissions.contents == "read"
}
` + metadata,
			wantErr: "malformed input probe",
		},
		{
			name: "malformed decision metadata",
			rego: `package sts.enterprise.v1
import rego.v1
decision := {"allow": false, "reasons": "deny"}
` + metadata,
			wantErr: "reasons must be an array",
		},
		{
			name: "missing permission control",
			rego: `package sts.enterprise.v1
import rego.v1
decision := {"allow": false, "reasons": ["deny"]}
metadata := {
  "contract_version": "v1",
  "policy_revision": "test-1",
  "controls": ["immutable_identity"],
}
`,
			wantErr: "permission_boundary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMandatoryEngine(context.Background(), buildTarball(t, map[string]string{
				"/policies/policy.rego": tt.rego,
			}))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnterprisePolicyData_Exceptions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name    string
		mutate  func(map[string]any, map[string]any)
		wantErr string
	}{
		{name: "valid"},
		{
			name: "unknown field",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["typo"] = true
			},
			wantErr: "unknown field",
		},
		{
			name: "same owner and approver",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["approved_by"] = exception["owner"]
			},
			wantErr: "must be distinct",
		},
		{
			name: "principal whitespace",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["approved_by"] = " security@example.com "
			},
			wantErr: "leading or trailing whitespace",
		},
		{
			name: "future creation",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["created_at"] = now.Add(time.Hour).Format(time.RFC3339)
				exception["expires_at"] = now.Add(2 * time.Hour).Format(time.RFC3339)
			},
			wantErr: "must not be in the future",
		},
		{
			name: "expired",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["created_at"] = now.Add(-48 * time.Hour).Format(time.RFC3339)
				exception["expires_at"] = now.Add(-24 * time.Hour).Format(time.RFC3339)
			},
			wantErr: "is expired",
		},
		{
			name: "lifetime over 30 days",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["created_at"] = now.Add(-time.Hour).Format(time.RFC3339)
				exception["expires_at"] = now.Add(31 * 24 * time.Hour).Format(time.RFC3339)
			},
			wantErr: "lifetime exceeds",
		},
		{
			name: "same organization",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["source"].(map[string]any)["owner_id"] = "123456"
			},
			wantErr: "owner IDs must differ",
		},
		{
			name: "invalid permission",
			mutate: func(_ map[string]any, exception map[string]any) {
				exception["permission_ceiling"] = map[string]any{"made_up": "write"}
			},
			wantErr: "invalid permission",
		},
		{
			name: "duplicate ID",
			mutate: func(config map[string]any, exception map[string]any) {
				config["cross_org_exceptions"] = []any{exception, exception}
			},
			wantErr: "duplicate exception_id",
		},
		{
			name: "duplicate context",
			mutate: func(config map[string]any, exception map[string]any) {
				duplicate := make(map[string]any, len(exception))
				for key, value := range exception {
					duplicate[key] = value
				}
				duplicate["exception_id"] = "xorg-002"
				config["cross_org_exceptions"] = []any{exception, duplicate}
			},
			wantErr: "duplicate source/target/app/identity context",
		},
		{
			name: "organization-wide grant",
			mutate: func(config map[string]any, _ map[string]any) {
				config["org_wide_grants"] = []any{map[string]any{"grant_id": "not-yet-supported"}}
			},
			wantErr: "must remain empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, config, exception := validEnterpriseExceptionData(now)
			if tt.mutate != nil {
				tt.mutate(config, exception)
			}
			err := validateEnterprisePolicyData(data, now)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_FiltersExpiredAdmittedExceptions(t *testing.T) {
	now := time.Now().UTC()
	engine := &Engine{crossOrgExceptions: []admittedCrossOrgException{
		{input: InputCrossOrgException{ExceptionID: "expired"}, expiresAt: now.Add(-time.Second)},
		{input: InputCrossOrgException{ExceptionID: "active"}, expiresAt: now.Add(time.Second)},
	}}
	active := engine.activeCrossOrgExceptions(now)
	if len(active) != 1 || active[0].ExceptionID != "active" {
		t.Fatalf("active exceptions = %+v, want only active", active)
	}
}

func TestEngine_RejectsVirtualEnterpriseConfig(t *testing.T) {
	tarb := buildTarball(t, map[string]string{
		"/policies/config.rego": `package sts.enterprise_config
import rego.v1
v1 := {"contract_version": "v1", "cross_org_exceptions": [], "org_wide_grants": []}
`,
		"/policies/decision.rego": `package sts.enterprise.test
import rego.v1
decision := {"allow": false, "reasons": ["deny"]}
`,
	})
	_, err := NewEngine(context.Background(), tarb)
	if err == nil || !strings.Contains(err.Error(), "reserved enterprise data namespace") {
		t.Fatalf("error = %v, want reserved namespace rejection", err)
	}
}

func TestEngine_InjectsOnlyActiveAdmittedExceptions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	data, _, _ := validEnterpriseExceptionData(now)
	dataJSON, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	rego := `package sts.enterprise.exception_input_test
import rego.v1
default decision := {"allow": false, "reasons": ["no active exception"]}
decision := {
  "allow": true,
  "reasons": ["active exception"],
  "exception_id": input.authorization.cross_org_exceptions[0].exception_id,
} if {
  count(input.authorization.cross_org_exceptions) == 1
}
`
	engine, err := NewEngine(context.Background(), buildTarball(t, map[string]string{
		"/policies/decision.rego": rego,
		"/data.json":              string(dataJSON),
	}))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	decision, err := engine.Eval(context.Background(), Input{
		Authorization: &InputAuthorization{CrossOrgExceptions: []InputCrossOrgException{{ExceptionID: "caller-injected"}}},
	})
	if err != nil {
		t.Fatalf("Eval active: %v", err)
	}
	if !decision.Allow || len(decision.Packages) != 1 || decision.Packages[0].ExceptionID != "xorg-001" {
		t.Fatalf("engine did not replace caller exceptions with admitted data: %+v", decision)
	}

	engine.crossOrgExceptions[0].expiresAt = now.Add(-time.Second)
	decision, err = engine.Eval(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Eval expired: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expired exception remained active: %+v", decision)
	}
}

func validEnterpriseExceptionData(now time.Time) (map[string]any, map[string]any, map[string]any) {
	exception := map[string]any{
		"exception_id": "xorg-001",
		"rule_id":      "sts.relationship.cross_org",
		"source":       map[string]any{"owner_id": "9001", "repository_id": "9002"},
		"target":       map[string]any{"owner_id": "123456", "repository_id": "456789"},
		"app":          "default",
		"identity":     "ci",
		"permission_ceiling": map[string]any{
			"contents": "read",
		},
		"owner":       "platform@example.com",
		"approved_by": "security@example.com",
		"reason":      "temporary migration",
		"created_at":  now.Add(-time.Hour).Format(time.RFC3339),
		"expires_at":  now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	config := map[string]any{
		"contract_version":     "v1",
		"cross_org_exceptions": []any{exception},
		"org_wide_grants":      []any{},
	}
	data := map[string]any{
		"sts": map[string]any{
			"enterprise_config": map[string]any{"v1": config},
		},
	}
	return data, config, exception
}
