package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
)

func permissionEvent(result ExchangeResult) Event {
	return Event{
		TraceID:              "trace-1",
		Scope:                "myorg/myrepo",
		AppName:              "default",
		Identity:             "ci",
		BundleEnforcement:    bundle.EnforcementOptional,
		Result:               result,
		PolicyPermissions:    map[string]string{"contents": "write", "issues": "write"},
		RequestedPermissions: map[string]string{"contents": "read"},
		GrantedPermissions:   map[string]string{"contents": "read", "metadata": "read"},
	}
}

// TestAuditSlog_CarriesPermissionSets is the regression guard for the gap
// that motivated this: the slog attributes are hand-picked, so a field added
// to Event reaches the JSON audit file automatically but reaches container
// logs only if it is listed here. A deployment without a mounted audit file
// -- the common Kubernetes case -- sees only the slog stream.
func TestAuditSlog_CarriesPermissionSets(t *testing.T) {
	_, logged := logAndCapture(t, permissionEvent(ResultSuccess))

	for _, want := range []string{
		"policy_permissions=contents:write,issues:write",
		"requested_permissions=contents:read",
		"granted_permissions=contents:read,metadata:read",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("slog output missing %q\ngot: %s", want, logged)
		}
	}
}

// The three sets must be rendered as sorted scalars, not Go maps: a log
// aggregator can group and filter on "contents:read,metadata:read" but not
// on "map[contents:read metadata:read]".
func TestAuditSlog_PermissionsAreSortedScalars(t *testing.T) {
	_, logged := logAndCapture(t, permissionEvent(ResultSuccess))

	if strings.Contains(logged, "map[") {
		t.Errorf("permissions rendered as a Go map, want a sorted scalar\ngot: %s", logged)
	}
	// Sorted, so "contents" precedes "issues" and "metadata" regardless of
	// map iteration order.
	if !strings.Contains(logged, "contents:write,issues:write") {
		t.Errorf("policy permissions not in sorted order\ngot: %s", logged)
	}
}

// A rejected request is precisely the one an investigator wants the ask for,
// so the sets must survive a non-success result too.
func TestAuditSlog_PermissionsPresentOnDenial(t *testing.T) {
	event := permissionEvent(ResultPolicyDenied)
	event.GrantedPermissions = nil // nothing was minted
	event.ErrorReason = "permission narrowing rejected"

	_, logged := logAndCapture(t, event)

	if !strings.Contains(logged, "requested_permissions=contents:read") {
		t.Errorf("denied exchange lost the requested permissions\ngot: %s", logged)
	}
	if !strings.Contains(logged, "policy_permissions=contents:write,issues:write") {
		t.Errorf("denied exchange lost the policy ceiling\ngot: %s", logged)
	}
	if strings.Contains(logged, "granted_permissions=") {
		t.Errorf("no token was minted, granted_permissions must be absent\ngot: %s", logged)
	}
}

// The JSON audit file keeps the structured maps; only the slog rendering is
// flattened. Both consumers stay correct.
func TestAuditFile_KeepsStructuredPermissionMaps(t *testing.T) {
	fileLine, _ := logAndCapture(t, permissionEvent(ResultSuccess))

	var decoded Event
	if err := json.Unmarshal(fileLine, &decoded); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, fileLine)
	}
	if decoded.PolicyPermissions["issues"] != "write" {
		t.Errorf("policy_permissions = %v", decoded.PolicyPermissions)
	}
	if decoded.RequestedPermissions["contents"] != "read" {
		t.Errorf("requested_permissions = %v", decoded.RequestedPermissions)
	}
	if decoded.GrantedPermissions["metadata"] != "read" {
		t.Errorf("granted_permissions = %v", decoded.GrantedPermissions)
	}
}

// An exchange with no narrowing must not emit an empty requested_permissions
// field: absent means "the caller asked for nothing in particular", and an
// empty rendering would read as "the caller asked for nothing".
func TestAuditSlog_OmitsAbsentPermissionSets(t *testing.T) {
	event := permissionEvent(ResultSuccess)
	event.RequestedPermissions = nil

	_, logged := logAndCapture(t, event)

	if strings.Contains(logged, "requested_permissions") {
		t.Errorf("un-narrowed exchange emitted requested_permissions\ngot: %s", logged)
	}
	if !strings.Contains(logged, "policy_permissions=") {
		t.Errorf("policy permissions should still be present\ngot: %s", logged)
	}
}

// TestAuditSlog_CarriesFullPrivilegeChain checks that all four levels reach
// the log. Each answers a different question, and only together do they let
// a reviewer distinguish "this exchange was correctly scoped" from "this
// broker holds far more power than anything here needed".
func TestAuditSlog_CarriesFullPrivilegeChain(t *testing.T) {
	event := permissionEvent(ResultSuccess)
	event.InstallationPermissions = map[string]string{
		"contents": "write", "issues": "write", "administration": "write",
	}

	_, logged := logAndCapture(t, event)

	for _, want := range []string{
		"installation_permissions=administration:write,contents:write,issues:write",
		"policy_permissions=contents:write,issues:write",
		"requested_permissions=contents:read",
		"granted_permissions=contents:read,metadata:read",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("slog output missing %q\ngot: %s", want, logged)
		}
	}
}

// The installation cache can expire between the mint and the read. That is
// rare and non-fatal, but it must render as absent rather than as an empty
// set: "we don't know the ceiling" and "the ceiling is nothing" are
// opposite conclusions for an auditor.
func TestAuditSlog_UnknownInstallationCeilingIsAbsentNotEmpty(t *testing.T) {
	event := permissionEvent(ResultSuccess)
	event.InstallationPermissions = nil

	fileLine, logged := logAndCapture(t, event)

	if strings.Contains(logged, "installation_permissions") {
		t.Errorf("unknown ceiling emitted a field\ngot: %s", logged)
	}
	if strings.Contains(string(fileLine), "installation_permissions") {
		t.Errorf("unknown ceiling serialized into the audit file\ngot: %s", fileLine)
	}
}

// TestAuditFile_PrivilegeChainIsDescending documents the invariant the four
// fields are meant to expose. It is not enforced by the type system, so a
// future change that wires the wrong map into the wrong field would be
// caught here rather than in an incident.
func TestAuditFile_PrivilegeChainIsDescending(t *testing.T) {
	event := permissionEvent(ResultSuccess)
	event.InstallationPermissions = map[string]string{"contents": "write", "issues": "write"}

	fileLine, _ := logAndCapture(t, event)
	var decoded Event
	if err := json.Unmarshal(fileLine, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// contents narrows write -> write -> read -> read down the chain.
	steps := []struct {
		name  string
		perms map[string]string
		want  string
	}{
		{"installation", decoded.InstallationPermissions, "write"},
		{"policy", decoded.PolicyPermissions, "write"},
		{"requested", decoded.RequestedPermissions, "read"},
		{"granted", decoded.GrantedPermissions, "read"},
	}
	for _, step := range steps {
		if got := step.perms["contents"]; got != step.want {
			t.Errorf("%s contents = %q, want %q", step.name, got, step.want)
		}
	}
}
