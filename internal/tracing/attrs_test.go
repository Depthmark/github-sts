package tracing

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/audit"
	"go.opentelemetry.io/otel/attribute"
)

// TestNoReservedAttributeNames is the trace-side twin of
// metrics.TestNoReservedLabelNames, and exists for the same reason one layer
// out: a span attribute does not stay in traces. The Collector's spanmetrics
// connector promotes span attributes to Prometheus metric dimensions, where
// the OTLP-to-Prometheus mapping normalizes "." to "_" and the result meets
// Kubernetes service discovery. A promoted `app` or `instance` collides exactly
// as it did before d6a89f4, and just as silently.
//
// The check is on the normalized form, not the raw key, because that is what a
// backend actually sees: "github.app" normalizes to "github_app", which is the
// label the metrics already use and the reason that key was chosen.
func TestNoReservedAttributeNames(t *testing.T) {
	for key := range AllowedKeys {
		normalized := strings.ReplaceAll(string(key), ".", "_")
		if _, bad := ReservedLabelNames[normalized]; bad {
			t.Errorf("attribute %q normalizes to reserved Prometheus label %q", key, normalized)
		}
		// A bare single-segment key is the shape most likely to collide with
		// something injected later, even if it is not reserved today.
		if !strings.Contains(string(key), ".") {
			t.Errorf("attribute %q has no namespace segment; prefix it", key)
		}
	}
}

// TestAllowedKeysMatchesDeclaredConstants reads the source rather than the
// package's own variable, so a constant added without being added to
// AllowedKeys fails the build. Without this, the allow-list silently drifts
// from what the package can actually emit and stops being an allow-list.
func TestAllowedKeysMatchesDeclaredConstants(t *testing.T) {
	source, err := os.ReadFile("attrs.go")
	if err != nil {
		t.Fatalf("read attrs.go: %v", err)
	}

	pattern := regexp.MustCompile(`attribute\.Key\("([^"]+)"\)`)
	matches := pattern.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("found no attribute.Key declarations; the pattern is stale and this test is inert")
	}

	for _, m := range matches {
		key := attribute.Key(m[1])
		// ReservedLabelNames is a plain string set, not attribute keys.
		if _, ok := AllowedKeys[key]; !ok {
			t.Errorf("attribute key %q is declared but missing from AllowedKeys", key)
		}
	}
}

// TestExchangeAttributesEmitsOnlyAllowedKeys is the deny-list guard. A bearer
// token, a minted installation token, an App private key or JWT, a raw claims
// map or a registry credential must never reach a span. Rather than pattern-
// matching for secrets, this asserts the stronger property: nothing outside the
// allow-list is emitted at all.
func TestExchangeAttributesEmitsOnlyAllowedKeys(t *testing.T) {
	immutable := true
	required := false

	// Every optional field populated, so the test exercises the widest
	// attribute set the function can produce.
	event := audit.Event{
		TraceID:                  "4bf92f3577b34da6a3ce929d0e0e4736",
		Scope:                    "myorg/myrepo",
		AppName:                  "checkout",
		Instance:                 "checkout-2",
		Identity:                 "ci",
		Issuer:                   "https://token.actions.githubusercontent.com",
		Subject:                  "repo:myorg@1001/myrepo@2002:ref:refs/heads/main",
		SourceRepositoryOwner:    "myorg",
		SourceRepositoryOwnerID:  "1001",
		SourceRepository:         "myorg/myrepo",
		SourceRepositoryID:       "2002",
		TargetRepositoryOwner:    "myorg",
		TargetRepositoryOwnerID:  "1001",
		TargetRepository:         "myorg/target",
		TargetRepositoryID:       "3001",
		ImmutableSubject:         &immutable,
		ImmutableSubjectRequired: &required,
		JTI:                      "jti-abc",
		PolicyRepository:         "myorg/.github",
		PolicyPath:               ".github/sts/myrepo.yaml",
		PolicyBlobSHA:            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
		PolicySource:             "centralized",
		InstallationPermissions:  map[string]string{"contents": "write", "issues": "write"},
		PolicyPermissions:        map[string]string{"contents": "write"},
		RequestedPermissions:     map[string]string{"contents": "read"},
		GrantedPermissions:       map[string]string{"contents": "read", "metadata": "read"},
		Result:                   audit.ResultSuccess,
		ErrorReason:              "should never be emitted",
		DurationMS:               840,
		UserAgent:                "github-sts-action/1.0",
		RemoteIP:                 "10.0.0.7",
		BundleDigest:             "sha256:abc",
		BundleEnforcement:        "required",
		OrgDecision:              &audit.OrgDecision{Applicable: true, Evaluated: true, Allow: true},
	}

	for _, kv := range ExchangeAttributes(event) {
		if _, ok := AllowedKeys[kv.Key]; !ok {
			t.Errorf("emitted attribute %q is not in AllowedKeys", kv.Key)
		}
		if strings.Contains(strings.ToLower(kv.Value.String()), "should never be emitted") {
			t.Errorf("attribute %q leaked audit.Event.ErrorReason", kv.Key)
		}
	}
}

// TestFormatPermissionsIsStable guards the property the attribute depends on:
// Go map iteration is randomized, so an unsorted render would produce a
// different string for the same grant on every call, making the value useless
// for grouping or diffing two spans.
func TestFormatPermissionsIsStable(t *testing.T) {
	perms := map[string]string{"issues": "write", "contents": "read", "actions": "read"}
	want := "actions=read,contents=read,issues=write"

	for i := 0; i < 32; i++ {
		if got := formatPermissions(perms); got != want {
			t.Fatalf("formatPermissions = %q, want %q", got, want)
		}
	}

	if got := formatPermissions(nil); got != "" {
		t.Errorf("formatPermissions(nil) = %q, want empty", got)
	}
}

// TestExchangeAttributesOmitsEmptyFields keeps a failed early-stage exchange
// from carrying a dozen blank attributes, which would both cost storage and
// make "absent" indistinguishable from "empty" in a query.
func TestExchangeAttributesOmitsEmptyFields(t *testing.T) {
	attrs := ExchangeAttributes(audit.Event{
		Scope:    "myorg/myrepo",
		Identity: "ci",
		Result:   audit.ResultOIDCInvalid,
	})

	for _, kv := range attrs {
		if kv.Value.String() == "" {
			t.Errorf("attribute %q emitted with an empty value", kv.Key)
		}
	}

	seen := make(map[attribute.Key]bool, len(attrs))
	for _, kv := range attrs {
		seen[kv.Key] = true
	}
	if seen[AttrGitHubAppInstance] {
		t.Error("github.app.instance emitted for an exchange that never reached the mint")
	}
	if seen[AttrPermissionsGranted] {
		t.Error("sts.permissions.granted emitted for an exchange that minted nothing")
	}
}
