package policy

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The published JSON Schema and this package state the same contract twice.
// The schema is served from
// https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json and
// consumed by editors in repositories this project does not control, so a
// divergence does not surface here as a failing exchange. It surfaces as
// somebody's editor accepting a policy the broker rejects, or flagging one it
// accepts. These tests make that divergence a failing build instead.
//
// Adding a permission means editing both ValidPermissionLevels and the
// schema. That is the intended cost: the second edit is what reaches users.

const schemaPath = "yaml/schema_v1.json"

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse %s: %v", schemaPath, err)
	}
	return schema
}

// dig walks a chain of object keys, failing the test with the path it got
// stuck on rather than a bare nil dereference.
func dig(t *testing.T, node map[string]any, keys ...string) any {
	t.Helper()
	var current any = node
	for i, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("schema: %v is not an object", keys[:i])
		}
		current, ok = object[key]
		if !ok {
			t.Fatalf("schema: missing %v", keys[:i+1])
		}
	}
	return current
}

func enumStrings(t *testing.T, node any, where string) map[string]bool {
	t.Helper()
	items, ok := node.([]any)
	if !ok {
		t.Fatalf("schema: %s is not an array", where)
	}
	out := make(map[string]bool, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok {
			t.Fatalf("schema: %s contains a non-string entry %v", where, item)
		}
		out[value] = true
	}
	return out
}

// levelDefs maps a $defs name to the levels it permits. Kept here rather than
// read out of the schema so the test states the expectation independently: if
// somebody edits both the $def and the table it feeds, that is two deliberate
// edits, not one slip.
var levelDefs = map[string][]string{
	"readWrite":      {"read", "write"},
	"readWriteAdmin": {"read", "write", "admin"},
	"readOnly":       {"read"},
	"writeOnly":      {"write"},
}

// TestSchemaPermissionsMatchValidPermissionLevels pins the schema's per
// permission level refs to ValidPermissionLevels, in both directions and for
// every permission.
//
// The uniform read/write/admin enum this replaced was wrong for 51 of 55
// permissions. GitHub accepts admin on only four, rejects write on
// organization_events and organization_plan, and rejects read on profile and
// workflows. Anything looser here hands the user a 422 from the mint call
// instead of a validation error while they are still editing the policy.
func TestSchemaPermissionsMatchValidPermissionLevels(t *testing.T) {
	schema := loadSchema(t)
	raw, ok := dig(t, schema, "properties", "permissions", "properties").(map[string]any)
	if !ok {
		t.Fatal("schema: properties.permissions.properties is not an object")
	}

	inSchema := make(map[string][]string, len(raw))
	for name, node := range raw {
		entry, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("schema: permission %q is not an object", name)
		}
		ref, ok := entry["$ref"].(string)
		if !ok {
			t.Fatalf("schema: permission %q has no $ref", name)
		}
		defName := strings.TrimPrefix(ref, "#/$defs/")
		levels, ok := levelDefs[defName]
		if !ok {
			t.Fatalf("schema: permission %q points at unknown $def %q", name, ref)
		}
		inSchema[name] = levels
	}

	for name, want := range ValidPermissionLevels {
		got, ok := inSchema[name]
		if !ok {
			t.Errorf("schema omits permission %q, which the broker accepts", name)
			continue
		}
		if !slices.Equal(got, want) {
			t.Errorf("permission %q: schema allows %v, broker allows %v", name, got, want)
		}
	}
	for name := range inSchema {
		if _, ok := ValidPermissionLevels[name]; !ok {
			t.Errorf("schema permits permission %q, which the broker rejects", name)
		}
	}
}

// TestSchemaLevelDefsMatchDeclaredEnums checks the $defs the table above names
// actually carry the levels it claims, so a silent edit to a $def cannot make
// the pinning test pass while the published schema says something else.
func TestSchemaLevelDefsMatchDeclaredEnums(t *testing.T) {
	schema := loadSchema(t)
	for defName, want := range levelDefs {
		got := enumStrings(t, dig(t, schema, "$defs", defName, "enum"), "$defs."+defName+".enum")
		if len(got) != len(want) {
			t.Errorf("$defs.%s.enum has %d entries, want %d", defName, len(got), len(want))
		}
		for _, level := range want {
			if !got[level] {
				t.Errorf("$defs.%s.enum is missing %q", defName, level)
			}
		}
	}
}

// TestPermissionLevelAllowed counter-validates the accessor against the four
// shapes, including the two that the old uniform enum got wrong.
func TestPermissionLevelAllowed(t *testing.T) {
	cases := []struct {
		permission, level string
		want              bool
	}{
		{"contents", "read", true},
		{"contents", "write", true},
		{"contents", "admin", false}, // 51 permissions do not take admin
		{"repository_projects", "admin", true},
		{"workflows", "write", true},
		{"workflows", "read", false}, // write-only
		{"organization_plan", "read", true},
		{"organization_plan", "write", false}, // read-only
		{"code_quality", "read", true},        // present upstream, was missing here
		{"contents", "none", false},
		{"not_a_permission", "read", false},
	}
	for _, tc := range cases {
		if got := PermissionLevelAllowed(tc.permission, tc.level); got != tc.want {
			t.Errorf("PermissionLevelAllowed(%q, %q) = %v, want %v",
				tc.permission, tc.level, got, tc.want)
		}
	}
}

// TestSchemaIDMatchesPublishedURL guards the one field a reader cannot verify
// by inspection. $id must name the URL the file is actually served from, or
// $ref resolution and schema-catalogue registration break against it. The
// previous value pointed at a host with no DNS record, which is exactly the
// failure this test exists to prevent recurring.
func TestSchemaIDMatchesPublishedURL(t *testing.T) {
	const want = "https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json"
	schema := loadSchema(t)
	got, _ := schema["$id"].(string)
	if got != want {
		t.Errorf("schema $id = %q, want %q\nThe path under docs/static/ (see SCHEMA_SITE_DIR in the Makefile) must match this URL.", got, want)
	}
}
