package policy

import (
	"errors"
	"testing"
)

// ceiling is the trust policy grant every case in this file narrows from.
func narrowCeiling() map[string]string {
	return map[string]string{"contents": "write", "issues": "write", "checks": "read"}
}

func TestNarrowPermissions_NilRequestReturnsFullCeiling(t *testing.T) {
	ceiling := narrowCeiling()
	got, err := NarrowPermissions(ceiling, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(ceiling) {
		t.Fatalf("got %v, want the full ceiling %v", got, ceiling)
	}
	for perm, level := range ceiling {
		if got[perm] != level {
			t.Fatalf("permission %q = %q, want %q", perm, got[perm], level)
		}
	}

	// The result must be a copy: a caller mutating it must not reach back
	// into the trust policy, which is shared and cached across requests.
	got["contents"] = "admin"
	if ceiling["contents"] != "write" {
		t.Fatalf("NarrowPermissions aliased the policy map: ceiling now %v", ceiling)
	}
}

func TestNarrowPermissions_Allowed(t *testing.T) {
	tests := []struct {
		name      string
		requested map[string]string
		want      map[string]string
	}{
		{
			name:      "downgrade write to read",
			requested: map[string]string{"contents": "read"},
			want:      map[string]string{"contents": "read"},
		},
		{
			name:      "request the ceiling level exactly",
			requested: map[string]string{"contents": "write"},
			want:      map[string]string{"contents": "write"},
		},
		{
			name:      "drop a permission and downgrade another",
			requested: map[string]string{"contents": "read", "issues": "read"},
			want:      map[string]string{"contents": "read", "issues": "read"},
		},
		{
			name:      "subset of one permission at its ceiling",
			requested: map[string]string{"checks": "read"},
			want:      map[string]string{"checks": "read"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NarrowPermissions(narrowCeiling(), tt.requested)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for perm, level := range tt.want {
				if got[perm] != level {
					t.Fatalf("permission %q = %q, want %q (full result %v)", perm, got[perm], level, got)
				}
			}
		})
	}
}

func TestNarrowPermissions_Rejected(t *testing.T) {
	tests := []struct {
		name      string
		requested map[string]string
	}{
		{
			name:      "permission absent from the policy",
			requested: map[string]string{"packages": "write"},
		},
		{
			name:      "level above the policy ceiling",
			requested: map[string]string{"checks": "write"},
		},
		{
			name:      "admin above a write ceiling",
			requested: map[string]string{"contents": "admin"},
		},
		{
			name:      "unrecognized permission name",
			requested: map[string]string{"not_a_real_permission": "read"},
		},
		{
			name:      "unrecognized level",
			requested: map[string]string{"contents": "bogus"},
		},
		{
			name:      "empty level",
			requested: map[string]string{"contents": ""},
		},
		{
			name:      "one valid entry does not excuse an invalid one",
			requested: map[string]string{"contents": "read", "packages": "write"},
		},
		{
			// Distinct from nil: a caller that built the map programmatically
			// and ended up with nothing must fail, not silently receive a
			// full-privilege token.
			name:      "explicitly empty request",
			requested: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NarrowPermissions(narrowCeiling(), tt.requested)
			if err == nil {
				t.Fatalf("expected rejection, got %v", got)
			}
			if got != nil {
				t.Fatalf("rejected request must return a nil map, got %v", got)
			}
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want *ValidationError", err)
			}
		})
	}
}

func TestNarrowPermissions_ErrorIsDeterministic(t *testing.T) {
	// Two invalid entries: whichever map iteration order Go picks, the
	// reported error must be the same one every time, or the failure is
	// unreproducible for whoever has to debug it.
	requested := map[string]string{"aaa_invalid": "read", "zzz_invalid": "read"}
	first, err := NarrowPermissions(narrowCeiling(), requested)
	if err == nil {
		t.Fatalf("expected rejection, got %v", first)
	}
	want := err.Error()
	for i := 0; i < 50; i++ {
		_, err := NarrowPermissions(narrowCeiling(), requested)
		if err == nil || err.Error() != want {
			t.Fatalf("iteration %d error = %v, want stable %q", i, err, want)
		}
	}
}

func TestPermissionRank_UnknownLevelIsLeastPrivileged(t *testing.T) {
	if PermissionRank("bogus") != 0 {
		t.Fatalf("unknown level ranked %d, want 0", PermissionRank("bogus"))
	}
	if PermissionRank("") != 0 {
		t.Fatalf("empty level ranked %d, want 0", PermissionRank(""))
	}
	if PermissionRank("read") >= PermissionRank("write") || PermissionRank("write") >= PermissionRank("admin") {
		t.Fatal("permission levels are not ordered read < write < admin")
	}
}

// TestFormatPermissions_IsDeterministic guards a bug that is invisible in
// casual testing: Go randomizes map iteration order, so an unsorted join
// renders the *same* permission set as different strings on different
// calls. That string is a Prometheus label value on
// githubsts_github_tokens_issued_total, so an unstable rendering splits one
// logical time series into as many as n! of them, and makes log lines for
// identical grants fail to group.
func TestFormatPermissions_IsDeterministic(t *testing.T) {
	perms := map[string]string{
		"contents": "write", "issues": "write", "checks": "read",
		"actions": "read", "packages": "write", "deployments": "read",
	}
	want := FormatPermissions(perms)
	for i := 0; i < 500; i++ {
		if got := FormatPermissions(perms); got != want {
			t.Fatalf("iteration %d rendered %q, want stable %q", i, got, want)
		}
	}
}

func TestFormatPermissions(t *testing.T) {
	tests := []struct {
		name  string
		perms map[string]string
		want  string
	}{
		{
			// GitHub's own semantics: omitting the field inherits every
			// permission the installation holds.
			name:  "empty means all",
			perms: map[string]string{},
			want:  "all",
		},
		{name: "nil means all", perms: nil, want: "all"},
		{name: "single", perms: map[string]string{"contents": "read"}, want: "contents:read"},
		{
			name:  "sorted by permission name, not insertion order",
			perms: map[string]string{"issues": "write", "actions": "read", "contents": "read"},
			want:  "actions:read,contents:read,issues:write",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatPermissions(tt.perms); got != tt.want {
				t.Fatalf("FormatPermissions() = %q, want %q", got, tt.want)
			}
		})
	}
}
