package github

import "testing"

// TestFormatPermissions_IsDeterministic guards a bug that is invisible in
// casual testing: Go randomizes map iteration order, so an unsorted join
// renders the *same* permission set as different strings on different calls.
// That string is a Prometheus label value on
// githubsts_github_tokens_issued_total, so an unstable rendering splits one
// logical time series into as many as n! of them.
func TestFormatPermissions_IsDeterministic(t *testing.T) {
	perms := map[string]string{
		"contents": "write", "issues": "write", "checks": "read",
		"actions": "read", "packages": "write", "deployments": "read",
	}
	want := formatPermissions(perms)
	for i := 0; i < 500; i++ {
		if got := formatPermissions(perms); got != want {
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
		// GitHub's own semantics: omitting the field inherits every
		// permission the installation holds.
		{name: "empty means all", perms: map[string]string{}, want: "all"},
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
			if got := formatPermissions(tt.perms); got != tt.want {
				t.Fatalf("formatPermissions() = %q, want %q", got, tt.want)
			}
		})
	}
}
