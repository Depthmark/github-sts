package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/metrics"
	dto "github.com/prometheus/client_model/go"
)

// divergenceServer fakes GitHub returning a specific grant in the 201,
// regardless of what was requested. That is the whole point: the grant is
// the authoritative statement, and the broker must read it rather than
// assume the ask was honored.
func divergenceServer(t *testing.T, granted map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Order matters: "/app/installations/42/access_tokens" also
		// contains "/installation".
		case strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":       "ghs_test",
				"expires_at":  "2026-01-01T00:00:00Z",
				"permissions": granted,
			})
		case strings.Contains(r.URL.Path, "/installation"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          int64(42),
				"permissions": map[string]string{"contents": "write", "issues": "write"},
			})
		}
	}))
}

func divergenceCount(t *testing.T, permission, direction string) float64 {
	t.Helper()
	m := &dto.Metric{}
	c, err := metrics.GitHubTokenPermissionDivergence.GetMetricWithLabelValues("test-app", "test-instance", permission, direction)
	if err != nil {
		t.Fatalf("get metric: %v", err)
	}
	if err := c.(interface{ Write(*dto.Metric) error }).Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

func mintWithGrant(t *testing.T, granted, requested map[string]string) MintedToken {
	t.Helper()
	srv := divergenceServer(t, granted)
	defer srv.Close()

	p := NewAppTokenProvider("test-app", "test-instance", 12345, generateTestKey(t), srv.URL, nil)
	minted, _, err := p.GetInstallationTokenForTarget(context.Background(),
		TargetIdentity{Scope: "myorg/myrepo", RepositoryID: "3001"},
		PermissionRequest{Ceiling: map[string]string{"contents": "write", "issues": "write"}, Effective: requested},
		"test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return minted
}

// TestMintedToken_CarriesGitHubGrant is the counter-validation hook: the
// permissions on the returned token come from GitHub's response body, not
// from what we asked for.
func TestMintedToken_CarriesGitHubGrant(t *testing.T) {
	minted := mintWithGrant(t,
		map[string]string{"contents": "read", "metadata": "read"},
		map[string]string{"contents": "read"})

	if minted.Token != "ghs_test" {
		t.Fatalf("token = %q", minted.Token)
	}
	if minted.Permissions["contents"] != "read" || minted.Permissions["metadata"] != "read" {
		t.Fatalf("granted permissions = %v, want GitHub's response body verbatim", minted.Permissions)
	}
	if minted.ExpiresAt.IsZero() {
		t.Fatal("expires_at was not decoded")
	}
}

// TestPermissionDivergence_ImplicitMetadataIsNotDivergence guards the noisy
// failure mode: GitHub attaches metadata:read to every installation token,
// so a check that flagged it would fire on every single exchange and be
// switched off within a day.
func TestPermissionDivergence_ImplicitMetadataIsNotDivergence(t *testing.T) {
	before := divergenceCount(t, "metadata", "above_requested")
	mintWithGrant(t,
		map[string]string{"contents": "read", "metadata": "read"},
		map[string]string{"contents": "read"})
	if got := divergenceCount(t, "metadata", "above_requested"); got != before {
		t.Fatalf("metadata counted as divergence: %v -> %v", before, got)
	}
}

func TestPermissionDivergence_ExactMatchIsSilent(t *testing.T) {
	before := divergenceCount(t, "contents", "above_requested")
	mintWithGrant(t,
		map[string]string{"contents": "read"},
		map[string]string{"contents": "read"})
	if got := divergenceCount(t, "contents", "above_requested"); got != before {
		t.Fatalf("exact match counted as divergence: %v -> %v", before, got)
	}
}

// TestPermissionDivergence_OverGrantIsDetected is the hypothesis under test:
// if GitHub ever ignored a requested downgrade and handed back the
// installation's write, narrowing would be silently unenforceable. This
// asserts the broker would notice.
func TestPermissionDivergence_OverGrantIsDetected(t *testing.T) {
	before := divergenceCount(t, "contents", "above_requested")
	mintWithGrant(t,
		map[string]string{"contents": "write"},
		map[string]string{"contents": "read"})
	if got := divergenceCount(t, "contents", "above_requested"); got != before+1 {
		t.Fatalf("over-grant not detected: %v -> %v, want +1", before, got)
	}
}

// A permission granted that was never asked for is also an over-grant,
// unless it is on the implicit list.
func TestPermissionDivergence_UnrequestedGrantIsDetected(t *testing.T) {
	before := divergenceCount(t, "issues", "above_requested")
	mintWithGrant(t,
		map[string]string{"contents": "read", "issues": "write"},
		map[string]string{"contents": "read"})
	if got := divergenceCount(t, "issues", "above_requested"); got != before+1 {
		t.Fatalf("unrequested grant not detected: %v -> %v, want +1", before, got)
	}
}

// An under-grant fails safe but still breaks callers, so it is counted in
// its own direction rather than ignored.
func TestPermissionDivergence_UnderGrantIsDetectedSeparately(t *testing.T) {
	beforeBelow := divergenceCount(t, "contents", "below_requested")
	beforeAbove := divergenceCount(t, "contents", "above_requested")
	mintWithGrant(t,
		map[string]string{"contents": "read"},
		map[string]string{"contents": "write"})
	if got := divergenceCount(t, "contents", "below_requested"); got != beforeBelow+1 {
		t.Fatalf("under-grant not detected: %v -> %v, want +1", beforeBelow, got)
	}
	if got := divergenceCount(t, "contents", "above_requested"); got != beforeAbove {
		t.Fatalf("under-grant misfiled as over-grant: %v -> %v", beforeAbove, got)
	}
}

func TestPermissionDivergence_MissingPermissionIsUnderGrant(t *testing.T) {
	before := divergenceCount(t, "issues", "below_requested")
	mintWithGrant(t,
		map[string]string{"contents": "read"},
		map[string]string{"contents": "read", "issues": "read"})
	if got := divergenceCount(t, "issues", "below_requested"); got != before+1 {
		t.Fatalf("missing permission not detected: %v -> %v, want +1", before, got)
	}
}

func TestPermissionNameOf(t *testing.T) {
	tests := map[string]string{
		"contents (requested read, granted write)": "contents",
		"issues (granted write, not requested)":    "issues",
		"contents":                                 "contents",
	}
	for entry, want := range tests {
		if got := permissionNameOf(entry); got != want {
			t.Fatalf("permissionNameOf(%q) = %q, want %q", entry, got, want)
		}
	}
}

// TestMintedToken_CarriesInstallationCeiling checks that the App
// installation's own grant rides along with the token. It is the only one of
// the four privilege levels the broker cannot reconstruct after the fact,
// and it is already cached by the installation lookup, so carrying it costs
// a map copy rather than an API call.
func TestMintedToken_CarriesInstallationCeiling(t *testing.T) {
	minted := mintWithGrant(t,
		map[string]string{"contents": "read", "metadata": "read"},
		map[string]string{"contents": "read"})

	// divergenceServer reports the installation holding contents+issues at
	// write, which is strictly above both the request and the grant.
	if minted.InstallationPermissions["contents"] != "write" {
		t.Fatalf("installation contents = %q, want write (the ceiling above the ask)",
			minted.InstallationPermissions["contents"])
	}
	if minted.InstallationPermissions["issues"] != "write" {
		t.Fatalf("installation permissions = %v, want the full installation grant",
			minted.InstallationPermissions)
	}
	// The token itself carries far less. That gap is the point.
	if _, ok := minted.Permissions["issues"]; ok {
		t.Fatalf("token permissions = %v, must not inherit the installation ceiling", minted.Permissions)
	}
}
