//go:build githubspec

// This file is excluded from normal builds and CI by the githubspec tag. It
// reaches the network, and GitHub adding a permission should open a pull
// request rather than turn an unrelated build red. Run it deliberately:
//
//	make check-github-permissions
package policy

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"
)

// specURL is GitHub's published OpenAPI description. app-permissions is the
// schema that create-installation-access-token declares for the permissions
// field of its request body, which is the call internal/github/app.go makes to
// mint a token. That linkage is what makes this file authoritative rather than
// merely plausible; TestGitHubSpecDescribesTheMintEndpoint asserts it still
// holds instead of assuming it.
const specURL = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json"

type openAPISpec struct {
	Paths map[string]struct {
		Post struct {
			OperationID string `json:"operationId"`
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Properties map[string]struct {
							Ref string `json:"$ref"`
						} `json:"properties"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		} `json:"post"`
	} `json:"paths"`
	Components struct {
		Schemas struct {
			AppPermissions struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"app-permissions"`
		} `json:"schemas"`
	} `json:"components"`
}

func fetchSpec(t *testing.T) *openAPISpec {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(specURL)
	if err != nil {
		t.Fatalf("fetch %s: %v", specURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch %s: HTTP %d", specURL, resp.StatusCode)
	}
	var spec openAPISpec
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	return &spec
}

// TestGitHubSpecDescribesTheMintEndpoint verifies the premise before the
// comparison: that app-permissions is still what the mint endpoint declares.
// If GitHub restructures the spec, this fails with a clear reason rather than
// letting the permission comparison silently check the wrong schema.
func TestGitHubSpecDescribesTheMintEndpoint(t *testing.T) {
	spec := fetchSpec(t)
	const path = "/app/installations/{installation_id}/access_tokens"
	entry, ok := spec.Paths[path]
	if !ok {
		t.Fatalf("spec has no path %s", path)
	}
	if entry.Post.OperationID != "apps/create-installation-access-token" {
		t.Errorf("operationId = %q, want apps/create-installation-access-token", entry.Post.OperationID)
	}
	body, ok := entry.Post.RequestBody.Content["application/json"]
	if !ok {
		t.Fatal("mint endpoint has no application/json request body")
	}
	if got := body.Schema.Properties["permissions"].Ref; got != "#/components/schemas/app-permissions" {
		t.Errorf("permissions $ref = %q, want #/components/schemas/app-permissions", got)
	}
}

// TestValidPermissionLevelsMatchGitHubSpec diffs our table against upstream in
// both directions. A failure is not a bug in this repository: it means GitHub
// changed the contract, and the fix is to regenerate ValidPermissionLevels and
// the JSON Schema together.
func TestValidPermissionLevelsMatchGitHubSpec(t *testing.T) {
	spec := fetchSpec(t)
	upstream := spec.Components.Schemas.AppPermissions.Properties
	if len(upstream) == 0 {
		t.Fatal("spec carries no app-permissions properties")
	}

	for name, entry := range upstream {
		ours, ok := ValidPermissionLevels[name]
		if !ok {
			t.Errorf("GitHub added permission %q (levels %v); add it to ValidPermissionLevels and the schema",
				name, entry.Enum)
			continue
		}
		want := slices.Clone(entry.Enum)
		got := slices.Clone(ours)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("permission %q: we allow %v, GitHub allows %v", name, ours, entry.Enum)
		}
	}
	for name := range ValidPermissionLevels {
		if _, ok := upstream[name]; !ok {
			t.Errorf("we allow permission %q, which GitHub no longer documents", name)
		}
	}
}
