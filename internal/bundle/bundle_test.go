package bundle

import (
	"encoding/json"
	"testing"

	"github.com/depthmark/github-sts/internal/policy"
)

func TestInputSourceIdentityJSON(t *testing.T) {
	withoutIdentity, err := json.Marshal(Input{Mode: ModeExchange})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(withoutIdentity, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["source_identity"]; ok {
		t.Fatal("source_identity should be omitted when nil")
	}

	withIdentity, err := json.Marshal(Input{
		Mode: ModeExchange,
		SourceIdentity: &InputSourceIdentity{
			Version:                  SourceIdentityVersionV1,
			Issuer:                   "https://token.actions.githubusercontent.com",
			Subject:                  "repo:org/repo:ref:refs/heads/main",
			RepositoryOwner:          "org",
			RepositoryOwnerID:        "1001",
			Repository:               "org/repo",
			RepositoryID:             "2002",
			ImmutableSubject:         false,
			ImmutableSubjectRequired: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(withIdentity, &raw); err != nil {
		t.Fatal(err)
	}
	source, ok := raw["source_identity"].(map[string]any)
	if !ok {
		t.Fatalf("source_identity has unexpected shape: %v", raw["source_identity"])
	}
	if source["version"] != SourceIdentityVersionV1 || source["repository_id"] != "2002" {
		t.Fatalf("source_identity fields missing: %v", source)
	}
	if immutable, ok := source["immutable_subject"].(bool); !ok || immutable {
		t.Fatalf("immutable_subject = %v, want explicit false", source["immutable_subject"])
	}
	if required, ok := source["immutable_subject_required"].(bool); !ok || required {
		t.Fatalf("immutable_subject_required = %v, want explicit false", source["immutable_subject_required"])
	}
}

func TestInputTargetIdentityJSON(t *testing.T) {
	data, err := json.Marshal(Input{
		Mode: ModeExchange,
		TargetIdentity: &InputTargetIdentity{
			Version: TargetIdentityVersionV1, Scope: "org/target",
			RepositoryOwner: "org", RepositoryOwnerID: "1001",
			Repository: "org/target", RepositoryID: "3001",
		},
		Requested: &InputRequested{
			Permissions:  map[string]string{"contents": "read"},
			Repositories: []string{"target"}, RepositoryIDs: []string{"3001"},
			OrganizationWide: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	target, ok := raw["target_identity"].(map[string]any)
	if !ok || target["repository_owner_id"] != "1001" || target["repository_id"] != "3001" {
		t.Fatalf("target_identity fields missing: %v", raw["target_identity"])
	}
	requested, ok := raw["requested"].(map[string]any)
	if !ok || requested["organization_wide"] != false {
		t.Fatalf("organization_wide must be explicit false: %v", raw["requested"])
	}
}

func TestFromPolicy_GitHubRelationship(t *testing.T) {
	input := FromPolicy(&policy.TrustPolicy{
		Issuer: "https://token.actions.githubusercontent.com",
		GitHub: &policy.GitHubPolicy{
			Sources: []policy.GitHubRepository{
				{OwnerID: "1001", RepositoryID: "2001"},
				{OwnerID: "1001", RepositoryID: "2002"},
			},
			Target: policy.GitHubRepository{OwnerID: "1001", RepositoryID: "3001"},
		},
	})
	if input.GitHub == nil || len(input.GitHub.Sources) != 2 {
		t.Fatalf("GitHub relationship missing: %+v", input.GitHub)
	}
	if input.GitHub.Target.OwnerID != "1001" || input.GitHub.Target.RepositoryID != "3001" {
		t.Fatalf("GitHub target mismatch: %+v", input.GitHub.Target)
	}
}
