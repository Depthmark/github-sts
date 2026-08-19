package bundle

import (
	"strings"
	"testing"
)

func TestValidatePolicyPromotion(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name      string
		mode      PolicyPromotionMode
		current   PolicyArtifactVersion
		candidate PolicyArtifactVersion
		wantErr   string
	}{
		{
			name:      "release advances",
			mode:      PolicyPromotionRelease,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "42"},
		},
		{
			name:      "deployment advances",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "42"},
		},
		{
			name:      "deployment exact no-op",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
		},
		{
			name:      "release exact no-op",
			mode:      PolicyPromotionRelease,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			wantErr:   "must increase",
		},
		{
			name:      "rollback",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "40"},
			wantErr:   "rollback",
		},
		{
			name:      "same revision different bytes",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "41"},
			wantErr:   "cannot be reused",
		},
		{
			name:      "same bytes different revision",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestA, PolicyRevision: "42"},
			wantErr:   "cannot declare two revisions",
		},
		{
			name:      "noncanonical candidate revision",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "042"},
			wantErr:   "candidate policy revision",
		},
		{
			name:      "noncanonical candidate digest",
			mode:      PolicyPromotionDeployment,
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: "sha256:" + strings.Repeat("A", 64), PolicyRevision: "42"},
			wantErr:   "candidate policy digest",
		},
		{
			name:      "unknown mode",
			mode:      "runtime",
			current:   PolicyArtifactVersion{Digest: digestA, PolicyRevision: "41"},
			candidate: PolicyArtifactVersion{Digest: digestB, PolicyRevision: "42"},
			wantErr:   "mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicyPromotion(tt.mode, tt.current, tt.candidate)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePolicyPromotion: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
