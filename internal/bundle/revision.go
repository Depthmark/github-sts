package bundle

import (
	"fmt"
	"strconv"
)

// PolicyArtifactVersion is the digest/revision tuple promoted by release and
// deployment automation. Digest is the OCI manifest digest, not a bundle-layer
// or tarball digest.
type PolicyArtifactVersion struct {
	Digest         string `json:"digest"`
	PolicyRevision string `json:"policy_revision"`
}

// PolicyPromotionMode selects whether an exact no-op tuple is accepted.
type PolicyPromotionMode string

const (
	// PolicyPromotionRelease requires a newly published revision.
	PolicyPromotionRelease PolicyPromotionMode = "release"
	// PolicyPromotionDeployment permits redeploying the exact current tuple.
	PolicyPromotionDeployment PolicyPromotionMode = "deployment"
)

// ParsePolicyRevision parses the canonical signed policy revision format used
// by bundle manifests and deployment configuration. A revision is a positive
// base-10 uint64 with no sign, whitespace, or leading zeroes.
func ParsePolicyRevision(revision string) (uint64, error) {
	if revision == "" {
		return 0, fmt.Errorf("policy revision is required")
	}
	if revision[0] == '0' {
		if len(revision) == 1 {
			return 0, fmt.Errorf("policy revision must be positive")
		}
		return 0, fmt.Errorf("policy revision must not contain leading zeroes")
	}
	for _, digit := range revision {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("policy revision must be a canonical base-10 uint64")
		}
	}
	parsed, err := strconv.ParseUint(revision, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("policy revision must be a canonical base-10 uint64: %w", err)
	}
	return parsed, nil
}

// ValidatePolicyPromotion enforces the stateless release/GitOps monotonicity
// contract. A higher revision must name a different digest. Reusing a revision
// for different bytes is always rejected; deployment checks alone may accept
// the exact current tuple as a no-op.
func ValidatePolicyPromotion(mode PolicyPromotionMode, current, candidate PolicyArtifactVersion) error {
	if mode != PolicyPromotionRelease && mode != PolicyPromotionDeployment {
		return fmt.Errorf("policy promotion mode must be %q or %q", PolicyPromotionRelease, PolicyPromotionDeployment)
	}
	currentRevision, err := ParsePolicyRevision(current.PolicyRevision)
	if err != nil {
		return fmt.Errorf("current policy revision: %w", err)
	}
	candidateRevision, err := ParsePolicyRevision(candidate.PolicyRevision)
	if err != nil {
		return fmt.Errorf("candidate policy revision: %w", err)
	}
	if err := validatePolicyDigest(current.Digest); err != nil {
		return fmt.Errorf("current policy digest: %w", err)
	}
	if err := validatePolicyDigest(candidate.Digest); err != nil {
		return fmt.Errorf("candidate policy digest: %w", err)
	}

	switch {
	case candidateRevision < currentRevision:
		return fmt.Errorf("policy revision rollback from %s to %s is not allowed", current.PolicyRevision, candidate.PolicyRevision)
	case candidateRevision == currentRevision && candidate.Digest != current.Digest:
		return fmt.Errorf("policy revision %s cannot be reused for a different digest", candidate.PolicyRevision)
	case candidateRevision == currentRevision && mode == PolicyPromotionRelease:
		return fmt.Errorf("release policy revision must increase beyond %s", current.PolicyRevision)
	case candidateRevision > currentRevision && candidate.Digest == current.Digest:
		return fmt.Errorf("policy digest %s cannot declare two revisions", candidate.Digest)
	default:
		return nil
	}
}

func validatePolicyDigest(digest string) error {
	const prefix = "sha256:"
	if len(digest) != len(prefix)+64 || digest[:len(prefix)] != prefix {
		return fmt.Errorf("must be sha256: followed by 64 lowercase hexadecimal characters")
	}
	for _, c := range digest[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("must be sha256: followed by 64 lowercase hexadecimal characters")
		}
	}
	return nil
}
