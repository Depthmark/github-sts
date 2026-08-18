package oidc

import (
	"fmt"
	"strings"
)

// GitHubActionsIssuer is the issuer used by GitHub.com Actions. GitHub
// Enterprise Server uses deployment-specific issuers and does not currently
// support GitHub.com's immutable subject format.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// GitHubIdentity is the canonical repository identity carried by a verified
// GitHub.com Actions token.
type GitHubIdentity struct {
	Issuer            string
	Subject           string
	RepositoryOwner   string
	RepositoryOwnerID string
	Repository        string
	RepositoryName    string
	RepositoryID      string
	ImmutableSubject  bool
}

// GitHubIdentityErrorReason is a bounded failure category safe for metrics.
type GitHubIdentityErrorReason string

const (
	GitHubIdentityMissingClaim               GitHubIdentityErrorReason = "github_identity_missing_claim"
	GitHubIdentityInvalidClaimType           GitHubIdentityErrorReason = "github_identity_invalid_claim_type"
	GitHubIdentityInvalidClaim               GitHubIdentityErrorReason = "github_identity_invalid_claim"
	GitHubIdentityInvalidID                  GitHubIdentityErrorReason = "github_identity_invalid_id"
	GitHubIdentitySubjectRepositoryMissing   GitHubIdentityErrorReason = "github_identity_subject_repository_missing"
	GitHubIdentitySubjectRepositoryDuplicate GitHubIdentityErrorReason = "github_identity_subject_repository_duplicate"
	GitHubIdentitySubjectRepositoryInvalid   GitHubIdentityErrorReason = "github_identity_subject_repository_invalid"
	GitHubIdentityImmutableSubjectRequired   GitHubIdentityErrorReason = "github_identity_immutable_subject_required"
	GitHubIdentityClaimMismatch              GitHubIdentityErrorReason = "github_identity_claim_mismatch"
)

// GitHubIdentityError describes a GitHub identity contract failure without
// exposing claim values in the public HTTP response.
type GitHubIdentityError struct {
	Reason GitHubIdentityErrorReason
	Claim  string
}

func (e *GitHubIdentityError) Error() string {
	if e.Claim == "" {
		return fmt.Sprintf("GitHub identity validation failed: %s", e.Reason)
	}
	return fmt.Sprintf("GitHub identity validation failed: %s (%s)", e.Reason, e.Claim)
}

// ParseGitHubIdentity validates and canonicalizes repository identity claims
// for GitHub.com Actions. It returns nil, nil for every other issuer.
//
// The immutable-subject switch controls only whether IDs must appear in sub.
// Separate signed repository_owner_id and repository_id claims are always
// required for GitHub.com tokens.
func ParseGitHubIdentity(claims Claims, requireImmutableSubject bool) (*GitHubIdentity, error) {
	issuer, _ := claims["iss"].(string)
	if issuer != GitHubActionsIssuer {
		return nil, nil
	}

	subject, err := requiredGitHubStringClaim(claims, "sub")
	if err != nil {
		return nil, err
	}
	repository, err := requiredGitHubStringClaim(claims, "repository")
	if err != nil {
		return nil, err
	}
	repositoryOwner, err := requiredGitHubStringClaim(claims, "repository_owner")
	if err != nil {
		return nil, err
	}
	repositoryID, err := requiredGitHubStringClaim(claims, "repository_id")
	if err != nil {
		return nil, err
	}
	repositoryOwnerID, err := requiredGitHubStringClaim(claims, "repository_owner_id")
	if err != nil {
		return nil, err
	}
	if !validGitHubID(repositoryID) {
		return nil, githubIdentityError(GitHubIdentityInvalidID, "repository_id")
	}
	if !validGitHubID(repositoryOwnerID) {
		return nil, githubIdentityError(GitHubIdentityInvalidID, "repository_owner_id")
	}

	claimOwner, claimRepository, ok := splitGitHubRepository(repository)
	if !ok {
		return nil, githubIdentityError(GitHubIdentityInvalidClaim, "repository")
	}
	if !strings.EqualFold(claimOwner, repositoryOwner) {
		return nil, githubIdentityError(GitHubIdentityClaimMismatch, "repository_owner")
	}

	segments := githubSubjectRepositorySegments(subject)
	if len(segments) == 0 {
		return nil, githubIdentityError(GitHubIdentitySubjectRepositoryMissing, "sub")
	}

	candidates := make([]bool, 0, 1)
	sawValid := false
	sawMatchingLegacy := false
	for _, segment := range segments {
		subjectOwner, subjectOwnerID, subjectRepositoryName, subjectRepositoryID, immutable, valid := splitGitHubSubjectRepository(segment)
		if !valid {
			continue
		}
		sawValid = true
		if !strings.EqualFold(subjectOwner, claimOwner) || !strings.EqualFold(subjectRepositoryName, claimRepository) {
			continue
		}
		if immutable {
			if subjectOwnerID != repositoryOwnerID || subjectRepositoryID != repositoryID {
				continue
			}
		} else if requireImmutableSubject {
			sawMatchingLegacy = true
			continue
		}
		candidates = append(candidates, immutable)
	}

	if len(candidates) > 1 {
		return nil, githubIdentityError(GitHubIdentitySubjectRepositoryDuplicate, "sub")
	}
	if len(candidates) == 0 && sawMatchingLegacy {
		return nil, githubIdentityError(GitHubIdentityImmutableSubjectRequired, "sub")
	}
	if len(candidates) == 0 && sawValid {
		return nil, githubIdentityError(GitHubIdentityClaimMismatch, "sub")
	}
	if len(candidates) == 0 {
		return nil, githubIdentityError(GitHubIdentitySubjectRepositoryInvalid, "sub")
	}
	return &GitHubIdentity{
		Issuer:            issuer,
		Subject:           subject,
		RepositoryOwner:   repositoryOwner,
		RepositoryOwnerID: repositoryOwnerID,
		Repository:        repository,
		RepositoryName:    claimRepository,
		RepositoryID:      repositoryID,
		ImmutableSubject:  candidates[0],
	}, nil
}

func githubSubjectRepositorySegments(subject string) []string {
	segments := make([]string, 0, 1)
	if strings.HasPrefix(subject, "repo:") {
		segments = append(segments, githubSubjectValue(subject, len("repo:")))
	}
	for offset := 0; offset < len(subject); {
		idx := strings.Index(subject[offset:], ":repo:")
		if idx < 0 {
			break
		}
		idx += offset
		segments = append(segments, githubSubjectValue(subject, idx+len(":repo:")))
		// Advance one byte so adjacent ":repo:repo:..." occurrences are both
		// considered. Values equal to "repo" are valid in custom templates.
		offset = idx + 1
	}
	return segments
}

func githubSubjectValue(subject string, start int) string {
	if end := strings.IndexByte(subject[start:], ':'); end >= 0 {
		return subject[start : start+end]
	}
	return subject[start:]
}

func requiredGitHubStringClaim(claims Claims, name string) (string, error) {
	v, ok := claims[name]
	if !ok {
		return "", githubIdentityError(GitHubIdentityMissingClaim, name)
	}
	s, ok := v.(string)
	if !ok {
		return "", githubIdentityError(GitHubIdentityInvalidClaimType, name)
	}
	if s == "" {
		return "", githubIdentityError(GitHubIdentityInvalidClaim, name)
	}
	return s, nil
}

func splitGitHubRepository(repository string) (string, string, bool) {
	if strings.Count(repository, "/") != 1 {
		return "", "", false
	}
	owner, repo, _ := strings.Cut(repository, "/")
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

func splitGitHubSubjectRepository(segment string) (owner, ownerID, repo, repoID string, immutable, ok bool) {
	ownerPart, repoPart, valid := splitGitHubRepository(segment)
	if !valid {
		return "", "", "", "", false, false
	}

	ownerAt := strings.Count(ownerPart, "@")
	repoAt := strings.Count(repoPart, "@")
	if ownerAt == 0 && repoAt == 0 {
		return ownerPart, "", repoPart, "", false, true
	}
	if ownerAt != 1 || repoAt != 1 {
		return "", "", "", "", false, false
	}

	owner, ownerID, _ = strings.Cut(ownerPart, "@")
	repo, repoID, _ = strings.Cut(repoPart, "@")
	if owner == "" || repo == "" || !validGitHubID(ownerID) || !validGitHubID(repoID) {
		return "", "", "", "", false, false
	}
	return owner, ownerID, repo, repoID, true, true
}

func validGitHubID(id string) bool {
	nonZero := false
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
		if c != '0' {
			nonZero = true
		}
	}
	return id != "" && nonZero
}

func githubIdentityError(reason GitHubIdentityErrorReason, claim string) error {
	return &GitHubIdentityError{Reason: reason, Claim: claim}
}
