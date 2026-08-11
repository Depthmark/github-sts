// Package bundle consumes signed OPA bundles that provide enterprise Rego
// guardrails. It pulls bundles from file or OCI sources, verifies OCI bundles
// with cosign keyless signatures, discovers every package exposing a decision
// document, and gates token exchanges on the composed YAML+Rego outcome.
// Deny wins across all configured bundles and packages.
package bundle

import (
	"context"
	"errors"
	"fmt"

	"github.com/depthmark/github-sts/internal/policy"
)

// Mode identifies which lifecycle hook is calling the bundle. Exchange mode is
// used for token minting decisions; validate mode is reserved for future Rego
// validation hooks. The current trust-policy validation endpoint is YAML-only.
type Mode string

const (
	ModeExchange Mode = "exchange"
	ModeValidate Mode = "validate" // reserved; not emitted in Phase 1
)

// Input is the top-level shape passed to data.sts.org.decision. The
// fields in this struct, their JSON tags, and their semantics are the
// contract with github-sts-policy. Adding new optional fields is
// non-breaking; renaming or removing fields requires a coordinated
// version bump in both repos.
type Input struct {
	Mode           Mode                 `json:"mode"`
	Request        InputRequest         `json:"request"`
	YAMLPolicy     InputYAMLPolicy      `json:"yaml_policy"`
	Claims         map[string]any       `json:"claims,omitempty"`          // present iff mode == "exchange"
	SourceIdentity *InputSourceIdentity `json:"source_identity,omitempty"` // present for GitHub.com exchanges
	TargetIdentity *InputTargetIdentity `json:"target_identity,omitempty"` // present for resolved repository targets
	Authorization  *InputAuthorization  `json:"authorization,omitempty"`   // populated by Engine from admitted bundle data
	Requested      *InputRequested      `json:"requested,omitempty"`       // present iff mode == "exchange"
}

// SourceIdentityVersionV1 identifies the initial canonical source identity
// contract supplied to Rego.
const SourceIdentityVersionV1 = "v1"

// TargetIdentityVersionV1 identifies the initial canonical target identity
// contract supplied to Rego.
const TargetIdentityVersionV1 = "v1"

// InputSourceIdentity is the canonical GitHub.com repository identity supplied
// to enterprise policy. Version makes future additions explicit without
// changing the meaning of existing fields.
type InputSourceIdentity struct {
	Version                  string `json:"version"`
	Issuer                   string `json:"issuer"`
	Subject                  string `json:"subject"`
	RepositoryOwner          string `json:"repository_owner"`
	RepositoryOwnerID        string `json:"repository_owner_id"`
	Repository               string `json:"repository"`
	RepositoryID             string `json:"repository_id"`
	ImmutableSubject         bool   `json:"immutable_subject"`
	ImmutableSubjectRequired bool   `json:"immutable_subject_required"`
}

// InputTargetIdentity is the broker-resolved immutable repository target.
type InputTargetIdentity struct {
	Version           string `json:"version"`
	Scope             string `json:"scope"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
}

// InputAuthorization contains active centrally managed authorization records.
// Engine replaces this field at evaluation time; callers cannot supply or
// extend these records.
type InputAuthorization struct {
	CrossOrgExceptions []InputCrossOrgException `json:"cross_org_exceptions"`
}

type InputCrossOrgException struct {
	ExceptionID       string                `json:"exception_id"`
	RuleID            string                `json:"rule_id"`
	Source            InputGitHubRepository `json:"source"`
	Target            InputGitHubRepository `json:"target"`
	App               string                `json:"app"`
	Identity          string                `json:"identity"`
	PermissionCeiling map[string]string     `json:"permission_ceiling"`
	Owner             string                `json:"owner"`
	ApprovedBy        string                `json:"approved_by"`
	Reason            string                `json:"reason"`
	CreatedAt         string                `json:"created_at"`
	ExpiresAt         string                `json:"expires_at"`
}

// InputRequest is the (scope, app, identity) triple from the exchange
// request. Identical in shape across modes.
type InputRequest struct {
	Scope    string `json:"scope"`
	App      string `json:"app"`
	Identity string `json:"identity"`
}

// InputYAMLPolicy is the loaded TrustPolicy serialised for Rego eval.
// Mirrors policy.TrustPolicy without the unexported regex caches.
type InputYAMLPolicy struct {
	Issuer         string             `json:"issuer"`
	Subject        string             `json:"subject,omitempty"`
	SubjectPattern string             `json:"subject_pattern,omitempty"`
	ClaimPattern   map[string]string  `json:"claim_pattern,omitempty"`
	Audience       string             `json:"audience,omitempty"`
	Repositories   []string           `json:"repositories,omitempty"`
	Permissions    map[string]string  `json:"permissions"`
	GitHub         *InputGitHubPolicy `json:"github,omitempty"`
	Centralized    bool               `json:"centralized"`
}

// InputGitHubPolicy is the exact immutable relationship declared by the
// target-owned trust policy.
type InputGitHubPolicy struct {
	Sources []InputGitHubRepository `json:"sources"`
	Target  InputGitHubRepository   `json:"target"`
}

type InputGitHubRepository struct {
	OwnerID      string `json:"owner_id"`
	RepositoryID string `json:"repository_id"`
}

// InputRequested captures what the broker is about to ask GitHub for.
// Distinct from YAMLPolicy.Permissions because future phases may allow
// callers to request a subset of the policy-declared permissions.
type InputRequested struct {
	Permissions      map[string]string `json:"permissions"`
	Repositories     []string          `json:"repositories,omitempty"`
	RepositoryIDs    []string          `json:"repository_ids,omitempty"`
	OrganizationWide bool              `json:"organization_wide"`
}

// Decision is the result of one or more package evaluations. Each participating
// package returns a decision document shaped as {"allow": bool, "reasons":
// [string]} with optional rule and exception metadata.
type Decision struct {
	Applicable      bool              `json:"applicable"`
	Evaluated       bool              `json:"evaluated"`
	SnapshotDigest  string            `json:"snapshot_digest,omitempty"`
	EvaluatedDigest string            `json:"evaluated_digest,omitempty"`
	Allow           bool              `json:"allow"`
	Reasons         []string          `json:"reasons,omitempty"`
	Packages        []PackageDecision `json:"packages,omitempty"`
	Exceptions      []Exception       `json:"exceptions,omitempty"`
}

// PackageDecision captures one package-level decision document. BundleName
// and Digest are filled by managers; Engine fills Package, Query, Allow,
// Reasons, and optional rule/exception metadata returned by Rego.
type PackageDecision struct {
	BundleName  string   `json:"bundle_name,omitempty"`
	Digest      string   `json:"digest,omitempty"`
	Package     string   `json:"package"`
	Query       string   `json:"query"`
	Allow       bool     `json:"allow"`
	Reasons     []string `json:"reasons,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	RuleName    string   `json:"rule_name,omitempty"`
	ExceptionID string   `json:"exception_id,omitempty"`
}

// Exception is inventory metadata exported by Rego bundles so operators can
// alert on expiring or stale exception entries. Enforcement still happens in
// Rego; the broker uses this inventory for metrics and audit visibility.
type Exception struct {
	BundleName             string  `json:"bundle_name,omitempty"`
	Digest                 string  `json:"digest,omitempty"`
	ExceptionID            string  `json:"exception_id"`
	RuleID                 string  `json:"rule_id,omitempty"`
	Owner                  string  `json:"owner"`
	Reason                 string  `json:"reason"`
	ApprovedBy             string  `json:"approved_by"`
	CreatedAt              string  `json:"created_at"`
	ExpiresAt              string  `json:"expires_at"`
	Status                 string  `json:"status"`
	ExpirationUnixSeconds  float64 `json:"expiration_unix_seconds,omitempty"`
	SecondsUntilExpiration float64 `json:"seconds_until_expiration,omitempty"`
}

// Manager is the dependency injected into the exchange handler. It
// hides the loader/verifier/engine wiring behind a narrow interface
// that's easy to fake in tests.
//
// Eval must be safe for concurrent use. Digest returns the OCI digest
// of the currently loaded bundle ("sha256:..."), used as the audit
// fingerprint that proves which bundle gated which decision. Enabled
// reports whether the bundle integration is active; when false, the
// handler skips the call entirely.
//
// BundleFile extracts a named file from the loaded bundle tarball.
// Used by the schema handler to republish static documents the bundle
// ships (e.g., the trust-policy JSON Schema at
// /data/sts/v1/trust-policy.json). Direct tar extraction — no Rego
// involved — so this works for any opaque bytes the producer places
// under /data/. Returns ErrFileNotFound when the path isn't in the
// bundle and ErrDisabled when the manager isn't loaded.
type Manager interface {
	Eval(ctx context.Context, input Input) (Decision, error)
	Digest() string
	Enabled() bool
	Enforcement() string
	BundleFile(name string) ([]byte, error)
	BundleStatuses() []Status
}

const (
	EnforcementRequired = "required"
	EnforcementOptional = "optional"
)

// Status is a health-friendly snapshot of one configured bundle.
type Status struct {
	Name           string  `json:"name"`
	Enabled        bool    `json:"enabled"`
	Mandatory      bool    `json:"mandatory"`
	Digest         string  `json:"digest,omitempty"`
	PolicyRevision string  `json:"policy_revision,omitempty"`
	AgeSeconds     float64 `json:"age_seconds"`
	LastPullError  string  `json:"last_pull_error,omitempty"`
}

// ErrDisabled is returned by Eval / BundleFile on a disabled manager.
// Callers should gate Eval on Enabled() and never see this in practice;
// it exists so a misuse fails loudly rather than silently allowing.
var ErrDisabled = errors.New("bundle manager: disabled (called when Enabled() == false)")

// ErrFileNotFound is returned by BundleFile when the named file is not
// present in the loaded bundle tarball. The schema handler maps this
// to a 503 with code "schema_missing" — distinct from "bundle_disabled"
// so operators can tell "fork forgot to ship the schema" from "operator
// hasn't enabled the bundle integration."
var ErrFileNotFound = errors.New("bundle manager: file not found in bundle")

// ErrBundleStale is returned by Eval when the bundle hasn't been
// successfully refreshed within MaxStaleness AND fail_mode == "closed".
// The handler maps this to a 503 bundle_stale and refuses to mint.
// In open mode, Eval proceeds with the stale bundle and increments
// BundleStaleEvalsTotal{mode="open"} instead.
var ErrBundleStale = errors.New("bundle manager: stale (last successful pull exceeded max_staleness; fail_mode=closed)")

// ErrBundleUnavailable means required enforcement could not prove that the
// mandatory baseline participated in the request.
var ErrBundleUnavailable = errors.New("bundle manager: mandatory baseline unavailable")

// Disabled is a no-op manager used when bundle.enabled == false.
// Enabled() returns false; Eval and BundleFile return ErrDisabled
// (defensive — the handler should never call them when disabled).
// Digest returns the empty string.
type Disabled struct{}

func (Disabled) Eval(context.Context, Input) (Decision, error) {
	return Decision{}, ErrDisabled
}

func (Disabled) Digest() string                    { return "" }
func (Disabled) Enabled() bool                     { return false }
func (Disabled) Enforcement() string               { return EnforcementOptional }
func (Disabled) BundleFile(string) ([]byte, error) { return nil, ErrDisabled }
func (Disabled) BundleStatuses() []Status          { return nil }

// FromPolicy builds an InputYAMLPolicy from a parsed TrustPolicy.
// Keeping the conversion here (rather than in internal/policy) means
// the policy package doesn't need to know about Rego or the bundle
// input contract.
func FromPolicy(p *policy.TrustPolicy) InputYAMLPolicy {
	if p == nil {
		return InputYAMLPolicy{}
	}
	input := InputYAMLPolicy{
		Issuer:         p.Issuer,
		Subject:        p.Subject,
		SubjectPattern: p.SubjectPattern,
		ClaimPattern:   p.ClaimPattern,
		Audience:       p.Audience,
		Repositories:   p.Repositories,
		Permissions:    p.Permissions,
		Centralized:    p.Centralized(),
	}
	if p.GitHub != nil {
		input.GitHub = &InputGitHubPolicy{
			Sources: make([]InputGitHubRepository, len(p.GitHub.Sources)),
			Target: InputGitHubRepository{
				OwnerID:      string(p.GitHub.Target.OwnerID),
				RepositoryID: string(p.GitHub.Target.RepositoryID),
			},
		}
		for i, source := range p.GitHub.Sources {
			input.GitHub.Sources[i] = InputGitHubRepository{
				OwnerID:      string(source.OwnerID),
				RepositoryID: string(source.RepositoryID),
			}
		}
	}
	return input
}

// DenyError wraps a Decision whose Allow is false, formatted as a
// concise message for log lines. The handler converts this to a 403
// org_policy_denied response and surfaces the reasons in the audit
// event, not the HTTP body (callers see only the coarse code).
type DenyError struct {
	Decision Decision
}

func (e *DenyError) Error() string {
	if len(e.Decision.Reasons) == 0 {
		return "bundle: org policy denied (no reasons)"
	}
	return fmt.Sprintf("bundle: org policy denied: %v", e.Decision.Reasons)
}
