package bundle

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps a compiled OPA bundle as prepared eval queries for every package
// that exposes a decision document. Eval is safe for concurrent use; prepared
// queries handle their own internal synchronisation. The instance is immutable
// once built; reloads happen by atomically swapping the manager's engine.
type Engine struct {
	decisions          []preparedQuery
	exceptions         []preparedQuery
	crossOrgExceptions []admittedCrossOrgException
	metadata           Metadata
	// keep a write lock around prepared in case future reload work
	// swaps it; Phase 1 never writes after construction.
	mu sync.RWMutex
}

const (
	mandatoryPackage    = "sts.enterprise.v1"
	mandatoryEntrypoint = "data." + mandatoryPackage + ".decision"
	mandatoryMetadata   = "data." + mandatoryPackage + ".metadata"

	controlImmutableIdentity  = "immutable_identity"
	controlPermissionBoundary = "permission_boundary"
)

// Metadata is the admitted contract declaration for a mandatory baseline.
type Metadata struct {
	ContractVersion string
	PolicyRevision  string
	Controls        []string
	admission       admissionContext
}

type admissionContext struct {
	App         string
	Identity    string
	Source      InputGitHubRepository
	Target      InputGitHubRepository
	Permissions map[string]string
}

type preparedQuery struct {
	Package  string
	Query    string
	Prepared rego.PreparedEvalQuery
}

type admittedCrossOrgException struct {
	input     InputCrossOrgException
	expiresAt time.Time
}

// NewEngine builds an Engine from a raw OPA bundle tarball (the
// `bundle.tar.gz` produced by `opa build`). The signature has already
// been verified by the time we get here; this function is concerned
// only with compilation.
//
// Returns an error if the tarball is malformed, the Rego doesn't
// compile, or the prepared-query construction fails. Any of these
// failures at startup should cause the broker to exit non-zero — see
// Manager.Init.
func NewEngine(ctx context.Context, tarball []byte) (*Engine, error) {
	return newEngine(ctx, tarball, false)
}

// NewMandatoryEngine builds an engine that exposes only the fixed v1
// enterprise entrypoint and passes metadata and negative admission probes.
func NewMandatoryEngine(ctx context.Context, tarball []byte) (*Engine, error) {
	return newEngine(ctx, tarball, true)
}

func newEngine(ctx context.Context, tarball []byte, mandatory bool) (*Engine, error) {
	if len(tarball) == 0 {
		return nil, fmt.Errorf("bundle engine: empty tarball")
	}

	loader := opabundle.NewTarballLoaderWithBaseURL(bytes.NewReader(tarball), "")
	reader := opabundle.NewCustomReader(loader).WithSkipBundleVerification(true)
	b, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("bundle engine: reading tarball: %w", err)
	}
	parsed := b.ParsedModules("sts-org")
	for _, mod := range parsed {
		pkg := modulePackage(mod)
		if pkg == "sts" || pkg == "sts.enterprise_config" || strings.HasPrefix(pkg, "sts.enterprise_config.") {
			return nil, fmt.Errorf("bundle engine: Rego modules may not define reserved enterprise data namespace %q", pkg)
		}
	}
	if err := validateEnterprisePolicyData(b.Data, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("bundle engine: enterprise data admission: %w", err)
	}
	crossOrgExceptions := admittedEnterpriseExceptions(b.Data)

	decisionQueries := make([]preparedQuery, 0, len(parsed))
	exceptionQueries := make([]preparedQuery, 0)
	mandatoryDecisionFound := false
	mandatoryMetadataFound := false
	for _, mod := range parsed {
		pkg := modulePackage(mod)
		if pkg == "" {
			continue
		}
		if hasRule(mod, "decision") {
			if mandatory && pkg != mandatoryPackage {
				return nil, fmt.Errorf("bundle engine: mandatory bundle exposes unsupported decision entrypoint %q", "data."+pkg+".decision")
			}
			if mandatory {
				mandatoryDecisionFound = true
			} else {
				query := "data." + pkg + ".decision"
				pq, err := rego.New(
					rego.Query(query),
					rego.ParsedBundle("sts-org", &b),
				).PrepareForEval(ctx)
				if err != nil {
					return nil, fmt.Errorf("bundle engine: preparing query %q: %w", query, err)
				}
				decisionQueries = append(decisionQueries, preparedQuery{Package: pkg, Query: query, Prepared: pq})
			}
		}
		if mandatory && pkg == mandatoryPackage && hasRule(mod, "metadata") {
			mandatoryMetadataFound = true
		}
		if hasRule(mod, "inventory") {
			query := "data." + pkg + ".inventory"
			pq, err := rego.New(
				rego.Query(query),
				rego.ParsedBundle("sts-org", &b),
			).PrepareForEval(ctx)
			if err != nil {
				return nil, fmt.Errorf("bundle engine: preparing query %q: %w", query, err)
			}
			exceptionQueries = append(exceptionQueries, preparedQuery{Package: pkg, Query: query, Prepared: pq})
		}
	}
	if mandatory {
		if !mandatoryDecisionFound {
			return nil, fmt.Errorf("bundle engine: mandatory entrypoint %q is required", mandatoryEntrypoint)
		}
		if !mandatoryMetadataFound {
			return nil, fmt.Errorf("bundle engine: mandatory metadata %q is required", mandatoryMetadata)
		}
		pq, err := prepareBundleQuery(ctx, &b, mandatoryPackage, mandatoryEntrypoint)
		if err != nil {
			return nil, err
		}
		decisionQueries = append(decisionQueries, pq)
	}
	if len(decisionQueries) == 0 {
		// Keep the failure explicit: a configured bundle with no enforcement
		// package is a security misconfiguration.
		return nil, fmt.Errorf("bundle engine: no packages expose a decision document")
	}

	eng := &Engine{decisions: decisionQueries, exceptions: exceptionQueries, crossOrgExceptions: crossOrgExceptions}
	if mandatory {
		metadataQuery, err := prepareBundleQuery(ctx, &b, mandatoryPackage, mandatoryMetadata)
		if err != nil {
			return nil, err
		}
		metadata, err := admitMandatoryMetadata(ctx, metadataQuery)
		if err != nil {
			return nil, fmt.Errorf("bundle engine: mandatory metadata admission: %w", err)
		}
		eng.metadata = metadata
		if err := eng.runMandatoryAdmissionProbes(ctx, b.Data); err != nil {
			return nil, fmt.Errorf("bundle engine: mandatory negative admission: %w", err)
		}
	}
	return eng, nil
}

func prepareBundleQuery(ctx context.Context, b *opabundle.Bundle, pkg, query string) (preparedQuery, error) {
	pq, err := rego.New(
		rego.Query(query),
		rego.ParsedBundle("sts-org", b),
	).PrepareForEval(ctx)
	if err != nil {
		return preparedQuery{}, fmt.Errorf("bundle engine: preparing query %q: %w", query, err)
	}
	return preparedQuery{Package: pkg, Query: query, Prepared: pq}, nil
}

// Metadata returns the mandatory contract metadata admitted at construction.
// Optional engines return the zero value.
func (e *Engine) Metadata() Metadata {
	if e == nil {
		return Metadata{}
	}
	return e.metadata
}

func admitMandatoryMetadata(ctx context.Context, q preparedQuery) (Metadata, error) {
	rs, err := q.Prepared.Eval(ctx)
	if err != nil {
		return Metadata{}, fmt.Errorf("evaluating %q: %w", q.Query, err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Metadata{}, fmt.Errorf("%q must produce exactly one document", q.Query)
	}
	raw, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Metadata{}, fmt.Errorf("%q must be an object", q.Query)
	}
	contractVersion, ok := raw["contract_version"].(string)
	if !ok || contractVersion != "v1" {
		return Metadata{}, fmt.Errorf("contract_version must be %q", "v1")
	}
	policyRevision, ok := raw["policy_revision"].(string)
	if !ok || strings.TrimSpace(policyRevision) == "" || policyRevision != strings.TrimSpace(policyRevision) {
		return Metadata{}, fmt.Errorf("policy_revision must be a non-empty trimmed string")
	}
	rawControls, ok := raw["controls"].([]any)
	if !ok {
		return Metadata{}, fmt.Errorf("controls must be an array")
	}
	controls := make([]string, 0, len(rawControls))
	declared := make(map[string]bool, len(rawControls))
	for i, rawControl := range rawControls {
		control, ok := rawControl.(string)
		if !ok || strings.TrimSpace(control) == "" || control != strings.TrimSpace(control) {
			return Metadata{}, fmt.Errorf("controls[%d] must be a non-empty trimmed string", i)
		}
		if declared[control] {
			return Metadata{}, fmt.Errorf("controls contains duplicate %q", control)
		}
		declared[control] = true
		controls = append(controls, control)
	}
	for _, required := range []string{controlImmutableIdentity, controlPermissionBoundary} {
		if !declared[required] {
			return Metadata{}, fmt.Errorf("controls must declare %q", required)
		}
	}
	admission, err := parseAdmissionContext(raw["admission"])
	if err != nil {
		return Metadata{}, fmt.Errorf("admission: %w", err)
	}
	sort.Strings(controls)
	return Metadata{
		ContractVersion: contractVersion,
		PolicyRevision:  policyRevision,
		Controls:        controls,
		admission:       admission,
	}, nil
}

func parseAdmissionContext(raw any) (admissionContext, error) {
	object, ok := raw.(map[string]any)
	if !ok {
		return admissionContext{}, fmt.Errorf("must be an object")
	}
	allowed := map[string]bool{"app": true, "identity": true, "source": true, "target": true, "permissions": true}
	for field := range object {
		if !allowed[field] {
			return admissionContext{}, fmt.Errorf("unknown field %q", field)
		}
	}
	app, err := requiredTrimmedString(object, "app")
	if err != nil {
		return admissionContext{}, err
	}
	identity, err := requiredTrimmedString(object, "identity")
	if err != nil {
		return admissionContext{}, err
	}
	source, err := admissionRepository(object, "source")
	if err != nil {
		return admissionContext{}, err
	}
	target, err := admissionRepository(object, "target")
	if err != nil {
		return admissionContext{}, err
	}
	rawPermissions, ok := object["permissions"].(map[string]any)
	if !ok || len(rawPermissions) == 0 {
		return admissionContext{}, fmt.Errorf("permissions must be a non-empty object")
	}
	permissions := make(map[string]string, len(rawPermissions))
	for permission, rawLevel := range rawPermissions {
		level, ok := rawLevel.(string)
		if !ok || !policy.ValidPermissions[permission] || !policy.ValidPermissionValues[level] {
			return admissionContext{}, fmt.Errorf("permissions contains invalid permission %q or level", permission)
		}
		permissions[permission] = level
	}
	return admissionContext{
		App: app, Identity: identity, Source: source, Target: target, Permissions: permissions,
	}, nil
}

func requiredTrimmedString(object map[string]any, field string) (string, error) {
	value, ok := object[field].(string)
	if !ok || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%s must be a non-empty trimmed string", field)
	}
	return value, nil
}

func admissionRepository(object map[string]any, field string) (InputGitHubRepository, error) {
	repository, ok := object[field].(map[string]any)
	if !ok {
		return InputGitHubRepository{}, fmt.Errorf("%s must be an object", field)
	}
	if err := validateExceptionRepository(repository); err != nil {
		return InputGitHubRepository{}, fmt.Errorf("%s: %w", field, err)
	}
	return InputGitHubRepository{
		OwnerID: repository["owner_id"].(string), RepositoryID: repository["repository_id"].(string),
	}, nil
}

func (e *Engine) runMandatoryAdmissionProbes(ctx context.Context, _ map[string]any) error {
	if len(e.decisions) != 1 || e.decisions[0].Query != mandatoryEntrypoint {
		return fmt.Errorf("internal entrypoint mismatch")
	}

	base := mandatoryProbeInput(e.metadata.admission)
	if err := e.requireProbeDecision(ctx, base, true); err != nil {
		return fmt.Errorf("declared known-good context: %w", err)
	}
	malformed := mandatoryProbeInput(e.metadata.admission)
	malformed.Mode = "invalid"
	missingIdentity := mandatoryProbeInput(e.metadata.admission)
	missingIdentity.SourceIdentity = nil
	unknownSource := mandatoryProbeInput(e.metadata.admission)
	unknownSource.SourceIdentity.RepositoryOwnerID = "99999999999999999999999999999999999998"
	unknownSource.SourceIdentity.RepositoryID = "99999999999999999999999999999999999999"
	unknownSource.YAMLPolicy.GitHub.Sources = []InputGitHubRepository{{
		OwnerID:      "99999999999999999999999999999999999998",
		RepositoryID: "99999999999999999999999999999999999999",
	}}
	unknownPermission := mandatoryProbeInput(e.metadata.admission)
	unknownPermission.Requested.Permissions = map[string]string{"github_sts_unknown_permission": "write"}

	probes := []struct {
		name  string
		input Input
	}{
		{name: "malformed input", input: malformed},
		{name: "missing identity", input: missingIdentity},
		{name: "unknown source", input: unknownSource},
		{name: "unknown permission", input: unknownPermission},
	}
	for _, probe := range probes {
		if err := e.requireProbeDecision(ctx, probe.input, false); err != nil {
			return fmt.Errorf("%s probe: %w", probe.name, err)
		}
	}
	return nil
}

func mandatoryProbeInput(admission admissionContext) Input {
	const scope = "github-sts-admission/target"
	permissions := make(map[string]string, len(admission.Permissions))
	for permission, level := range admission.Permissions {
		permissions[permission] = level
	}
	return Input{
		Mode: ModeExchange,
		Request: InputRequest{
			Scope: scope, App: admission.App, Identity: admission.Identity,
		},
		YAMLPolicy: InputYAMLPolicy{
			Issuer:      "https://token.actions.githubusercontent.com",
			Permissions: permissions,
			GitHub: &InputGitHubPolicy{
				Sources: []InputGitHubRepository{admission.Source},
				Target:  admission.Target,
			},
		},
		Claims: map[string]any{"iss": "https://token.actions.githubusercontent.com"},
		SourceIdentity: &InputSourceIdentity{
			Version: SourceIdentityVersionV1, Issuer: "https://token.actions.githubusercontent.com",
			RepositoryOwner: "github-sts-admission", RepositoryOwnerID: admission.Source.OwnerID,
			Repository: "github-sts-admission/source", RepositoryID: admission.Source.RepositoryID,
			ImmutableSubject: true, ImmutableSubjectRequired: true,
		},
		TargetIdentity: &InputTargetIdentity{
			Version: TargetIdentityVersionV1, Scope: scope,
			RepositoryOwner: "github-sts-admission", RepositoryOwnerID: admission.Target.OwnerID,
			Repository: scope, RepositoryID: admission.Target.RepositoryID,
		},
		Requested: &InputRequested{
			Permissions: permissions, Repositories: []string{scope},
			RepositoryIDs: []string{admission.Target.RepositoryID},
		},
	}
}

func (e *Engine) requireProbeDecision(ctx context.Context, input Input, wantAllow bool) error {
	input.Authorization = &InputAuthorization{CrossOrgExceptions: e.activeCrossOrgExceptions(time.Now().UTC())}
	q := e.decisions[0]
	decision, err := evalPackageDecision(ctx, q, input)
	if err != nil {
		return err
	}
	if decision.Allow != wantAllow {
		if wantAllow {
			return fmt.Errorf("entrypoint denied the declared known-good admission context")
		}
		return fmt.Errorf("entrypoint allowed a broker-generated negative probe")
	}
	return nil
}

const maxExceptionLifetime = 30 * 24 * time.Hour

func validateEnterprisePolicyData(data map[string]any, now time.Time) error {
	sts, ok := objectField(data, "sts")
	if !ok {
		return nil
	}
	enterprise, ok := objectField(sts, "enterprise_config")
	if !ok {
		return nil
	}
	config, ok := objectField(enterprise, "v1")
	if !ok {
		return fmt.Errorf("sts.enterprise_config.v1 must be an object")
	}
	if version, ok := config["contract_version"].(string); !ok || version != "v1" {
		return fmt.Errorf("contract_version must be %q", "v1")
	}

	rawExceptions, ok := config["cross_org_exceptions"]
	if !ok {
		return fmt.Errorf("cross_org_exceptions is required")
	}
	exceptions, ok := rawExceptions.([]any)
	if !ok {
		return fmt.Errorf("cross_org_exceptions must be an array")
	}
	seen := make(map[string]struct{}, len(exceptions))
	seenContexts := make(map[string]struct{}, len(exceptions))
	for i, raw := range exceptions {
		exception, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("cross_org_exceptions[%d] must be an object", i)
		}
		id, err := validateCrossOrgException(exception, now)
		if err != nil {
			return fmt.Errorf("cross_org_exceptions[%d]: %w", i, err)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("cross_org_exceptions[%d]: duplicate exception_id %q", i, id)
		}
		seen[id] = struct{}{}
		contextKey := crossOrgExceptionContextKey(exception)
		if _, ok := seenContexts[contextKey]; ok {
			return fmt.Errorf("cross_org_exceptions[%d]: duplicate source/target/app/identity context", i)
		}
		seenContexts[contextKey] = struct{}{}
	}

	rawGrants, ok := config["org_wide_grants"]
	if !ok {
		return fmt.Errorf("org_wide_grants is required")
	}
	grants, ok := rawGrants.([]any)
	if !ok {
		return fmt.Errorf("org_wide_grants must be an array")
	}
	if len(grants) != 0 {
		return fmt.Errorf("org_wide_grants must remain empty while organization-level scopes are disabled")
	}
	return nil
}

func crossOrgExceptionContextKey(exception map[string]any) string {
	source := exception["source"].(map[string]any)
	target := exception["target"].(map[string]any)
	return fmt.Sprintf("%s/%s>%s/%s:%s:%s",
		source["owner_id"], source["repository_id"],
		target["owner_id"], target["repository_id"],
		exception["app"], exception["identity"],
	)
}

func admittedEnterpriseExceptions(data map[string]any) []admittedCrossOrgException {
	sts, ok := objectField(data, "sts")
	if !ok {
		return nil
	}
	enterprise, ok := objectField(sts, "enterprise_config")
	if !ok {
		return nil
	}
	config, ok := objectField(enterprise, "v1")
	if !ok {
		return nil
	}
	exceptions, _ := config["cross_org_exceptions"].([]any)
	out := make([]admittedCrossOrgException, 0, len(exceptions))
	for _, raw := range exceptions {
		exception, _ := raw.(map[string]any)
		source, _ := exception["source"].(map[string]any)
		target, _ := exception["target"].(map[string]any)
		rawCeiling, _ := exception["permission_ceiling"].(map[string]any)
		ceiling := make(map[string]string, len(rawCeiling))
		for permission, level := range rawCeiling {
			ceiling[permission], _ = level.(string)
		}
		expiresAt, _ := time.Parse(time.RFC3339, exception["expires_at"].(string))
		out = append(out, admittedCrossOrgException{
			input: InputCrossOrgException{
				ExceptionID: exception["exception_id"].(string),
				RuleID:      exception["rule_id"].(string),
				Source: InputGitHubRepository{
					OwnerID: source["owner_id"].(string), RepositoryID: source["repository_id"].(string),
				},
				Target: InputGitHubRepository{
					OwnerID: target["owner_id"].(string), RepositoryID: target["repository_id"].(string),
				},
				App: exception["app"].(string), Identity: exception["identity"].(string),
				PermissionCeiling: ceiling,
				Owner:             exception["owner"].(string), ApprovedBy: exception["approved_by"].(string),
				Reason: exception["reason"].(string), CreatedAt: exception["created_at"].(string),
				ExpiresAt: exception["expires_at"].(string),
			},
			expiresAt: expiresAt,
		})
	}
	return out
}

func validateCrossOrgException(exception map[string]any, now time.Time) (string, error) {
	allowedFields := map[string]bool{
		"exception_id": true, "rule_id": true, "source": true, "target": true,
		"app": true, "identity": true, "permission_ceiling": true,
		"owner": true, "approved_by": true, "reason": true,
		"created_at": true, "expires_at": true,
	}
	for field := range exception {
		if !allowedFields[field] {
			return "", fmt.Errorf("unknown field %q", field)
		}
	}

	requiredStrings := []string{"exception_id", "rule_id", "app", "identity", "owner", "approved_by", "reason", "created_at", "expires_at"}
	values := make(map[string]string, len(requiredStrings))
	for _, field := range requiredStrings {
		value, ok := exception[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%s must be a non-empty string", field)
		}
		if value != strings.TrimSpace(value) {
			return "", fmt.Errorf("%s must not contain leading or trailing whitespace", field)
		}
		values[field] = value
	}
	if values["rule_id"] != "sts.relationship.cross_org" {
		return "", fmt.Errorf("rule_id must be %q", "sts.relationship.cross_org")
	}
	if values["owner"] == values["approved_by"] {
		return "", fmt.Errorf("owner and approved_by must be distinct")
	}

	repositories := make(map[string]map[string]any, 2)
	for _, field := range []string{"source", "target"} {
		repository, ok := exception[field].(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s must be an object", field)
		}
		if err := validateExceptionRepository(repository); err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		repositories[field] = repository
	}
	if repositories["source"]["owner_id"] == repositories["target"]["owner_id"] {
		return "", fmt.Errorf("source and target owner IDs must differ for a cross-organization exception")
	}
	ceiling, ok := exception["permission_ceiling"].(map[string]any)
	if !ok || len(ceiling) == 0 {
		return "", fmt.Errorf("permission_ceiling must be a non-empty object")
	}
	for permission, rawLevel := range ceiling {
		level, ok := rawLevel.(string)
		if !ok || !policy.ValidPermissions[permission] || !policy.ValidPermissionValues[level] {
			return "", fmt.Errorf("permission_ceiling contains invalid permission %q or level", permission)
		}
	}

	createdAt, err := time.Parse(time.RFC3339, values["created_at"])
	if err != nil {
		return "", fmt.Errorf("created_at must be RFC3339: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, values["expires_at"])
	if err != nil {
		return "", fmt.Errorf("expires_at must be RFC3339: %w", err)
	}
	if createdAt.After(now) {
		return "", fmt.Errorf("created_at must not be in the future")
	}
	if !expiresAt.After(createdAt) {
		return "", fmt.Errorf("expires_at must be after created_at")
	}
	if expiresAt.Sub(createdAt) > maxExceptionLifetime {
		return "", fmt.Errorf("exception lifetime exceeds %s", maxExceptionLifetime)
	}
	if !expiresAt.After(now) {
		return "", fmt.Errorf("exception is expired")
	}
	return values["exception_id"], nil
}

func validateExceptionRepository(repository map[string]any) error {
	if len(repository) != 2 {
		return fmt.Errorf("must contain only owner_id and repository_id")
	}
	for _, field := range []string{"owner_id", "repository_id"} {
		id, ok := repository[field].(string)
		if !ok || !validDecimalID(id) {
			return fmt.Errorf("%s must be a non-zero decimal string", field)
		}
	}
	return nil
}

func validDecimalID(id string) bool {
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

func objectField(parent map[string]any, field string) (map[string]any, bool) {
	value, ok := parent[field].(map[string]any)
	return value, ok
}

// Eval runs the prepared query against the given input and returns the
// composed decision. Missing or malformed decision documents are evaluation
// faults so callers can distinguish policy denial from operational failure.
func (e *Engine) Eval(ctx context.Context, input Input) (Decision, error) {
	input.Authorization = &InputAuthorization{CrossOrgExceptions: e.activeCrossOrgExceptions(time.Now().UTC())}
	e.mu.RLock()
	queries := append([]preparedQuery(nil), e.decisions...)
	e.mu.RUnlock()

	d := Decision{Allow: true}
	for _, q := range queries {
		pd, err := evalPackageDecision(ctx, q, input)
		if err != nil {
			return d, err
		}
		d.Packages = append(d.Packages, pd)
		if !pd.Allow {
			d.Allow = false
			d.Reasons = append(d.Reasons, qualifyReasons(pd)...)
		}
	}
	return d, nil
}

func (e *Engine) activeCrossOrgExceptions(now time.Time) []InputCrossOrgException {
	active := make([]InputCrossOrgException, 0, len(e.crossOrgExceptions))
	for _, exception := range e.crossOrgExceptions {
		if now.Before(exception.expiresAt) {
			active = append(active, exception.input)
		}
	}
	return active
}

// Exceptions evaluates optional inventory documents used for exception
// expiration metrics. It does not affect authorization decisions.
func (e *Engine) Exceptions(ctx context.Context) ([]Exception, error) {
	e.mu.RLock()
	queries := append([]preparedQuery(nil), e.exceptions...)
	e.mu.RUnlock()

	out := make([]Exception, 0)
	for _, q := range queries {
		rs, err := q.Prepared.Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("bundle engine: eval exception inventory %q: %w", q.Query, err)
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			continue
		}
		out = append(out, parseExceptions(rs[0].Expressions[0].Value)...)
	}
	return out, nil
}

func evalPackageDecision(ctx context.Context, q preparedQuery, input Input) (PackageDecision, error) {
	rs, err := q.Prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return PackageDecision{}, fmt.Errorf("bundle engine: eval %q: %w", q.Query, err)
	}
	pd := PackageDecision{Package: q.Package, Query: q.Query}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return PackageDecision{}, fmt.Errorf("bundle engine: decision %q must produce exactly one document", q.Query)
	}

	raw, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return PackageDecision{}, fmt.Errorf("bundle engine: decision %q must be an object", q.Query)
	}

	allow, ok := raw["allow"].(bool)
	if !ok {
		return PackageDecision{}, fmt.Errorf("bundle engine: decision %q allow must be a boolean", q.Query)
	}
	pd.Allow = allow
	if rawReasons, exists := raw["reasons"]; exists {
		reasons, ok := rawReasons.([]any)
		if !ok {
			return PackageDecision{}, fmt.Errorf("bundle engine: decision %q reasons must be an array of strings", q.Query)
		}
		pd.Reasons = make([]string, 0, len(reasons))
		for i, reason := range reasons {
			s, ok := reason.(string)
			if !ok {
				return PackageDecision{}, fmt.Errorf("bundle engine: decision %q reasons[%d] must be a string", q.Query, i)
			}
			pd.Reasons = append(pd.Reasons, s)
		}
	}
	if rawRuleID, exists := raw["rule_id"]; exists {
		v, ok := rawRuleID.(string)
		if !ok {
			return PackageDecision{}, fmt.Errorf("bundle engine: decision %q rule_id must be a string", q.Query)
		}
		pd.RuleID = safeLabel(v)
	}
	if rawRuleName, exists := raw["rule_name"]; exists {
		v, ok := rawRuleName.(string)
		if !ok {
			return PackageDecision{}, fmt.Errorf("bundle engine: decision %q rule_name must be a string", q.Query)
		}
		pd.RuleName = v
	}
	if rawExceptionID, exists := raw["exception_id"]; exists {
		v, ok := rawExceptionID.(string)
		if !ok {
			return PackageDecision{}, fmt.Errorf("bundle engine: decision %q exception_id must be a string", q.Query)
		}
		pd.ExceptionID = safeLabel(v)
	}
	return pd, nil
}

func modulePackage(mod *ast.Module) string {
	if mod == nil || mod.Package == nil {
		return ""
	}
	p := mod.Package.Path.String()
	p = strings.TrimPrefix(p, "data.")
	return p
}

func hasRule(mod *ast.Module, name string) bool {
	for _, rule := range mod.Rules {
		if rule.Head != nil && string(rule.Head.Name) == name {
			return true
		}
	}
	return false
}

func qualifyReasons(pd PackageDecision) []string {
	reasons := make([]string, 0, len(pd.Reasons))
	reasons = append(reasons, pd.Reasons...)
	return reasons
}

func parseExceptions(v any) []Exception {
	items := flattenInventory(v)
	out := make([]Exception, 0, len(items))
	for _, raw := range items {
		ex := Exception{
			ExceptionID: stringField(raw, "exception_id"),
			RuleID:      stringField(raw, "rule_id"),
			Owner:       stringField(raw, "owner"),
			Reason:      stringField(raw, "reason"),
			ApprovedBy:  stringField(raw, "approved_by"),
			CreatedAt:   stringField(raw, "created_at"),
			ExpiresAt:   stringField(raw, "expires_at"),
		}
		ex.ExceptionID = safeLabel(ex.ExceptionID)
		ex.RuleID = safeLabel(ex.RuleID)
		ex.Owner = safeLabel(ex.Owner)
		ex.Status = "invalid"
		if t, err := time.Parse(time.RFC3339, ex.ExpiresAt); err == nil {
			ex.ExpirationUnixSeconds = float64(t.Unix())
			ex.SecondsUntilExpiration = time.Until(t).Seconds()
			if ex.SecondsUntilExpiration < 0 {
				ex.Status = "expired"
			} else if ex.SecondsUntilExpiration < (7 * 24 * time.Hour).Seconds() {
				ex.Status = "expiring"
			} else {
				ex.Status = "active"
			}
		}
		out = append(out, ex)
	}
	return out
}

func flattenInventory(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		// OPA sets can decode as object-like values depending on bundle shape.
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func safeLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	repl := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", "\n", "_", "\t", "_")
	return repl.Replace(s)
}
