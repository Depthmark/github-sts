package bundle

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps a compiled OPA bundle as prepared eval queries for every package
// that exposes a decision document. Eval is safe for concurrent use; prepared
// queries handle their own internal synchronisation. The instance is immutable
// once built; reloads happen by atomically swapping the manager's engine.
type Engine struct {
	decisions  []preparedQuery
	exceptions []preparedQuery
	// keep a write lock around prepared in case future reload work
	// swaps it; Phase 1 never writes after construction.
	mu sync.RWMutex
}

type preparedQuery struct {
	Package  string
	Query    string
	Prepared rego.PreparedEvalQuery
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
	decisionQueries := make([]preparedQuery, 0, len(parsed))
	exceptionQueries := make([]preparedQuery, 0)
	for _, mod := range parsed {
		pkg := modulePackage(mod)
		if pkg == "" {
			continue
		}
		if hasRule(mod, "decision") {
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
	if len(decisionQueries) == 0 {
		// Keep the failure explicit: a configured bundle with no enforcement
		// package is a security misconfiguration.
		return nil, fmt.Errorf("bundle engine: no packages expose a decision document")
	}

	return &Engine{decisions: decisionQueries, exceptions: exceptionQueries}, nil
}

// Eval runs the prepared query against the given input and returns the
// composed decision. A missing or malformed decision document is
// treated as a default-deny — the broker should never allow on
// ambiguous Rego output.
func (e *Engine) Eval(ctx context.Context, input Input) (Decision, error) {
	e.mu.RLock()
	queries := append([]preparedQuery(nil), e.decisions...)
	e.mu.RUnlock()

	d := Decision{Allow: true}
	for _, q := range queries {
		pd, err := evalPackageDecision(ctx, q, input)
		if err != nil {
			return Decision{}, err
		}
		d.Packages = append(d.Packages, pd)
		if !pd.Allow {
			d.Allow = false
			d.Reasons = append(d.Reasons, qualifyReasons(pd)...)
		}
	}
	return d, nil
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
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		pd.Allow = false
		pd.Reasons = []string{"bundle: no decision document at " + q.Query}
		return pd, nil
	}

	raw, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		pd.Allow = false
		pd.Reasons = []string{"bundle: decision document has unexpected shape at " + q.Query}
		return pd, nil
	}

	if v, ok := raw["allow"].(bool); ok {
		pd.Allow = v
	}
	if reasons, ok := raw["reasons"].([]any); ok {
		pd.Reasons = make([]string, 0, len(reasons))
		for _, r := range reasons {
			if s, ok := r.(string); ok {
				pd.Reasons = append(pd.Reasons, s)
			}
		}
	}
	if v, ok := raw["rule_id"].(string); ok {
		pd.RuleID = safeLabel(v)
	}
	if v, ok := raw["rule_name"].(string); ok {
		pd.RuleName = v
	}
	if v, ok := raw["exception_id"].(string); ok {
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
