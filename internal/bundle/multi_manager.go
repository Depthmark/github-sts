package bundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/depthmark/github-sts/internal/metrics"
)

// LifecycleManager is implemented by live bundle managers that need server
// lifecycle hooks in addition to the request-time Manager interface.
type LifecycleManager interface {
	Manager
	Mandatory() bool
	Available() bool
	Start(ctx context.Context)
	Stop()
	Reload(ctx context.Context) (string, error)
	AgeSeconds() float64
	LastPullError() error
}

// MultiManager composes independently-owned enterprise bundles. Every bundle
// is evaluated on every request; deny wins across all bundles and packages.
type MultiManager struct {
	children    []LifecycleManager
	enforcement string
	mu          sync.RWMutex
}

func NewMultiManager(children []LifecycleManager, enforcement string) *MultiManager {
	if enforcement != EnforcementRequired {
		enforcement = EnforcementOptional
	}
	return &MultiManager{
		children: append([]LifecycleManager(nil), children...), enforcement: enforcement,
	}
}

func (m *MultiManager) Eval(ctx context.Context, input Input) (Decision, error) {
	m.mu.RLock()
	children := append([]LifecycleManager(nil), m.children...)
	m.mu.RUnlock()

	combined := Decision{Allow: true}
	mandatoryParticipated := false
	for _, child := range children {
		if !child.Enabled() {
			continue
		}
		d, err := child.Eval(ctx, input)
		if d.Applicable {
			combined.Applicable = true
			combined.SnapshotDigest = appendDigest(combined.SnapshotDigest, d.SnapshotDigest)
		}
		if d.Evaluated {
			combined.Evaluated = true
			combined.EvaluatedDigest = appendDigest(combined.EvaluatedDigest, d.EvaluatedDigest)
			if child.Mandatory() && err == nil {
				mandatoryParticipated = true
			}
			combined.Packages = append(combined.Packages, d.Packages...)
			combined.Exceptions = append(combined.Exceptions, d.Exceptions...)
			if !d.Allow {
				combined.Allow = false
				combined.Reasons = append(combined.Reasons, d.Reasons...)
			}
			for _, pd := range d.Packages {
				result := "allow"
				if !pd.Allow {
					result = "deny"
				}
				metrics.BundlePolicyDecisionsTotal.WithLabelValues(input.Request.App, pd.BundleName, pd.Digest, result).Inc()
				if pd.RuleID != "" && pd.RuleID != "unknown" {
					metrics.BundlePolicyRuleDecisionsTotal.WithLabelValues(pd.BundleName, pd.RuleID, result).Inc()
				}
				if pd.ExceptionID != "" && pd.ExceptionID != "unknown" {
					metrics.BundlePolicyExceptionHitsTotal.WithLabelValues(pd.BundleName, pd.Digest, pd.ExceptionID, pd.RuleID, "unknown", input.Request.App).Inc()
				}
			}
		}
		if err != nil {
			return combined, err
		}
	}
	if m.enforcement == EnforcementRequired && !mandatoryParticipated {
		return combined, ErrBundleUnavailable
	}
	return combined, nil
}

func appendDigest(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}
	return existing + "," + next
}

func (m *MultiManager) Digest() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	parts := make([]string, 0, len(m.children))
	for _, child := range m.children {
		for _, st := range child.BundleStatuses() {
			if st.Digest != "" {
				parts = append(parts, st.Name+"="+st.Digest)
			}
		}
	}
	return strings.Join(parts, ",")
}

func (m *MultiManager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.enforcement == EnforcementRequired {
		return true
	}
	for _, child := range m.children {
		if child.Enabled() {
			return true
		}
	}
	return false
}

// Available reports actual loaded policy availability without weakening
// Enabled's required-mode guarantee that the handler always calls Eval.
func (m *MultiManager) Available() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.enforcement == EnforcementRequired {
		for _, child := range m.children {
			if child.Mandatory() {
				return child.Enabled()
			}
		}
		return false
	}
	for _, child := range m.children {
		if child.Enabled() {
			return true
		}
	}
	return false
}

func (m *MultiManager) Enforcement() string { return m.enforcement }

func (m *MultiManager) Mandatory() bool { return m.enforcement == EnforcementRequired }

func (m *MultiManager) BundleFile(name string) ([]byte, error) {
	m.mu.RLock()
	children := append([]LifecycleManager(nil), m.children...)
	m.mu.RUnlock()
	for _, child := range children {
		b, err := child.BundleFile(name)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, ErrFileNotFound) && !errors.Is(err, ErrDisabled) {
			return nil, err
		}
	}
	return nil, ErrFileNotFound
}

func (m *MultiManager) BundleStatuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(m.children))
	for _, child := range m.children {
		out = append(out, child.BundleStatuses()...)
	}
	return out
}

func (m *MultiManager) AgeSeconds() float64 {
	statuses := m.BundleStatuses()
	var max float64
	for _, st := range statuses {
		if st.AgeSeconds > max {
			max = st.AgeSeconds
		}
	}
	return max
}

func (m *MultiManager) LastPullError() error {
	statuses := m.BundleStatuses()
	for _, st := range statuses {
		if st.LastPullError != "" {
			return fmt.Errorf("%s: %s", st.Name, st.LastPullError)
		}
	}
	return nil
}

func (m *MultiManager) Start(ctx context.Context) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, child := range m.children {
		child.Start(ctx)
	}
}

func (m *MultiManager) Stop() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, child := range m.children {
		child.Stop()
	}
}

func (m *MultiManager) Reload(ctx context.Context) (string, error) {
	m.mu.RLock()
	children := append([]LifecycleManager(nil), m.children...)
	m.mu.RUnlock()

	digests := make([]string, 0, len(children))
	var errs []string
	for _, child := range children {
		digest, err := child.Reload(ctx)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if digest != "" {
			digests = append(digests, digest)
		}
	}
	if len(errs) > 0 {
		return strings.Join(digests, ","), fmt.Errorf("bundle reload errors: %s", strings.Join(errs, "; "))
	}
	return strings.Join(digests, ","), nil
}
