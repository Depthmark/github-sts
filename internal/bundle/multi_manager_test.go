package bundle

import (
	"context"
	"errors"
	"testing"
)

type fakeLifecycleManager struct {
	enabled   bool
	mandatory bool
	decision  Decision
	err       error
	status    Status
}

func (m *fakeLifecycleManager) Eval(context.Context, Input) (Decision, error) {
	return m.decision, m.err
}
func (m *fakeLifecycleManager) Digest() string                    { return m.status.Digest }
func (m *fakeLifecycleManager) Enabled() bool                     { return m.enabled }
func (m *fakeLifecycleManager) Available() bool                   { return m.enabled }
func (m *fakeLifecycleManager) Enforcement() string               { return EnforcementOptional }
func (m *fakeLifecycleManager) Mandatory() bool                   { return m.mandatory }
func (m *fakeLifecycleManager) BundleFile(string) ([]byte, error) { return nil, ErrFileNotFound }
func (m *fakeLifecycleManager) BundleStatuses() []Status          { return []Status{m.status} }
func (m *fakeLifecycleManager) Start(context.Context)             {}
func (m *fakeLifecycleManager) Stop()                             {}
func (m *fakeLifecycleManager) Reload(context.Context) (string, error) {
	return m.status.Digest, nil
}
func (m *fakeLifecycleManager) AgeSeconds() float64  { return m.status.AgeSeconds }
func (m *fakeLifecycleManager) LastPullError() error { return nil }

func TestMultiManager_RequiredBaselineMustParticipate(t *testing.T) {
	tests := []struct {
		name  string
		child *fakeLifecycleManager
	}{
		{
			name:  "disabled",
			child: &fakeLifecycleManager{mandatory: true},
		},
		{
			name: "not evaluated",
			child: &fakeLifecycleManager{
				enabled: true, mandatory: true,
				decision: Decision{Applicable: false, Evaluated: false},
			},
		},
	}

	for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mgr := NewMultiManager([]LifecycleManager{tt.child}, EnforcementRequired)
			if !mgr.Enabled() {
				t.Fatal("required manager must remain enabled so the handler cannot skip evaluation")
			}
			_, err := mgr.Eval(context.Background(), Input{})
				if !errors.Is(err, ErrBundleUnavailable) {
					t.Fatalf("Eval error = %v, want ErrBundleUnavailable", err)
				}
			if got := mgr.Available(); got != tt.child.enabled {
				t.Fatalf("Available() = %v, want loaded mandatory state %v", got, tt.child.enabled)
			}
		})
	}
}

func TestMultiManager_RequiredBaselineParticipationAllowsComposition(t *testing.T) {
	mandatory := &fakeLifecycleManager{
		enabled: true, mandatory: true,
		decision: Decision{
			Applicable: true, Evaluated: true, EvaluatedDigest: "baseline=sha256:one", Allow: true,
			Packages: []PackageDecision{{BundleName: "baseline", Allow: true}},
		},
	}
	additiveExcluded := &fakeLifecycleManager{
		enabled:  true,
		decision: Decision{Applicable: false, Evaluated: false},
	}
	mgr := NewMultiManager([]LifecycleManager{mandatory, additiveExcluded}, EnforcementRequired)

	d, err := mgr.Eval(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !d.Allow || !d.Applicable || !d.Evaluated || d.EvaluatedDigest != "baseline=sha256:one" || len(d.Packages) != 1 {
		t.Fatalf("combined decision = %+v", d)
	}
}

func TestMultiManager_EvaluationErrorPreservesPriorParticipants(t *testing.T) {
	first := &fakeLifecycleManager{
		enabled: true,
		decision: Decision{
			Applicable: true, Evaluated: true, EvaluatedDigest: "first=sha256:one", Allow: true,
			Packages: []PackageDecision{{BundleName: "first", Digest: "sha256:one", Allow: true}},
		},
	}
	second := &fakeLifecycleManager{enabled: true, err: errors.New("evaluation failed")}
	mgr := NewMultiManager([]LifecycleManager{first, second}, EnforcementOptional)

	d, err := mgr.Eval(context.Background(), Input{})
	if err == nil {
		t.Fatal("Eval error = nil, want failure")
	}
	if !d.Evaluated || d.EvaluatedDigest != "first=sha256:one" || len(d.Packages) != 1 {
		t.Fatalf("partial decision lost prior participant: %+v", d)
	}
}

func TestMultiManager_OptionalExcludedBundleIsNotEvaluatedAllow(t *testing.T) {
	excluded := &fakeLifecycleManager{
		enabled:  true,
		decision: Decision{Applicable: false, Evaluated: false},
	}
	mgr := NewMultiManager([]LifecycleManager{excluded}, EnforcementOptional)

	d, err := mgr.Eval(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !d.Allow {
		t.Fatal("optional composition with no applicable bundle should permit YAML-only authorization")
	}
	if d.Applicable || d.Evaluated {
		t.Fatalf("excluded bundle was represented as participation: %+v", d)
	}
}
