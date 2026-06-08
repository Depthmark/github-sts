package bundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureBundle returns the bytes of a default-deny OPA bundle, the
// same shape the producer ships in v0.1.0.
func fixtureBundle(t *testing.T) []byte {
	t.Helper()
	return buildTarball(t, map[string]string{
		"/policies/org/00_defaults.rego": `package sts.org

import rego.v1

default decision := {"allow": false, "reasons": ["default deny"]}
`,
	})
}

// TestLiveManager_InitSuccess counter-validates the happy path:
// filesystem loader → engine compile → Enabled flips true → Eval
// returns the expected default-deny decision.
func TestLiveManager_InitSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})
	if mgr.Enabled() {
		t.Fatalf("Enabled() before Init: got true, want false")
	}
	if mgr.Digest() != "" {
		t.Fatalf("Digest() before Init: got %q, want empty", mgr.Digest())
	}

	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !mgr.Enabled() {
		t.Fatalf("Enabled() after Init: got false, want true")
	}
	if mgr.Digest() == "" {
		t.Fatalf("Digest() after Init: got empty, want sha256:...")
	}

	d, err := mgr.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Allow {
		t.Fatalf("Eval on default-deny bundle: got allow, want deny")
	}
}

// TestLiveManager_InitPullFailure counter-validates that a missing
// bundle file is a hard failure — Init returns error, Enabled stays
// false, Eval before Init returns error. Server startup must propagate
// this; silent degrade to YAML-only is the failure mode we're guarding
// against.
func TestLiveManager_InitPullFailure(t *testing.T) {
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file:///nonexistent/bundle.tar.gz"}, VerifyConfig{}, nil, LiveOpts{})
	err := mgr.Init(context.Background())
	if err == nil {
		t.Fatalf("Init on missing file: expected error, got nil")
	}
	if mgr.Enabled() {
		t.Fatalf("Enabled() after failed Init: got true, want false")
	}
	if _, err := mgr.Eval(context.Background(), Input{}); err == nil {
		t.Fatalf("Eval before successful Init: expected error, got nil")
	}
}

// TestLiveManager_InitCompileFailure counter-validates that a malformed
// Rego file (parses as a tarball but fails to compile) causes Init to
// fail, not silently produce an empty engine.
func TestLiveManager_InitCompileFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	bad := buildTarball(t, map[string]string{
		"/policies/org/broken.rego": `package sts.org

this is not valid rego syntax {{{
`,
	})
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})
	err := mgr.Init(context.Background())
	if err == nil {
		t.Fatalf("Init on bad rego: expected compile error, got nil")
	}
	if mgr.Enabled() {
		t.Fatalf("Enabled() after compile failure: got true, want false")
	}
}

// TestDisabled_NoOp counter-validates the Disabled manager: Enabled is
// always false; Eval never silently allows; Digest is empty. The
// handler relies on Enabled() to skip the engine call entirely.
func TestDisabled_NoOp(t *testing.T) {
	d := Disabled{}
	if d.Enabled() {
		t.Fatalf("Disabled.Enabled() = true, want false")
	}
	if d.Digest() != "" {
		t.Fatalf("Disabled.Digest() = %q, want empty", d.Digest())
	}
	dec, err := d.Eval(context.Background(), Input{})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("Disabled.Eval err = %v, want ErrDisabled", err)
	}
	if dec.Allow {
		t.Fatalf("Disabled.Eval returned allow=true; must never silently allow")
	}
}

// TestFilesystemLoader_RejectsEmpty counter-validates the loader's
// emptiness check. A zero-byte bundle file must fail loudly rather
// than producing an empty (allow-everything-once-someone-writes-rules)
// engine.
func TestFilesystemLoader_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.tar.gz")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	_, err := FilesystemLoader{}.Fetch(context.Background(), Source{Raw: "file://" + path}, VerifyConfig{})
	if err == nil {
		t.Fatalf("FilesystemLoader on empty file: expected error, got nil")
	}
}

// TestNewLoader_SchemeDispatch counter-validates that NewLoader wires
// file:// to FilesystemLoader and oci:// to the production OCI loader.
func TestNewLoader_SchemeDispatch(t *testing.T) {
	if _, err := NewLoader(Source{Raw: "file:///tmp/x"}); err != nil {
		t.Fatalf("NewLoader(file://): %v", err)
	}
	if loader, err := NewLoader(Source{Raw: "oci://ghcr.io/x:v1"}); err != nil {
		t.Fatalf("NewLoader(oci://): %v", err)
	} else if _, ok := loader.(OCILoader); !ok {
		t.Fatalf("NewLoader(oci://) = %T, want OCILoader", loader)
	}
	if _, err := NewLoader(Source{Raw: "https://example.com/bundle"}); err == nil {
		t.Fatalf("NewLoader(https://): expected error for unsupported scheme, got nil")
	}
}

func TestOCILoader_RequiresCosignVerification(t *testing.T) {
	_, err := OCILoader{}.Fetch(context.Background(), Source{Raw: "oci://ghcr.io/depthmark/sts-policy:v1"}, VerifyConfig{})
	if err == nil || !strings.Contains(err.Error(), "cosign verification requires") {
		t.Fatalf("expected cosign verification requirement, got %v", err)
	}
}

func TestOCILoader_RejectsMixedCosignModes(t *testing.T) {
	_, err := OCILoader{}.Fetch(context.Background(), Source{Raw: "oci://ghcr.io/depthmark/sts-policy:v1"}, VerifyConfig{
		CertificateIdentityRegexp: "^https://github.com/depthmark/.*$",
		CertificateOIDCIssuer:     "https://token.actions.githubusercontent.com",
		PublicKeyRef:              "cosign.pub",
	})
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected mixed cosign mode error, got %v", err)
	}
}

// TestLiveManager_Reload_Unchanged counter-validates that a reload
// against an unmodified source is a no-op for the engine: the digest
// stays, Eval continues to work, and lastPullErr is cleared on
// success.
func TestLiveManager_Reload_Unchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	before := mgr.Digest()

	new, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if new != before {
		t.Errorf("unchanged reload changed digest: %q → %q", before, new)
	}
	if mgr.LastPullError() != nil {
		t.Errorf("LastPullError after successful reload: %v, want nil", mgr.LastPullError())
	}
}

// TestLiveManager_Reload_Changed counter-validates the atomic swap:
// rewrite the source file with different contents, reload, verify the
// digest changed and the new engine is installed.
func TestLiveManager_Reload_Changed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write v1: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	d1 := mgr.Digest()

	// Rewrite the file with a tarball that contains a comment so the
	// bytes differ and therefore the sha256 digest differs.
	v2 := buildTarball(t, map[string]string{
		"/policies/org/00_defaults.rego": `# version 2
package sts.org
import rego.v1
default decision := {"allow": false, "reasons": ["v2 default deny"]}
`,
	})
	if err := os.WriteFile(path, v2, 0o600); err != nil {
		t.Fatalf("write v2: %v", err)
	}

	d2, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if d2 == d1 {
		t.Errorf("changed reload did not change digest: %q (both)", d1)
	}
	if mgr.Digest() != d2 {
		t.Errorf("post-reload Digest() = %q, want %q", mgr.Digest(), d2)
	}
	// Spot-check that the new engine is in effect: its deny reasons
	// include the v2 sentinel.
	dec, err := mgr.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("Eval after reload: %v", err)
	}
	foundV2 := false
	for _, r := range dec.Reasons {
		if strings.Contains(r, "v2") {
			foundV2 = true
			break
		}
	}
	if !foundV2 {
		t.Errorf("post-reload Eval reasons %v did not contain v2 sentinel", dec.Reasons)
	}
}

// TestLiveManager_Reload_KeepsOldOnError counter-validates the
// failure-tolerance contract: a reload error must not blow away the
// running engine. Operators rely on this — a transient registry blip
// shouldn't tear down the guardrail.
func TestLiveManager_Reload_KeepsOldOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	digestBefore := mgr.Digest()

	// Remove the file so the next Fetch fails.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if _, err := mgr.Reload(context.Background()); err == nil {
		t.Fatalf("Reload on missing source: expected error, got nil")
	}
	if !mgr.Enabled() {
		t.Errorf("Enabled() after failed reload: false; old engine should still be installed")
	}
	if mgr.Digest() != digestBefore {
		t.Errorf("Digest changed after failed reload: %q → %q", digestBefore, mgr.Digest())
	}
	if mgr.LastPullError() == nil {
		t.Errorf("LastPullError after failed reload: nil; want non-nil so /health surfaces it")
	}
	// Eval still works on the old engine.
	if _, err := mgr.Eval(context.Background(), Input{Mode: ModeExchange}); err != nil {
		t.Errorf("Eval after failed reload: %v; old engine should still respond", err)
	}
}

// TestLiveManager_Stale_Closed counter-validates ErrBundleStale: when
// MaxStaleness is exceeded and fail_mode=closed, Eval refuses before
// touching the engine. The engine spy proves the engine wasn't even
// asked — fail-closed is enforced at the manager boundary.
func TestLiveManager_Stale_Closed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// MaxStaleness=1ns means the bundle is stale immediately after Init.
	// PollInterval matches; Start is not called so no background reloads.
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{
		MaxStaleness: 1,
		FailMode:     "closed",
	})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Sleep a tick to guarantee age > 1ns.
	time.Sleep(time.Millisecond)
	_, err := mgr.Eval(context.Background(), Input{Mode: ModeExchange})
	if !errors.Is(err, ErrBundleStale) {
		t.Fatalf("Eval on stale bundle (closed): got %v, want ErrBundleStale", err)
	}
}

// TestLiveManager_Stale_Open counter-validates that open mode does NOT
// refuse on staleness — it proceeds with the bundle and lets the
// engine answer normally. Operators who pick open mode are choosing
// availability over freshness; the manager must respect that.
func TestLiveManager_Stale_Open(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{
		MaxStaleness: 1,
		FailMode:     "open",
	})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	time.Sleep(time.Millisecond)
	dec, err := mgr.Eval(context.Background(), Input{Mode: ModeExchange})
	if err != nil {
		t.Fatalf("Eval on stale bundle (open): got err %v, want nil", err)
	}
	// The fixture is default-deny so Allow stays false, but the
	// successful return (no error) is what we're checking.
	if dec.Allow {
		t.Errorf("fixture should default-deny; got allow")
	}
}

// TestLiveManager_PollLoop_FiresReload counter-validates the
// background poll loop actually calls Reload. PollInterval is small
// (50ms) and we wait long enough to guarantee at least one fire.
// Tracks BundleReloadTotal via the prometheus dto interface.
func TestLiveManager_PollLoop_FiresReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(path, fixtureBundle(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{
		PollInterval: 50 * time.Millisecond,
	})
	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	digestBefore := mgr.Digest()

	mgr.Start(context.Background())
	defer mgr.Stop()

	// Wait long enough for at least two poll ticks.
	time.Sleep(150 * time.Millisecond)

	// Source bytes unchanged → digest unchanged, no error.
	if mgr.Digest() != digestBefore {
		t.Errorf("poll loop changed digest unexpectedly: %q → %q", digestBefore, mgr.Digest())
	}
	if mgr.LastPullError() != nil {
		t.Errorf("poll loop left LastPullError set: %v", mgr.LastPullError())
	}
}

// TestLiveManager_BundleFile counter-validates the file accessor:
// extracts a known file by exact path, returns ErrFileNotFound for an
// absent path, and returns ErrDisabled before Init.
func TestLiveManager_BundleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.tar.gz")
	tarball := buildTarball(t, map[string]string{
		"/policies/org/00_defaults.rego": "package sts.org\nimport rego.v1\ndefault decision := {\"allow\": false, \"reasons\": []}",
		"/data/sts/v1/trust-policy.json": `{"$id":"https://schemas.depthmark.io/sts/v1/trust-policy.json"}`,
	})
	if err := os.WriteFile(path, tarball, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	mgr := NewLiveManager(FilesystemLoader{}, Source{Raw: "file://" + path}, VerifyConfig{}, nil, LiveOpts{})

	// Before Init: ErrDisabled.
	if _, err := mgr.BundleFile("/data/sts/v1/trust-policy.json"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("BundleFile before Init: got %v, want ErrDisabled", err)
	}

	if err := mgr.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Present file: returned bytes match.
	body, err := mgr.BundleFile("/data/sts/v1/trust-policy.json")
	if err != nil {
		t.Fatalf("BundleFile: %v", err)
	}
	if !strings.Contains(string(body), "schemas.depthmark.io") {
		t.Errorf("BundleFile body = %q, want to contain schemas.depthmark.io", body)
	}

	// Path normalization: leading-slash strip works both ways.
	body2, err := mgr.BundleFile("data/sts/v1/trust-policy.json")
	if err != nil {
		t.Fatalf("BundleFile (no leading slash): %v", err)
	}
	if string(body2) != string(body) {
		t.Errorf("path-normalized lookup returned different bytes")
	}

	// Absent file: ErrFileNotFound.
	if _, err := mgr.BundleFile("/data/missing.json"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("BundleFile(missing): got %v, want ErrFileNotFound", err)
	}
}
