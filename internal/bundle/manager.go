package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
)

// LiveManager is the production Manager implementation. It composes a
// Loader (pull + verify) and an Engine (compile + eval) and exposes
// the narrow Manager interface to the rest of the broker.
//
// Lifecycle:
//   - NewLiveManager — constructs but does not pull.
//   - Init — synchronous pull + verify + compile; called at startup; a
//     failure here aborts server creation.
//   - Start — launches the background poll loop; called after Init.
//   - Reload — explicit pull + swap; used by SIGHUP and by the poll
//     loop. Safe to call concurrently with Eval; in-flight evals see
//     the old engine, new evals see the new engine.
//   - Stop — drains the poll loop; called on shutdown.
//
// Staleness:
//   - bundle_age_seconds is "time since the last *successful* pull."
//   - When MaxStaleness > 0 and the age exceeds it, Eval's behaviour
//     depends on FailMode: closed → ErrBundleStale (handler returns
//     503 bundle_stale); open → eval proceeds, BundleStaleEvalsTotal
//     increments, slogger emits a warn-level line.
type LiveManager struct {
	name    string
	loader  Loader
	source  Source
	verify  VerifyConfig
	slogger *slog.Logger

	pollInterval           time.Duration
	maxStaleness           time.Duration
	failMode               string
	apps                   map[string]struct{}
	mandatory              bool
	expectedPolicyRevision string

	reloadMu       sync.Mutex
	mu             sync.RWMutex
	engine         *Engine
	digest         string
	loadedAt       time.Time
	tarball        []byte // retained for BundleFile; bundles are small (~1KB-MB)
	exceptions     []Exception
	policyRevision string
	lastPullErr    error // most recent reload failure, surfaced via /health

	// Lifecycle state for the background poller. ctx is the parent the
	// poller listens on; cancel stops the poller without affecting the
	// context the request handlers use.
	pollerCtx    context.Context
	pollerCancel context.CancelFunc
	pollerWG     sync.WaitGroup
	startedOnce  sync.Once
}

// LiveOpts bundles the Phase-2 reload tunables so the constructor stays
// readable. Zero values are accepted as "feature off":
//   - PollInterval == 0 → no background polling (Reload still works on
//     demand via SIGHUP).
//   - MaxStaleness == 0 → staleness check disabled; Eval ignores age.
//   - FailMode == "" → defaults to "closed" when MaxStaleness > 0.
//   - ExpectedPolicyRevision == "" → no revision pin (optional legacy only).
type LiveOpts struct {
	Name                   string
	Apps                   []string
	Mandatory              bool
	ExpectedPolicyRevision string
	PollInterval           time.Duration
	MaxStaleness           time.Duration
	FailMode               string
}

// NewLiveManager constructs a manager but does not pull anything. Call
// Init before serving traffic. A failed Init must cause the broker to
// exit non-zero — silently degrading to YAML-only would mask a
// security configuration error.
func NewLiveManager(loader Loader, source Source, verify VerifyConfig, slogger *slog.Logger, opts LiveOpts) *LiveManager {
	if slogger == nil {
		slogger = slog.Default()
	}
	failMode := opts.FailMode
	if opts.MaxStaleness > 0 && failMode == "" {
		failMode = "closed"
	}
	name := opts.Name
	if name == "" {
		name = "default"
	}
	apps := make(map[string]struct{}, len(opts.Apps))
	for _, app := range opts.Apps {
		apps[app] = struct{}{}
	}
	return &LiveManager{
		name:                   name,
		loader:                 loader,
		source:                 source,
		verify:                 verify,
		slogger:                slogger,
		pollInterval:           opts.PollInterval,
		maxStaleness:           opts.MaxStaleness,
		failMode:               failMode,
		apps:                   apps,
		mandatory:              opts.Mandatory,
		expectedPolicyRevision: opts.ExpectedPolicyRevision,
	}
}

// Init pulls the bundle, verifies its signature, compiles a prepared
// query, and atomically installs it. Increments the appropriate
// metrics so an operator can tell pull failures from verify failures
// from compile failures from a Prometheus dashboard.
func (m *LiveManager) Init(ctx context.Context) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if err := m.fetchAndInstall(ctx, "init"); err != nil {
		return err
	}
	m.mu.RLock()
	digest := m.digest
	policyRevision := m.policyRevision
	loadedAt := m.loadedAt
	m.mu.RUnlock()
	m.slogger.Info("bundle init: ready",
		"digest", digest,
		"policy_revision", policyRevision,
		"loaded_at", loadedAt.Format(time.RFC3339),
	)
	return nil
}

// Reload performs an on-demand pull + verify + compile + atomic swap.
// Used by SIGHUP and by the background poll loop. Returns the new
// digest (or empty + an error) so callers can log the outcome.
//
// On reload failure, the existing engine stays installed. lastPullErr
// is set so /health surfaces the failure to operators; metrics are
// stamped (BundleReloadTotal{result="failure"}, BundlePullTotal); the
// bundle continues to serve traffic until age > MaxStaleness.
//
// On reload success with an unchanged digest, no swap happens but
// loadedAt advances (the bundle is "fresh" again from staleness's
// perspective) and BundleReloadTotal{result="unchanged"} increments.
func (m *LiveManager) Reload(ctx context.Context) (string, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.RLock()
	prev := m.digest
	m.mu.RUnlock()

	if err := m.fetchAndInstall(ctx, "reload"); err != nil {
		m.mu.Lock()
		m.lastPullErr = err
		m.mu.Unlock()
		metrics.BundleReloadTotal.WithLabelValues(m.name, "failure").Inc()
		metrics.BundlePolicyRevisionChangesTotal.WithLabelValues(m.name, "failure").Inc()
		return "", err
	}

	m.mu.Lock()
	m.lastPullErr = nil
	new := m.digest
	m.mu.Unlock()

	if new == prev {
		metrics.BundleReloadTotal.WithLabelValues(m.name, "unchanged").Inc()
		metrics.BundlePolicyRevisionChangesTotal.WithLabelValues(m.name, "unchanged").Inc()
		m.slogger.Debug("bundle reload: unchanged digest", "digest", new)
	} else {
		metrics.BundleReloadTotal.WithLabelValues(m.name, "success").Inc()
		metrics.BundlePolicyRevisionChangesTotal.WithLabelValues(m.name, "changed").Inc()
		m.slogger.Info("bundle reload: swapped",
			"old_digest", prev,
			"new_digest", new,
		)
	}
	return new, nil
}

// fetchAndInstall is the shared body of Init and Reload: pull, verify,
// compile, atomic swap. Caller is responsible for any digest-comparison
// logic and for setting/clearing lastPullErr around the call.
func (m *LiveManager) fetchAndInstall(ctx context.Context, kind string) error {
	if m.expectedPolicyRevision != "" {
		if _, err := ParsePolicyRevision(m.expectedPolicyRevision); err != nil {
			return fmt.Errorf("bundle %s: expected policy revision %q is invalid: %w", kind, m.expectedPolicyRevision, err)
		}
	}
	scheme := m.source.Scheme()
	if scheme == "" {
		scheme = "file"
	}
	verificationMode := m.signatureVerificationMode()
	m.slogger.Info("bundle "+kind+": loading rego bundle",
		"source", m.source.Raw,
		"source_scheme", scheme,
		"signature_verification", verificationMode,
	)
	fetch, err := m.loader.Fetch(ctx, m.source, m.verify)
	if err != nil {
		var verificationErr *verificationError
		if errors.As(err, &verificationErr) {
			metrics.BundleVerifyTotal.WithLabelValues(m.name, "failure").Inc()
		} else {
			metrics.BundlePullTotal.WithLabelValues(m.name, "failure").Inc()
		}
		return fmt.Errorf("bundle %s: pull/verify: %w", kind, err)
	}
	metrics.BundlePullTotal.WithLabelValues(m.name, "success").Inc()
	if verificationMode == "skipped" {
		metrics.BundleVerifyTotal.WithLabelValues(m.name, "skipped").Inc()
	} else {
		metrics.BundleVerifyTotal.WithLabelValues(m.name, "success").Inc()
	}
	m.slogger.Info("bundle "+kind+": pull succeeded",
		"digest", fetch.Digest,
		"size_bytes", len(fetch.Tarball),
	)
	m.logSignatureVerification(kind, verificationMode)

	m.slogger.Info("bundle "+kind+": compiling",
		"digest", fetch.Digest,
		"size_bytes", len(fetch.Tarball),
	)
	var eng *Engine
	if m.mandatory {
		eng, err = NewMandatoryEngine(ctx, fetch.Tarball)
	} else {
		eng, err = NewEngine(ctx, fetch.Tarball)
	}
	if err != nil {
		return fmt.Errorf("bundle %s: compile: %w", kind, err)
	}
	manifestRevision := eng.ManifestRevision()
	if m.expectedPolicyRevision != "" && manifestRevision != m.expectedPolicyRevision {
		if manifestRevision == "" {
			return fmt.Errorf("bundle %s: expected policy revision %q but bundle manifest revision is missing", kind, m.expectedPolicyRevision)
		}
		return fmt.Errorf("bundle %s: expected policy revision %q does not match bundle manifest revision %q", kind, m.expectedPolicyRevision, manifestRevision)
	}
	exceptions, err := eng.Exceptions(ctx)
	if err != nil {
		return fmt.Errorf("bundle %s: exception inventory: %w", kind, err)
	}
	for i := range exceptions {
		exceptions[i].BundleName = m.name
		exceptions[i].Digest = fetch.Digest
	}

	now := time.Now()
	m.mu.Lock()
	previousDigest := m.digest
	previousRevision := m.policyRevision
	m.engine = eng
	m.digest = fetch.Digest
	m.loadedAt = now
	m.tarball = fetch.Tarball
	m.exceptions = exceptions
	m.policyRevision = manifestRevision
	m.mu.Unlock()

	if previousDigest != "" && (previousDigest != fetch.Digest || previousRevision != manifestRevision) {
		// Drop the gauge for the old digest so dashboards don't show
		// two simultaneously-loaded bundles. The new digest's gauge is
		// set below.
		metrics.BundleLoadedDigestInfo.DeleteLabelValues(m.name, previousDigest)
		metrics.BundlePolicyRevisionInfo.DeleteLabelValues(m.name, previousDigest, previousRevision)
	}
	metrics.BundleLoadedDigestInfo.WithLabelValues(m.name, fetch.Digest).Set(1)
	metrics.BundlePolicyRevisionInfo.WithLabelValues(m.name, fetch.Digest, manifestRevision).Set(1)
	metrics.BundleAgeSeconds.WithLabelValues(m.name).Set(0)
	m.updateExceptionMetrics(fetch.Digest, exceptions)
	return nil
}

func (m *LiveManager) signatureVerificationMode() string {
	if m.source.Scheme() != "oci" {
		return "skipped"
	}
	if m.verify.SkipVerification {
		return "skipped"
	}
	if m.verify.PublicKeyRef != "" {
		return "cosign_public_key"
	}
	return "cosign_keyless"
}

func (m *LiveManager) logSignatureVerification(kind, mode string) {
	if mode == "skipped" {
		if m.source.Scheme() == "oci" && m.verify.SkipVerification {
			m.slogger.Warn("bundle "+kind+": signature verification skipped",
				"reason", "configured_skip_verification",
				"risk", "unsigned OCI bundles are unsafe for production",
			)
			return
		}
		m.slogger.Info("bundle "+kind+": signature verification skipped",
			"reason", "non_oci_source",
		)
		return
	}
	m.slogger.Info("bundle "+kind+": signature verification validated",
		"signature_verification", mode,
	)
}

// Start launches the background poll loop. Safe to call once. No-op
// when PollInterval == 0 (polling disabled — operators may still
// reload via SIGHUP). Must be called after Init.
func (m *LiveManager) Start(parent context.Context) {
	if m.pollInterval <= 0 {
		m.slogger.Info("bundle poll loop: disabled (poll_interval == 0)")
		return
	}
	m.startedOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		m.pollerCtx = ctx
		m.pollerCancel = cancel
		m.pollerWG.Add(1)
		go m.pollLoop(ctx)
		m.slogger.Info("bundle poll loop: started", "interval", m.pollInterval)
	})
}

// Stop signals the poll loop to exit and waits for it. Safe to call
// even if Start was never called.
func (m *LiveManager) Stop() {
	if m.pollerCancel != nil {
		m.pollerCancel()
		m.pollerWG.Wait()
		m.slogger.Info("bundle poll loop: stopped")
	}
}

// pollLoop runs Reload on a fixed interval until the context is
// cancelled. Reload errors are logged and recorded but never abort the
// loop — a transient registry failure must not silently disable the
// guardrail. Operators see the failure via /health and metrics.
func (m *LiveManager) pollLoop(ctx context.Context) {
	defer m.pollerWG.Done()
	t := time.NewTicker(m.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Reload uses the parent context with its own timeout so a
			// hanging registry doesn't stall the whole loop forever.
			rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			if _, err := m.Reload(rctx); err != nil {
				m.slogger.Warn("bundle poll: reload failed (keeping previous bundle)",
					"error", err,
				)
			}
			cancel()
		}
	}
}

// LastPullError returns the most recent reload error, or nil if the
// last reload (or Init) succeeded. Used by /health to surface
// drift-into-error states without needing log access.
func (m *LiveManager) LastPullError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPullErr
}

// AgeSeconds returns time since the last successful pull, in seconds.
// Used by /health and by the staleness check in Eval.
func (m *LiveManager) AgeSeconds() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.loadedAt.IsZero() {
		return 0
	}
	return time.Since(m.loadedAt).Seconds()
}

// Eval forwards to the loaded engine and stamps metrics. The
// Manager.Eval contract is that the returned error is non-nil only on
// engine errors or staleness rejection; a deny is a successful
// evaluation with Decision.Allow == false. The handler translates
// errors into appropriate response codes.
//
// Staleness handling:
//   - MaxStaleness == 0: skip the check entirely.
//   - age <= MaxStaleness: eval normally.
//   - age > MaxStaleness && fail_mode == "closed": refuse with
//     ErrBundleStale before touching the engine. Increments
//     BundleStaleEvalsTotal{mode="closed"}.
//   - age > MaxStaleness && fail_mode == "open": proceed with the
//     stale bundle, log a warning, increment
//     BundleStaleEvalsTotal{mode="open"}.
func (m *LiveManager) Eval(ctx context.Context, input Input) (Decision, error) {
	if !m.appliesToApp(input.Request.App) {
		return Decision{}, nil
	}

	m.mu.RLock()
	eng := m.engine
	loadedAt := m.loadedAt
	digest := m.digest
	policyRevision := m.policyRevision
	m.mu.RUnlock()

	if eng == nil {
		return Decision{Applicable: true}, fmt.Errorf("%w: bundle %q has no installed engine", ErrBundleUnavailable, m.name)
	}
	snapshotDigest := m.name + "=" + digest

	age := time.Since(loadedAt)
	metrics.BundleAgeSeconds.WithLabelValues(m.name).Set(age.Seconds())

	if m.maxStaleness > 0 && age > m.maxStaleness {
		switch m.failMode {
		case "open":
			metrics.BundleStaleEvalsTotal.WithLabelValues(m.name, "open").Inc()
			m.slogger.Warn("bundle stale: proceeding (fail_mode=open)",
				"age_seconds", age.Seconds(),
				"max_staleness_seconds", m.maxStaleness.Seconds(),
				"digest", digest,
			)
			// Fall through to eval.
		default: // "closed" or unset
			metrics.BundleStaleEvalsTotal.WithLabelValues(m.name, "closed").Inc()
			return Decision{Applicable: true, SnapshotDigest: snapshotDigest}, ErrBundleStale
		}
	}

	d, err := eng.Eval(ctx, input)
	for i := range d.Packages {
		d.Packages[i].BundleName = m.name
		d.Packages[i].Digest = digest
		d.Packages[i].PolicyRevision = policyRevision
	}
	for i := range d.Exceptions {
		d.Exceptions[i].BundleName = m.name
		d.Exceptions[i].Digest = digest
	}
	d.Applicable = true
	d.SnapshotDigest = snapshotDigest
	d.Evaluated = len(d.Packages) > 0
	if d.Evaluated {
		d.EvaluatedDigest = snapshotDigest
	}
	return d, err
}

func (m *LiveManager) appliesToApp(app string) bool {
	if len(m.apps) == 0 {
		return true
	}
	_, ok := m.apps[app]
	return ok
}

// Digest returns the OCI digest of the loaded bundle, used as the
// audit fingerprint. Empty string before Init succeeds.
func (m *LiveManager) Digest() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.digest
}

// Enabled returns true once Init has installed an engine. The exchange
// handler gates its bundle call on this method; a manager that fails
// to Init must never report Enabled() == true (LiveManager achieves
// this naturally because engine stays nil on failure).
func (m *LiveManager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engine != nil
}

func (m *LiveManager) Available() bool { return m.Enabled() }

func (m *LiveManager) Enforcement() string {
	if m.mandatory {
		return EnforcementRequired
	}
	return EnforcementOptional
}

func (m *LiveManager) Mandatory() bool { return m.mandatory }

func (m *LiveManager) BundleStatuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{
		Name: m.name, Enabled: m.engine != nil, Mandatory: m.mandatory,
		Digest: m.digest, PolicyRevision: m.policyRevision,
	}
	if !m.loadedAt.IsZero() {
		st.AgeSeconds = time.Since(m.loadedAt).Seconds()
	}
	if m.lastPullErr != nil {
		st.LastPullError = m.lastPullErr.Error()
	}
	return []Status{st}
}

func (m *LiveManager) updateExceptionMetrics(digest string, exceptions []Exception) {
	counts := map[string]int{"active": 0, "expiring": 0, "expired": 0, "invalid": 0}
	for _, ex := range exceptions {
		status := ex.Status
		if status == "" {
			status = "invalid"
		}
		counts[status]++
		metrics.BundlePolicyExceptionExpirationTimestampSeconds.WithLabelValues(m.name, digest, ex.ExceptionID, ex.RuleID, ex.Owner).Set(ex.ExpirationUnixSeconds)
		metrics.BundlePolicyExceptionSecondsUntilExpiration.WithLabelValues(m.name, digest, ex.ExceptionID, ex.RuleID, ex.Owner).Set(ex.SecondsUntilExpiration)
	}
	for status, count := range counts {
		metrics.BundlePolicyExceptionsTotal.WithLabelValues(m.name, digest, status).Set(float64(count))
	}
}

// BundleFile extracts a single named file from the cached bundle
// tarball. The match is exact after stripping a leading "./" or "/"
// from both the requested name and each tar header, since `opa build`
// emits entries with various leading-path conventions across versions.
//
// Returns ErrDisabled if Init hasn't run, ErrFileNotFound if the path
// is absent, or a wrapped error on tar/gzip read failure. The returned
// slice is a fresh copy — callers may mutate it freely.
func (m *LiveManager) BundleFile(name string) ([]byte, error) {
	m.mu.RLock()
	tarball := m.tarball
	m.mu.RUnlock()
	if tarball == nil {
		return nil, ErrDisabled
	}

	want := canonicalTarPath(name)
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("bundle file %q: opening gzip: %w", name, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, ErrFileNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("bundle file %q: reading tar: %w", name, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if canonicalTarPath(hdr.Name) != want {
			continue
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, fmt.Errorf("bundle file %q: reading body: %w", name, err)
		}
		return buf, nil
	}
}

// canonicalTarPath strips leading "./" and "/" so callers and tar
// entries compare cleanly regardless of which leading-path convention
// the producer's `opa build` emits.
func canonicalTarPath(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}
