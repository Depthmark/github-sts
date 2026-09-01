// Package audit provides structured audit logging for token exchange events.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/depthmark/github-sts/internal/bundle"
	"github.com/depthmark/github-sts/internal/metrics"
)

// auditLogLevel returns the appropriate slog level for a given exchange result.
func auditLogLevel(result ExchangeResult) slog.Level {
	switch result {
	case ResultSuccess:
		return slog.LevelInfo
	case ResultPolicyDenied, ResultPolicyInvalid, ResultOrgPolicyDenied, ResultNotFound, ResultOIDCInvalid, ResultJTIReplay:
		return slog.LevelWarn
	default:
		// ResultGitHubError, ResultCacheError, ResultUnknownError
		return slog.LevelError
	}
}

// ExchangeResult represents the outcome of a token exchange attempt.
type ExchangeResult string

const (
	ResultSuccess                ExchangeResult = "success"
	ResultPolicyDenied           ExchangeResult = "policy_denied"
	ResultPolicyInvalid          ExchangeResult = "trust_policy_invalid"
	ResultOrgPolicyDenied        ExchangeResult = "org_policy_denied"
	ResultOIDCInvalid            ExchangeResult = "oidc_invalid"
	ResultJTIReplay              ExchangeResult = "jti_replay"
	ResultNotFound               ExchangeResult = "policy_not_found"
	ResultCacheError             ExchangeResult = "cache_error"
	ResultGitHubError            ExchangeResult = "github_error"
	ResultBundleStale            ExchangeResult = "bundle_stale"
	ResultBundleUnavailable      ExchangeResult = "bundle_unavailable"
	ResultBundleEvaluationFailed ExchangeResult = "bundle_evaluation_failed"
	ResultUnknownError           ExchangeResult = "unknown_error"
)

// Event represents a single token exchange audit event.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id"`
	Scope     string    `json:"scope"`
	AppName   string    `json:"app"`
	// Instance is which physical pool member minted the token (design doc
	// §5.4.1/§5.5) — the forensic hook for scoping an incident to one
	// credential (e.g. "grep instance=checkout-2" if that key is suspected
	// compromised) instead of the whole logical app. Empty on any failed
	// exchange: ErrorReason already carries the failure detail, and for a
	// pool-exhaustion failure naming one arbitrary tried instance out of
	// several that all failed would misleadingly suggest it was uniquely
	// implicated.
	Instance                 string `json:"instance,omitempty"`
	Identity                 string `json:"identity"`
	Issuer                   string `json:"issuer"`
	Subject                  string `json:"subject"`
	SourceRepositoryOwner    string `json:"source_repository_owner,omitempty"`
	SourceRepositoryOwnerID  string `json:"source_repository_owner_id,omitempty"`
	SourceRepository         string `json:"source_repository,omitempty"`
	SourceRepositoryID       string `json:"source_repository_id,omitempty"`
	TargetRepositoryOwner    string `json:"target_repository_owner,omitempty"`
	TargetRepositoryOwnerID  string `json:"target_repository_owner_id,omitempty"`
	TargetRepository         string `json:"target_repository,omitempty"`
	TargetRepositoryID       string `json:"target_repository_id,omitempty"`
	ImmutableSubject         *bool  `json:"immutable_subject,omitempty"`
	ImmutableSubjectRequired *bool  `json:"immutable_subject_required,omitempty"`
	JTI                      string `json:"jti,omitempty"`
	// Trust-policy provenance: which policy file governed this exchange,
	// and which exact bytes of it. BundleDigest below does the same job for
	// the org Rego bundle; both halves of the decision are now nameable.
	//
	// PolicySource ("centralized" or "repository") is not cosmetic. Under
	// repo_first resolution a repo owner can override the centralized org
	// policy, so which side won is an authorization fact, not a detail.
	//
	// PolicyBlobSHA is git's own object hash, so an auditor can verify the
	// record against a clone with `git hash-object`, and reach the commits
	// behind it with `git log --find-object`, without any API access.
	PolicyRepository string `json:"policy_repository,omitempty"`
	PolicyPath       string `json:"policy_path,omitempty"`
	PolicyBlobSHA    string `json:"policy_blob_sha,omitempty"`
	PolicySource     string `json:"policy_source,omitempty"`

	Result            ExchangeResult   `json:"result"`
	ErrorReason       string           `json:"error_reason,omitempty"`
	DurationMS        int64            `json:"duration_ms"`
	UserAgent         string           `json:"user_agent,omitempty"`
	RemoteIP          string           `json:"remote_ip,omitempty"`
	OrgDecision       *OrgDecision     `json:"org_decision,omitempty"`
	BundleDigest      string           `json:"bundle_digest,omitempty"`
	BundleEnforcement string           `json:"bundle_enforcement"`
	BundleDecisions   []BundleDecision `json:"bundle_decisions,omitempty"`
}

// OrgDecision is the bundle's verdict captured in the audit trail. Allow
// is the final allow/deny outcome; Reasons is the producer's
// allow_reasons (on allow) or deny_reasons (on deny). Phase 3 will add
// a Mode field here to disambiguate validate-mode from exchange-mode.
type OrgDecision struct {
	Applicable bool     `json:"applicable"`
	Evaluated  bool     `json:"evaluated"`
	Allow      bool     `json:"allow"`
	Reasons    []string `json:"reasons,omitempty"`
}

type BundleDecision struct {
	BundleName     string            `json:"bundle_name"`
	Digest         string            `json:"digest"`
	PolicyRevision string            `json:"policy_revision,omitempty"`
	Packages       []PackageDecision `json:"packages,omitempty"`
}

type PackageDecision struct {
	Package     string   `json:"package"`
	Query       string   `json:"query"`
	Allow       bool     `json:"allow"`
	Reasons     []string `json:"reasons,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	RuleName    string   `json:"rule_name,omitempty"`
	ExceptionID string   `json:"exception_id,omitempty"`
}

func FromBundleDecision(d bundle.Decision) []BundleDecision {
	byBundle := make(map[string]*BundleDecision)
	order := make([]string, 0)
	for _, pd := range d.Packages {
		name := pd.BundleName
		if name == "" {
			name = "unknown"
		}
		bd, ok := byBundle[name]
		if !ok {
			bd = &BundleDecision{BundleName: name, Digest: pd.Digest, PolicyRevision: pd.PolicyRevision}
			byBundle[name] = bd
			order = append(order, name)
		}
		bd.Packages = append(bd.Packages, PackageDecision{
			Package:     pd.Package,
			Query:       pd.Query,
			Allow:       pd.Allow,
			Reasons:     pd.Reasons,
			RuleID:      pd.RuleID,
			RuleName:    pd.RuleName,
			ExceptionID: pd.ExceptionID,
		})
	}
	out := make([]BundleDecision, 0, len(order))
	for _, name := range order {
		out = append(out, *byBundle[name])
	}
	return out
}

// Logger is the interface for audit event logging.
type Logger interface {
	Log(event Event)
	Close() error
}

// FileLogger writes audit events as JSON lines to a file using a buffered
// channel for non-blocking writes.
type FileLogger struct {
	ch      chan Event
	file    *os.File
	slogger *slog.Logger
	done    chan struct{}
}

// NewFileLogger creates a FileLogger that writes to the given path.
// If path is empty, events are only emitted to the slog logger.
func NewFileLogger(path string, bufferSize int, slogger *slog.Logger) (*FileLogger, error) {
	var file *os.File
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		file = f
	}

	if bufferSize <= 0 {
		bufferSize = 1024
	}

	fl := &FileLogger{
		ch:      make(chan Event, bufferSize),
		file:    file,
		slogger: slogger,
		done:    make(chan struct{}),
	}

	go fl.writer()
	return fl, nil
}

// Log queues an audit event for writing. Non-blocking — if the channel is full,
// the event is dropped and a warning is logged.
func (fl *FileLogger) Log(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case fl.ch <- event:
	default:
		metrics.AuditEventsDropped.Inc()
		if fl.slogger != nil {
			fl.slogger.Warn("audit event dropped, channel full")
		}
	}
}

// Close drains remaining events and closes the file. Waits up to 5 seconds.
func (fl *FileLogger) Close() error {
	close(fl.ch)
	select {
	case <-fl.done:
	case <-time.After(5 * time.Second):
		if fl.slogger != nil {
			fl.slogger.Warn("audit logger drain timed out")
		}
	}
	if fl.file != nil {
		return fl.file.Close()
	}
	return nil
}

// writer is the background goroutine that consumes events from the channel.
func (fl *FileLogger) writer() {
	defer close(fl.done)
	enc := json.NewEncoder(os.Stderr) // fallback if file is nil
	if fl.file != nil {
		enc = json.NewEncoder(fl.file)
	}

	for event := range fl.ch {
		if fl.file != nil {
			if err := enc.Encode(event); err != nil {
				metrics.AuditLogErrors.WithLabelValues("file").Inc()
				if fl.slogger != nil {
					fl.slogger.Error("audit write error", "error", err)
				}
			}
		}

		// Also emit to slog for container log aggregation.
		if fl.slogger != nil {
			attrs := []any{
				"trace_id", event.TraceID,
				"scope", event.Scope,
				"app", event.AppName,
				"instance", event.Instance,
				"identity", event.Identity,
				"issuer", event.Issuer,
				"subject", event.Subject,
				"result", string(event.Result),
				"duration_ms", event.DurationMS,
			}
			if event.ErrorReason != "" {
				attrs = append(attrs, "error_reason", event.ErrorReason)
			}
			if event.SourceRepositoryID != "" {
				attrs = append(attrs,
					"source_repository_owner", event.SourceRepositoryOwner,
					"source_repository_owner_id", event.SourceRepositoryOwnerID,
					"source_repository", event.SourceRepository,
					"source_repository_id", event.SourceRepositoryID,
				)
			}
			if event.TargetRepositoryID != "" {
				attrs = append(attrs,
					"target_repository_owner", event.TargetRepositoryOwner,
					"target_repository_owner_id", event.TargetRepositoryOwnerID,
					"target_repository", event.TargetRepository,
					"target_repository_id", event.TargetRepositoryID,
				)
			}
			if event.PolicyBlobSHA != "" {
				attrs = append(attrs,
					"policy_repository", event.PolicyRepository,
					"policy_path", event.PolicyPath,
					"policy_blob_sha", event.PolicyBlobSHA,
				)
			}
			if event.PolicySource != "" {
				attrs = append(attrs, "policy_source", event.PolicySource)
			}
			if event.ImmutableSubject != nil {
				attrs = append(attrs, "immutable_subject", *event.ImmutableSubject)
			}
			if event.ImmutableSubjectRequired != nil {
				attrs = append(attrs, "immutable_subject_required", *event.ImmutableSubjectRequired)
			}
			if event.BundleDigest != "" {
				attrs = append(attrs, "bundle_digest", event.BundleDigest)
			}
			attrs = append(attrs, "bundle_enforcement", event.BundleEnforcement)
			if event.OrgDecision != nil {
				attrs = append(attrs,
					"org_decision_applicable", event.OrgDecision.Applicable,
					"org_decision_evaluated", event.OrgDecision.Evaluated,
					"org_decision_allow", event.OrgDecision.Allow,
					"org_decision_reasons", event.OrgDecision.Reasons,
				)
			}
			if len(event.BundleDecisions) > 0 {
				attrs = append(attrs, "bundle_decisions", event.BundleDecisions)
			}
			fl.slogger.Log(context.Background(), auditLogLevel(event.Result), "audit", attrs...)
		}

		metrics.AuditEventsLogged.WithLabelValues(string(event.Result)).Inc()
	}
}

// TruncateJTI truncates a JTI string to the given maximum length.
func TruncateJTI(jti string, max int) string {
	if len(jti) <= max {
		return jti
	}
	return jti[:max]
}

// TruncateUserAgent truncates a user agent string to the given maximum length.
func TruncateUserAgent(ua string, max int) string {
	if len(ua) <= max {
		return ua
	}
	return ua[:max]
}

// NopLogger is a no-op audit logger for testing.
type NopLogger struct{}

func (NopLogger) Log(Event)    {}
func (NopLogger) Close() error { return nil }
