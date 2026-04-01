// Package audit provides structured audit logging for token exchange events.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/depthmark/github-sts/internal/metrics"
)

// auditLogLevel returns the appropriate slog level for a given exchange result.
func auditLogLevel(result ExchangeResult) slog.Level {
	switch result {
	case ResultSuccess:
		return slog.LevelInfo
	case ResultPolicyDenied, ResultNotFound, ResultOIDCInvalid, ResultJTIReplay:
		return slog.LevelWarn
	default:
		// ResultGitHubError, ResultCacheError, ResultUnknownError
		return slog.LevelError
	}
}

// ExchangeResult represents the outcome of a token exchange attempt.
type ExchangeResult string

const (
	ResultSuccess      ExchangeResult = "success"
	ResultPolicyDenied ExchangeResult = "policy_denied"
	ResultOIDCInvalid  ExchangeResult = "oidc_invalid"
	ResultJTIReplay    ExchangeResult = "jti_replay"
	ResultNotFound     ExchangeResult = "policy_not_found"
	ResultCacheError   ExchangeResult = "cache_error"
	ResultGitHubError  ExchangeResult = "github_error"
	ResultUnknownError ExchangeResult = "unknown_error"
)

// Event represents a single token exchange audit event.
type Event struct {
	Timestamp   time.Time      `json:"timestamp"`
	TraceID     string         `json:"trace_id"`
	Scope       string         `json:"scope"`
	AppName     string         `json:"app"`
	Identity    string         `json:"identity"`
	Issuer      string         `json:"issuer"`
	Subject     string         `json:"subject"`
	JTI         string         `json:"jti,omitempty"`
	Result      ExchangeResult `json:"result"`
	ErrorReason string         `json:"error_reason,omitempty"`
	DurationMS  int64          `json:"duration_ms"`
	UserAgent   string         `json:"user_agent,omitempty"`
	RemoteIP    string         `json:"remote_ip,omitempty"`
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
				"identity", event.Identity,
				"issuer", event.Issuer,
				"subject", event.Subject,
				"result", string(event.Result),
				"duration_ms", event.DurationMS,
			}
			if event.ErrorReason != "" {
				attrs = append(attrs, "error_reason", event.ErrorReason)
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
