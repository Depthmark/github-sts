package tracing

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// StageResult returns a bounded outcome attribute for a child operation span.
// Authorization denials are outcomes rather than instrumentation errors, so
// callers may set "denied" without changing the OpenTelemetry span status.
func StageResult(result string) attribute.KeyValue {
	return AttrStageResult.String(result)
}

// GitHubOperationAttributes describes one GitHub operation without exposing
// repository names, credentials, request bodies, or upstream error messages.
func GitHubOperationAttributes(app, instance, operation, tokenPurpose string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 4)
	if app != "" {
		attrs = append(attrs, AttrGitHubApp.String(app))
	}
	if instance != "" {
		attrs = append(attrs, AttrGitHubAppInstance.String(instance))
	}
	if operation != "" {
		attrs = append(attrs, AttrGitHubAPIOperation.String(operation))
	}
	if tokenPurpose != "" {
		attrs = append(attrs, AttrTokenPurpose.String(tokenPurpose))
	}
	return attrs
}

// AppPoolAttemptAttributes identifies a bounded pool attempt. attempt is
// one-based and capped by the configured pool size.
func AppPoolAttemptAttributes(app, instance, operation, tokenPurpose string, attempt int) []attribute.KeyValue {
	attrs := GitHubOperationAttributes(app, instance, operation, tokenPurpose)
	return append(attrs, AttrGitHubPoolAttempt.Int(attempt))
}

// CacheAttributes identifies a local credential/cache lookup. result is one
// of hit, miss, or shared.
func CacheAttributes(app, instance, name, result string) []attribute.KeyValue {
	attrs := GitHubOperationAttributes(app, instance, "", "")
	if name != "" {
		attrs = append(attrs, AttrCacheName.String(name))
	}
	if result != "" {
		attrs = append(attrs, AttrCacheResult.String(result))
	}
	return attrs
}

// MarkError records a stable error category and ERROR status without attaching
// err.Error(), which may contain GitHub response bodies or credential context.
func MarkError(span trace.Span, errorType string) {
	if errorType == "" {
		errorType = "unknown"
	}
	span.SetAttributes(AttrErrorType.String(errorType), StageResult("error"))
	span.SetStatus(codes.Error, errorType)
}
