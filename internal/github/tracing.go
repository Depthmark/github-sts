package github

import (
	"context"
	"errors"
	"net/http"

	ststracing "github.com/depthmark/github-sts/internal/tracing"
	"go.opentelemetry.io/otel/trace"
)

func tokenPurpose(caller string) string {
	switch caller {
	case "policy_loader":
		return "policy_fetch"
	case "target_resolver":
		return "target_resolution"
	default:
		return "internal"
	}
}

func tokenMintErrorType(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}

	var mintErr *TokenMintError
	if !errors.As(err, &mintErr) {
		return "github_operation_failed"
	}
	switch {
	case mintErr.StatusCode == http.StatusUnprocessableEntity:
		return "github_permissions_not_granted"
	case mintErr.StatusCode == http.StatusNotFound:
		return "github_not_found"
	case (mintErr.StatusCode == http.StatusForbidden || mintErr.StatusCode == http.StatusTooManyRequests) && mintErr.Retryable:
		return "github_rate_limited"
	case mintErr.StatusCode == http.StatusUnauthorized || mintErr.StatusCode == http.StatusForbidden:
		return "github_authentication_failed"
	case mintErr.StatusCode >= 500:
		return "github_upstream_error"
	case mintErr.StatusCode == 0:
		return "github_transport_error"
	default:
		return "github_unexpected_response"
	}
}

func endGitHubSpan(span trace.Span, err error) {
	if err != nil {
		ststracing.MarkError(span, tokenMintErrorType(err))
	} else {
		span.SetAttributes(ststracing.StageResult("success"))
	}
	span.End()
}
