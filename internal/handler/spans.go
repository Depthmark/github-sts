package handler

import (
	"context"

	"github.com/depthmark/github-sts/internal/audit"
	ststracing "github.com/depthmark/github-sts/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func startStage(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return ststracing.Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

func endStage(span trace.Span, result, errorType string) {
	if errorType != "" {
		ststracing.MarkError(span, errorType)
	} else if result != "" {
		span.SetAttributes(ststracing.StageResult(result))
	}
	span.End()
}

func annotateExchangeSpan(ctx context.Context, event *audit.Event) {
	span := trace.SpanFromContext(ctx)
	if event == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(ststracing.ExchangeAttributes(*event)...)
	if code, description := ststracing.SpanStatus(event.Result); code != codes.Unset {
		span.SetStatus(code, description)
	}
}
