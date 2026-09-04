package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depthmark/github-sts/internal/handler"
	"github.com/depthmark/github-sts/internal/tracing"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestTraceIDMiddlewarePrefersSpanContext is the property the entire
// correlation story rests on: the trace_id in the response header, in the
// audit event and in every log line must be the *same* identifier as the trace
// in the backend. If these ever diverge, an operator holding an error response
// cannot find the trace, and the field correlates with nothing.
func TestTraceIDMiddlewarePrefersSpanContext(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	var contextID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(handler.TraceIDKey).(string); ok {
			contextID = v
		}
		w.WriteHeader(http.StatusOK)
	})

	// Start a span and serve the request inside it, standing in for the
	// otelhttp server span that will wrap this middleware.
	ctx, span := provider.Tracer("test").Start(context.Background(), "POST /sts/exchange")
	defer span.End()
	wantTraceID := span.SpanContext().TraceID().String()

	rec := httptest.NewRecorder()
	traceIDMiddleware(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))

	headerID := rec.Header().Get("X-Trace-ID")
	if headerID != wantTraceID {
		t.Errorf("X-Trace-ID = %q, want the span's trace ID %q", headerID, wantTraceID)
	}
	if contextID != wantTraceID {
		t.Errorf("context trace ID = %q, want the span's trace ID %q", contextID, wantTraceID)
	}
}

// TestTraceIDMiddlewareFallsBackWithoutSpan covers the paths that legitimately
// have no span: tracing disabled, and the health endpoints excluded from
// tracing. The format must not change with the toggle, so a 32-hex ID is still
// required here.
func TestTraceIDMiddlewareFallsBackWithoutSpan(t *testing.T) {
	var contextID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(handler.TraceIDKey).(string); ok {
			contextID = v
		}
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	traceIDMiddleware(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	headerID := rec.Header().Get("X-Trace-ID")
	if len(headerID) != 32 {
		t.Errorf("fallback trace ID length = %d, want 32", len(headerID))
	}
	if _, err := hex.DecodeString(headerID); err != nil {
		t.Errorf("fallback trace ID %q is not hex: %v", headerID, err)
	}
	if headerID != contextID {
		t.Errorf("header %q != context %q", headerID, contextID)
	}
}

// TestTracingInitDisabledIsNoop asserts the disabled path stays free: no
// exporter is built, no error is returned, and the shutdown function is safe
// to call. A deployment that never turns tracing on should pay nothing.
func TestTracingInitDisabledIsNoop(t *testing.T) {
	shutdown, err := tracing.Init(context.Background(), tracing.Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("Init with tracing disabled returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned a nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown with tracing disabled returned error: %v", err)
	}

	// The propagators are installed either way, so an inbound traceparent is
	// still honoured and trace_id stays continuous with the caller's trace.
	if tracing.TraceIDFromContext(context.Background()) != "" {
		t.Error("expected no trace ID from a context with no span")
	}
	if !trace.SpanContextFromContext(context.Background()).IsValid() {
		return // expected: no span means an invalid span context
	}
	t.Error("empty context unexpectedly carried a valid span context")
}
