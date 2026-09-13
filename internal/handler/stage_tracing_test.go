package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func stageTraceRecorder(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	t.Helper()
	previous := otel.GetTracerProvider()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(previous)
	})
	return provider, recorder
}

func TestExchangeStageSpansAreSiblings(t *testing.T) {
	provider, recorder := stageTraceRecorder(t)
	app := &mockExchangeApp{instance: "app-2"}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{
		pol: validExchangePolicy("2001", "2002"),
	}, &recordingAuditLogger{})

	ctx, root := provider.Tracer("test").Start(context.Background(), "GET /sts/exchange")
	rootID := root.SpanContext().SpanID()
	req := authorizedExchangeRequest().WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	root.End()

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	want := map[string]bool{
		"sts.oidc.validate":       false,
		"sts.jti.reserve":         false,
		"github.target.resolve":   false,
		"sts.policy.load":         false,
		"sts.policy.validate":     false,
		"sts.policy.evaluate":     false,
		"sts.policy.relationship": false,
		"sts.permissions.narrow":  false,
		"sts.token.issue":         false,
	}
	for _, span := range recorder.Ended() {
		if span.Name() == "GET /sts/exchange" {
			if got := spanAttributeValue(span.Attributes(), "sts.result"); got != "success" {
				t.Errorf("root sts.result = %q, want success", got)
			}
		}
		if _, ok := want[span.Name()]; !ok {
			continue
		}
		want[span.Name()] = true
		if span.Parent().SpanID() != rootID {
			t.Errorf("span %q parent = %s, want root %s", span.Name(), span.Parent().SpanID(), rootID)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing stage span %q", name)
		}
	}
}

func spanAttributeValue(attrs []attribute.KeyValue, key string) string {
	for _, attr := range attrs {
		if string(attr.Key) == key {
			return attr.Value.AsString()
		}
	}
	return ""
}

func TestPolicyLoadSpanUsesSanitizedErrorType(t *testing.T) {
	provider, recorder := stageTraceRecorder(t)
	secret := "ghs_must_not_reach_trace"
	app := &mockExchangeApp{}
	h := authorizedExchangeHandler(app, &mockPolicyLoader{
		err: errors.New("GitHub response contained " + secret),
	}, &recordingAuditLogger{})

	ctx, root := provider.Tracer("test").Start(context.Background(), "GET /sts/exchange")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedExchangeRequest().WithContext(ctx))
	root.End()

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	foundPolicyLoad := false
	for _, span := range recorder.Ended() {
		if span.Name() == "GET /sts/exchange" {
			if got := spanAttributeValue(span.Attributes(), "sts.result"); got != "github_error" {
				t.Errorf("root sts.result = %q, want github_error", got)
			}
			if span.Status().Code != codes.Error {
				t.Errorf("root status = %v, want error", span.Status().Code)
			}
		}
		if span.Name() != "sts.policy.load" {
			continue
		}
		foundPolicyLoad = true
		if span.Status().Code != codes.Error {
			t.Errorf("policy load status = %v, want error", span.Status().Code)
		}
		for _, attr := range span.Attributes() {
			if strings.Contains(attr.Value.AsString(), secret) {
				t.Fatalf("attribute %q leaked upstream response", attr.Key)
			}
		}
	}
	if !foundPolicyLoad {
		t.Fatal("missing sts.policy.load span")
	}
}

func TestBundleEvaluationSpanRecordsDecision(t *testing.T) {
	provider, recorder := stageTraceRecorder(t)
	mgr := &spyManager{
		enabled: true,
		decision: bundle.Decision{
			Applicable: true,
			Evaluated:  true,
			Allow:      true,
		},
	}
	h, _, _ := newBundleTestHandler(t, mgr)

	ctx, root := provider.Tracer("test").Start(context.Background(), "GET /sts/exchange")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bundleExchangeRequest().WithContext(ctx))
	root.End()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	for _, span := range recorder.Ended() {
		if span.Name() == "sts.bundle.evaluate" {
			if got := spanAttributeValue(span.Attributes(), "sts.stage.result"); got != "allowed" {
				t.Errorf("bundle result = %q, want allowed", got)
			}
			return
		}
	}
	t.Fatal("missing sts.bundle.evaluate span")
}
