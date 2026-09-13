package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func githubTraceRecorder(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
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

func spanAttribute(span sdktrace.ReadOnlySpan, key string) string {
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			return attr.Value.AsString()
		}
	}
	return ""
}

func TestAppJWTSpansDistinguishSigningFromCacheHits(t *testing.T) {
	provider, recorder := githubTraceRecorder(t)
	p := NewAppTokenProvider("test-app", "app-2", 12345, generateTestKey(t), "https://api.github.com", nil)

	ctx, root := provider.Tracer("test").Start(context.Background(), "root")
	if _, err := p.GenerateAppJWT(ctx); err != nil {
		t.Fatalf("first GenerateAppJWT: %v", err)
	}
	if _, err := p.GenerateAppJWT(ctx); err != nil {
		t.Fatalf("second GenerateAppJWT: %v", err)
	}
	root.End()

	var gets, signs int
	cacheResults := map[string]int{}
	for _, span := range recorder.Ended() {
		switch span.Name() {
		case "github.app_jwt.get":
			gets++
			cacheResults[spanAttribute(span, string(tracing.AttrCacheResult))]++
		case "github.app_jwt.sign":
			signs++
		}
	}
	if gets != 2 || signs != 1 || cacheResults["miss"] != 1 || cacheResults["hit"] != 1 {
		t.Fatalf("JWT spans: gets=%d signs=%d cache=%v; want 2 gets, 1 sign, one miss and one hit", gets, signs, cacheResults)
	}
}

func TestPolicyToken422HasPurposeAndSafeErrorType(t *testing.T) {
	provider, recorder := githubTraceRecorder(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/myorg/installation":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          42,
				"permissions": map[string]string{"metadata": "read"},
			})
		default:
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"sensitive upstream detail"}`))
		}
	}))
	defer srv.Close()

	client := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
	p := NewAppTokenProvider("test-actions-app", "app-2", 12345, generateTestKey(t), srv.URL, client)
	ctx, root := provider.Tracer("test").Start(context.Background(), "sts.policy.load")
	_, err := p.GetInstallationToken(ctx, "myorg/policies", map[string]string{"contents": "read"}, nil, "policy_loader")
	root.End()
	if err == nil {
		t.Fatal("expected GitHub 422")
	}

	var foundMint, foundHTTP422 bool
	for _, span := range recorder.Ended() {
		if span.Name() == "github.token.mint" {
			foundMint = true
			if span.Status().Code != codes.Error {
				t.Errorf("mint status = %v, want error", span.Status().Code)
			}
			if got := spanAttribute(span, string(tracing.AttrTokenPurpose)); got != "policy_fetch" {
				t.Errorf("token purpose = %q, want policy_fetch", got)
			}
			if got := spanAttribute(span, string(tracing.AttrErrorType)); got != "github_permissions_not_granted" {
				t.Errorf("error.type = %q, want github_permissions_not_granted", got)
			}
		}
		for _, attr := range span.Attributes() {
			if string(attr.Key) == "http.response.status_code" && attr.Value.AsInt64() == http.StatusUnprocessableEntity {
				foundHTTP422 = true
			}
			if strings.Contains(attr.Value.AsString(), "sensitive upstream detail") {
				t.Fatalf("span %q leaked the upstream response body", span.Name())
			}
		}
	}
	if !foundMint || !foundHTTP422 {
		t.Fatalf("found mint=%v HTTP 422=%v, want both", foundMint, foundHTTP422)
	}
}
