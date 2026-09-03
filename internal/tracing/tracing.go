package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ScopeName is the instrumentation scope for every span this service creates.
const ScopeName = "github.com/depthmark/github-sts"

// Config is the subset of settings this package needs. It mirrors
// config.TracingConfig, kept as a local type so internal/tracing does not
// import internal/config (which would make the config package harder to test
// in isolation and invites an import cycle later).
type Config struct {
	Enabled     bool
	Endpoint    string
	Protocol    string
	Insecure    bool
	SampleRatio float64
	Timeout     time.Duration
	ServiceName string
	Environment string
	Headers     map[string]string
}

// ShutdownFunc flushes buffered spans and releases the exporter. It is safe to
// call when tracing is disabled, where it is a no-op.
type ShutdownFunc func(context.Context) error

// Init installs the global TracerProvider and propagators, returning a
// shutdown function the caller must invoke during graceful shutdown.
//
// When cfg.Enabled is false this installs a noop provider rather than leaving
// the global unset. Both are silent, but a noop provider makes every
// instrumentation call in the codebase a cheap, non-nil no-op with no
// conditional guards at the call sites, and it means the disabled path is the
// same code path as the enabled one.
func Init(ctx context.Context, cfg Config, slogger *slog.Logger) (ShutdownFunc, error) {
	// Propagators are installed either way. Honouring an inbound traceparent
	// costs nothing when we are not exporting, and it keeps the trace ID in
	// logs and audit events continuous with the caller's trace even for a
	// deployment that never turns exporting on.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp exporter: %w", err)
	}

	res, err := newResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	// ParentBased so an inbound sampling decision is respected: a caller that
	// sampled its trace gets our spans too, and one that did not is not
	// half-recorded. See the design doc on why the ratio should stay at 1.0
	// and result-aware selection belongs in the Collector's tail sampler --
	// the exchange result is not known when a head sampler runs, so sampling
	// down here discards denials, which are the spans worth keeping.
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(provider)

	if slogger != nil {
		slogger.Info("tracing enabled",
			"endpoint", cfg.Endpoint,
			"protocol", cfg.Protocol,
			"sample_ratio", cfg.SampleRatio,
			"service_name", cfg.ServiceName,
		)
	}

	return provider.Shutdown, nil
}

// newExporter builds the OTLP exporter for the configured protocol.
func newExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch strings.ToLower(cfg.Protocol) {
	case "", "grpc":
		opts := []otlptracegrpc.Option{otlptracegrpc.WithTimeout(cfg.Timeout)}
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		return otlptracegrpc.New(ctx, opts...)

	case "http", "http/protobuf":
		opts := []otlptracehttp.Option{otlptracehttp.WithTimeout(cfg.Timeout)}
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		return otlptracehttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unsupported protocol %q (want grpc or http)", cfg.Protocol)
	}
}

// newResource describes this service to the backend.
//
// service.instance.id is deliberately NOT set. The OTLP-to-Prometheus
// specification maps service.name -> the `job` label and service.instance.id ->
// the `instance` label, both of which Kubernetes service discovery also
// injects. Setting service.instance.id here to a pod identity would look like
// agreement while silently discarding the pool-member meaning that
// github_app_instance exists to expose. The label set for derived metrics is
// settled in the Collector config instead, where it can be seen and validated.
func newResource(cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
	}
	if v := buildVersion(); v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, semconv.DeploymentEnvironmentNameKey.String(cfg.Environment))
	}

	return resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL, attrs...))
}

// buildVersion reads the version stamped into the binary by the Go toolchain.
// Returns "" for a binary built outside a module context (such as `go test`),
// where the attribute is simply omitted.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}

// Tracer returns this service's tracer. Safe before Init: the OTel global
// falls back to a no-op.
func Tracer() trace.Tracer {
	return otel.Tracer(ScopeName)
}

// TraceIDFromContext returns the W3C trace ID of the active span as 32 lowercase
// hex characters, or "" when there is no valid span context.
//
// This is what makes trace_id in the audit log, the server logs, the
// X-Trace-ID header and the error response the *same* identifier as the trace
// in the backend. Without it the field correlates with nothing.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasTraceID() {
		return ""
	}
	return sc.TraceID().String()
}
