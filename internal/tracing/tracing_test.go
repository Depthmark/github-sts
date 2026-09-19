package tracing

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

// TestNewResourceMergesWithSDKDefault guards server startup with tracing
// enabled. newResource merges resource.Default(), whose schema URL comes from
// the OTel SDK, with attributes built from this package's semconv import.
// resource.Merge fails when the two schema URLs differ, Init returns that
// error, and the server refuses to start.
//
// A dependency update alone is enough to break it: after the SDK moved to
// semconv 1.43.0 while this package still imported 1.41.0, github-sts-dev
// crash-looped with "conflicting Schema URL: https://opentelemetry.io/schemas/1.43.0
// and https://opentelemetry.io/schemas/1.41.0". If this test fails after an
// OTel update, move every go.opentelemetry.io/otel/semconv import to the
// version resource.Default() reports.
func TestNewResourceMergesWithSDKDefault(t *testing.T) {
	sdkSchema := resource.Default().SchemaURL()

	res, err := newResource(Config{ServiceName: "github-sts", Environment: "test"})
	if err != nil {
		t.Fatalf("newResource: %v\nresource.Default() uses schema %s; align the semconv imports with it", err, sdkSchema)
	}
	if got := res.SchemaURL(); got != sdkSchema {
		t.Errorf("resource schema URL = %q, want the SDK's %q", got, sdkSchema)
	}

	for key, want := range map[attribute.Key]string{
		"service.name":                "github-sts",
		"deployment.environment.name": "test",
	} {
		got, ok := res.Set().Value(key)
		if !ok || got.AsString() != want {
			t.Errorf("resource attribute %s = %q (present %v), want %q", key, got.AsString(), ok, want)
		}
	}
}
