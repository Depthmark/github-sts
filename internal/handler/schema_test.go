package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depthmark/github-sts/internal/bundle"
)

// fixtureSchemaJSON is a minimal, well-formed JSON Schema body for
// testing the route's passthrough behaviour. The full canonical schema
// lives at internal/policy/yaml/schema_v1.json and is consumed by
// IDEs in production via the bundle, not by these unit tests — the
// route's job is to republish whatever the bundle ships, regardless of
// schema content.
var fixtureSchemaJSON = []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json",
  "title": "test trust policy schema",
  "type": "object"
}`)

// fakeFileManager is a bundle.Manager that answers BundleFile from an
// in-memory map. It does not implement Eval (panics if called). The
// schema handler only ever calls Enabled / Digest / BundleFile, so
// that's all this fake supplies.
type fakeFileManager struct {
	enabled bool
	digest  string
	files   map[string][]byte
}

func (m *fakeFileManager) Eval(_ context.Context, _ bundle.Input) (bundle.Decision, error) {
	panic("fakeFileManager.Eval should not be called by the schema route")
}
func (m *fakeFileManager) Digest() string      { return m.digest }
func (m *fakeFileManager) Enabled() bool       { return m.enabled }
func (m *fakeFileManager) Enforcement() string { return bundle.EnforcementOptional }
func (m *fakeFileManager) BundleStatuses() []bundle.Status {
	return []bundle.Status{{Name: "test", Enabled: m.enabled, Digest: m.digest}}
}
func (m *fakeFileManager) BundleFile(name string) ([]byte, error) {
	if !m.enabled {
		return nil, bundle.ErrDisabled
	}
	if b, ok := m.files[name]; ok {
		return b, nil
	}
	return nil, bundle.ErrFileNotFound
}

func decodeErr(t *testing.T, body []byte) ErrorResponse {
	t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error body: %v\nraw: %s", err, body)
	}
	return resp
}

// TestSchema_RouteServesBundleFile counter-validates the happy path:
// a bundle that ships /data/sts/v1/trust-policy.json with the
// canonical reference schema → the route returns 200, the right
// Content-Type, an ETag, and the exact bytes the bundle held.
func TestSchema_RouteServesBundleFile(t *testing.T) {
	mgr := &fakeFileManager{
		enabled: true,
		digest:  "sha256:test-digest",
		files:   map[string][]byte{schemaBundlePath: fixtureSchemaJSON},
	}
	h := NewSchemaHandler(mgr)

	req := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/schema+json" {
		t.Errorf("Content-Type = %q, want application/schema+json", got)
	}
	if w.Header().Get("ETag") == "" {
		t.Errorf("ETag header missing")
	}
	if w.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", w.Header().Get("Cache-Control"))
	}
	if w.Body.String() != string(fixtureSchemaJSON) {
		t.Errorf("body length mismatch: got %d, want %d", w.Body.Len(), len(fixtureSchemaJSON))
	}

	// Sanity: the served bytes parse as JSON and carry the canonical
	// $id. A failure here means the fixture drifted from the contract,
	// not that the handler is broken — but it would still surface as
	// "VS Code can't validate."
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("served bytes not valid JSON: %v", err)
	}
	if id, _ := parsed["$id"].(string); id != "https://depthmark.github.io/github-sts/schemas/sts/v1/trust-policy.json" {
		t.Errorf("served schema $id = %q, want canonical URL", id)
	}
}

// TestSchema_HEAD counter-validates that HEAD returns headers without
// a body. IDEs (and curl --head) use HEAD to check freshness; missing
// HEAD support would force a full GET on every editor focus event.
func TestSchema_HEAD(t *testing.T) {
	mgr := &fakeFileManager{
		enabled: true,
		digest:  "sha256:test-digest",
		files:   map[string][]byte{schemaBundlePath: fixtureSchemaJSON},
	}
	h := NewSchemaHandler(mgr)
	req := httptest.NewRequest(http.MethodHead, "/sts/v1/trust-policy.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD returned body of %d bytes, want 0", w.Body.Len())
	}
	if w.Header().Get("ETag") == "" {
		t.Errorf("HEAD missing ETag")
	}
}

// TestSchema_BundleDisabled_503 counter-validates that an unconfigured
// bundle yields a clear 503 with a distinct code, not a 200 with a
// fallback schema. A baked-in fallback would defeat the
// bundle-as-source-of-truth property the design depends on.
func TestSchema_BundleDisabled_503(t *testing.T) {
	h := NewSchemaHandler(bundle.Disabled{})
	req := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Errorf("Retry-After missing on 503")
	}
	resp := decodeErr(t, w.Body.Bytes())
	if resp.Code != codeBundleDisabled {
		t.Errorf("code = %q, want %q", resp.Code, codeBundleDisabled)
	}
}

// TestSchema_BundleHasNoSchema_503 counter-validates the
// contract-violation alarm: bundle is loaded but doesn't ship the
// schema at the conventional path. This is the signal that a customer
// fork forgot to include /data/sts/v1/trust-policy.json in their
// bundle. Surfaces as a distinct code so it can be alerted on
// separately from the disabled case.
func TestSchema_BundleHasNoSchema_503(t *testing.T) {
	mgr := &fakeFileManager{
		enabled: true,
		digest:  "sha256:noschema-digest",
		files:   map[string][]byte{}, // no schema in the bundle
	}
	h := NewSchemaHandler(mgr)
	req := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	resp := decodeErr(t, w.Body.Bytes())
	if resp.Code != codeSchemaMissing {
		t.Errorf("code = %q, want %q", resp.Code, codeSchemaMissing)
	}
}

// TestSchema_BundleSchemaNotJSON_503 counter-validates that the
// broker refuses to serve non-JSON bytes as application/schema+json.
// Without this check, a producer who accidentally shipped a
// .yaml-formatted schema file at the JSON path would see IDEs
// silently break with no clear signal.
func TestSchema_BundleSchemaNotJSON_503(t *testing.T) {
	mgr := &fakeFileManager{
		enabled: true,
		digest:  "sha256:badjson-digest",
		files:   map[string][]byte{schemaBundlePath: []byte("not valid json {")},
	}
	h := NewSchemaHandler(mgr)
	req := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	resp := decodeErr(t, w.Body.Bytes())
	if resp.Code != codeSchemaInvalid {
		t.Errorf("code = %q, want %q", resp.Code, codeSchemaInvalid)
	}
}

// TestSchema_ETagDeterministic counter-validates that two requests
// against the same loaded bundle return the same ETag — necessary for
// IDE / proxy caching to work — and that a request against a
// different digest returns a different ETag.
func TestSchema_ETagDeterministic(t *testing.T) {
	mk := func(digest string) http.Handler {
		mgr := &fakeFileManager{
			enabled: true,
			digest:  digest,
			files:   map[string][]byte{schemaBundlePath: fixtureSchemaJSON},
		}
		return NewSchemaHandler(mgr)
	}
	get := func(h http.Handler) string {
		req := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Header().Get("ETag")
	}

	a1 := get(mk("sha256:A"))
	a2 := get(mk("sha256:A"))
	b := get(mk("sha256:B"))

	if a1 == "" || a2 == "" || b == "" {
		t.Fatalf("missing ETag(s): a1=%q a2=%q b=%q", a1, a2, b)
	}
	if a1 != a2 {
		t.Errorf("same digest returned different ETags: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Errorf("different digests returned same ETag: %q", a1)
	}
}

// TestSchema_IfNoneMatch_304 counter-validates that an IDE polling
// with the previous ETag gets 304 Not Modified, avoiding a body
// transfer.
func TestSchema_IfNoneMatch_304(t *testing.T) {
	mgr := &fakeFileManager{
		enabled: true,
		digest:  "sha256:cache-test",
		files:   map[string][]byte{schemaBundlePath: fixtureSchemaJSON},
	}
	h := NewSchemaHandler(mgr)

	// First request: capture ETag.
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil))
	etag := w1.Header().Get("ETag")
	if etag == "" || w1.Code != http.StatusOK {
		t.Fatalf("first GET status=%d etag=%q", w1.Code, etag)
	}

	// Second request: send If-None-Match → 304.
	req2 := httptest.NewRequest(http.MethodGet, "/sts/v1/trust-policy.json", nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotModified {
		t.Errorf("conditional GET status = %d, want 304", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Errorf("304 response carried body of %d bytes", w2.Body.Len())
	}
}

// TestSchema_MethodNotAllowed counter-validates that POST/PUT/DELETE
// to the schema route return 405 — schema is read-only.
func TestSchema_MethodNotAllowed(t *testing.T) {
	h := NewSchemaHandler(bundle.Disabled{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/sts/v1/trust-policy.json", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", method, w.Code)
			}
		})
	}
}
