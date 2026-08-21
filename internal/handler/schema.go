package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/depthmark/github-sts/internal/bundle"
)

// schemaBundlePath is the conventional location of the trust-policy
// JSON Schema inside the OPA bundle tarball. Producers (forks of
// github-sts-policy) ship the schema at this path; the broker
// republishes whatever bytes it finds. The path is part of the
// contract documented in docs/org-policy.md.
const schemaBundlePath = "/data/sts/v1/trust-policy.json"

// schemaErrorCodes — distinct so operators can tell three different
// failure modes apart in audit logs and from the response body alone.
const (
	codeBundleDisabled = "bundle_disabled" // operator hasn't enabled the bundle
	codeSchemaMissing  = "schema_missing"  // bundle is loaded but doesn't ship a schema at the conventional path
	codeSchemaInvalid  = "schema_invalid"  // bundle ships bytes there but they aren't valid JSON
)

// SchemaHandler serves the trust-policy JSON Schema bundled by the
// loaded OPA bundle at GET /sts/v1/trust-policy.json. The broker is a
// passthrough: it does not interpret the schema beyond a json.Valid
// check (so it never serves non-JSON bytes as application/schema+json).
type SchemaHandler struct {
	mgr bundle.Manager
}

// NewSchemaHandler constructs a schema handler from a bundle manager.
// nil mgr is normalized to bundle.Disabled so the route still answers
// (with 503 / bundle_disabled) rather than nil-panicking.
func NewSchemaHandler(mgr bundle.Manager) *SchemaHandler {
	if mgr == nil {
		mgr = bundle.Disabled{}
	}
	return &SchemaHandler{mgr: mgr}
}

// ServeHTTP handles GET /sts/v1/trust-policy.json.
//
// Status taxonomy:
//   - 200: bundle present, schema bytes well-formed JSON. Response is
//     application/schema+json with a Cache-Control max-age=300 and an
//     ETag derived from the bundle digest + sha256 of the bytes.
//   - 503 bundle_disabled: bundle integration is off on this broker.
//   - 503 schema_missing: bundle is loaded but doesn't carry the file
//     at the conventional path. Surfaces the contract-violation
//     ("fork forgot to include the schema").
//   - 503 schema_invalid: the bytes are present but not valid JSON.
//     Counter-validates that the broker doesn't blindly republish
//     non-JSON as application/schema+json.
//
// All 503s carry Retry-After: 60 so polling IDEs back off but recover
// when the operator fixes the underlying issue (typically a bundle
// reload — Phase 2).
func (h *SchemaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed", Code: CodeMethodNotAllowed})
		return
	}

	if !h.mgr.Enabled() {
		writeSchemaUnavailable(w, http.StatusServiceUnavailable, "schema not available: bundle integration is disabled on this broker", codeBundleDisabled)
		return
	}

	body, err := h.mgr.BundleFile(schemaBundlePath)
	if err != nil {
		switch {
		case errors.Is(err, bundle.ErrFileNotFound):
			writeSchemaUnavailable(w, http.StatusServiceUnavailable, "schema not available: loaded bundle does not ship a schema at "+schemaBundlePath, codeSchemaMissing)
		case errors.Is(err, bundle.ErrDisabled):
			// Should be unreachable since we checked Enabled above, but
			// fail safely.
			writeSchemaUnavailable(w, http.StatusServiceUnavailable, "schema not available: bundle integration is disabled on this broker", codeBundleDisabled)
		default:
			writeSchemaUnavailable(w, http.StatusServiceUnavailable, "schema not available: error reading bundle file", codeSchemaMissing)
		}
		return
	}
	if !json.Valid(body) {
		writeSchemaUnavailable(w, http.StatusServiceUnavailable, "schema not available: bundle file at "+schemaBundlePath+" is not valid JSON", codeSchemaInvalid)
		return
	}

	etag := schemaETag(h.mgr.Digest(), body)
	w.Header().Set("Content-Type", "application/schema+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// writeSchemaUnavailable emits a uniform 503 envelope with the given
// code and a Retry-After hint. ErrorResponse is reused so the schema
// route mirrors the rest of the broker's error shape (operators get
// one parser for everything).
func writeSchemaUnavailable(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, status, ErrorResponse{Error: message, Code: code})
}

// schemaETag derives a strong ETag from the loaded bundle digest plus
// the sha256 of the served bytes. Using the digest ensures the ETag
// changes when the bundle reloads (Phase 2); hashing the bytes too
// means a producer that swaps the schema in-place across tags still
// invalidates IDE caches.
func schemaETag(bundleDigest string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(bundleDigest))
	h.Write([]byte{0})
	h.Write(body)
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}
