package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPolicyValidationHandler_ValidRawYAML(t *testing.T) {
	body := []byte(`issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: repo:org@123456/repo@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
`)
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp PolicyValidationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("valid = false, diagnostics=%+v", resp.Diagnostics)
	}
	if resp.Formatted == "" {
		t.Fatalf("formatted YAML missing")
	}
}

func TestPolicyValidationHandler_JSONRequest(t *testing.T) {
	payload := PolicyValidationRequest{Content: `issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: repo:org@123456/repo@456789:ref:refs/heads/main
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
`}
	buf, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestPolicyValidationHandler_InvalidYAML(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewBufferString("not: [valid: yaml"))
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	resp := decodeValidationResponse(t, w.Body.Bytes())
	if resp.Valid || resp.Diagnostics[0].Code != "yaml_parse_error" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestPolicyValidationHandler_UnknownFieldAndSubjectConflict(t *testing.T) {
	body := `issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: repo:org@123456/repo@456789:ref:refs/heads/main
subject_pattern: repo:org@123456/repo@456789:.*
unexpected: true
github:
  sources:
    - owner_id: "123456"
      repository_id: "456789"
  target:
    owner_id: "123456"
    repository_id: "456789"
permissions:
  contents: read
`
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	resp := decodeValidationResponse(t, w.Body.Bytes())
	if !hasDiagnostic(resp, "unknown_field") || !hasDiagnostic(resp, "subject_conflict") {
		t.Fatalf("expected unknown_field and subject_conflict diagnostics, got %+v", resp.Diagnostics)
	}
}

func TestPolicyValidationHandler_RequiresGitHubRelationship(t *testing.T) {
	body := `issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: repo:org@123456/repo@456789:ref:refs/heads/main
permissions:
  contents: read
`
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if resp := decodeValidationResponse(t, w.Body.Bytes()); !hasDiagnostic(resp, "policy_validation_error") {
		t.Fatalf("expected policy_validation_error, got %+v", resp.Diagnostics)
	}
}

func TestPolicyValidationHandler_RejectsRepositories(t *testing.T) {
	body := `issuer: https://issuer.example.com
audience: https://sts.example.com
subject: workload-1
repositories:
  - repo-a
permissions:
  contents: read
`
	req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	NewPolicyValidationHandler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if resp := decodeValidationResponse(t, w.Body.Bytes()); !hasDiagnostic(resp, "repositories_unsupported") {
		t.Fatalf("expected repositories_unsupported, got %+v", resp.Diagnostics)
	}
}

func decodeValidationResponse(t *testing.T, body []byte) PolicyValidationResponse {
	t.Helper()
	var resp PolicyValidationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	return resp
}

func hasDiagnostic(resp PolicyValidationResponse, code string) bool {
	for _, d := range resp.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}

// The trust-policy field list is written down three times: the yaml tags on
// policy.TrustPolicy, the published JSON Schema's top-level properties, and
// the known map in lintPolicyShape. The first two are pinned to each other by
// tests in internal/policy. This pins the third.
//
// The failure this prevents is quiet. A field added to the struct and the
// schema but not to lintPolicyShape makes the validation endpoint report
// "unknown trust policy field" for a field the exchange path accepts, so the
// endpoint tells users their working policy is broken.
func TestLintPolicyShapeKnownFieldsMatchSchema(t *testing.T) {
	raw, err := os.ReadFile("../policy/yaml/schema_v1.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if len(schema.Properties) == 0 {
		t.Fatal("schema has no top-level properties")
	}

	// lintPolicyShape owns the list; reach for it the same way the handler
	// does rather than restating it here, or this test pins a copy.
	known := knownPolicyFields()

	for field := range schema.Properties {
		if !known[field] {
			t.Errorf("schema declares %q but lintPolicyShape rejects it as unknown", field)
		}
	}
	for field := range known {
		if _, ok := schema.Properties[field]; !ok {
			// repositories is the deliberate exception: lintPolicyShape
			// recognises it in order to emit a specific diagnostic saying it
			// is unsupported, while the schema omits it so
			// additionalProperties:false rejects it outright.
			if field == "repositories" {
				continue
			}
			t.Errorf("lintPolicyShape accepts %q but the schema omits it", field)
		}
	}
}
