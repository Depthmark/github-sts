package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyValidationHandler_ValidRawYAML(t *testing.T) {
	body := []byte(`issuer: https://token.actions.githubusercontent.com
audience: https://sts.example.com
subject: repo:org/repo:ref:refs/heads/main
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
subject: repo:org/repo:ref:refs/heads/main
subject_pattern: repo:org/repo:.*
unexpected: true
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
