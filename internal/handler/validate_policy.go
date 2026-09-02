package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/depthmark/github-sts/internal/policy"
	"gopkg.in/yaml.v3"
)

const maxValidationBodyBytes = 1 << 20

type PolicyValidationRequest struct {
	Content  string `json:"content"`
	Filename string `json:"filename,omitempty"`
}

type PolicyValidationResponse struct {
	Valid       bool               `json:"valid"`
	Diagnostics []PolicyDiagnostic `json:"diagnostics"`
	Formatted   string             `json:"formatted,omitempty"`
}

type PolicyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// PolicyValidationHandler validates/lints trust-policy YAML for editor tooling.
// It intentionally evaluates only the YAML policy contract; it does not read
// enterprise Rego bundles or expose exception inventory.
type PolicyValidationHandler struct{}

func NewPolicyValidationHandler() *PolicyValidationHandler { return &PolicyValidationHandler{} }

func (h *PolicyValidationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed", Code: CodeMethodNotAllowed})
		return
	}
	content, err := readValidationContent(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error(), Code: CodeBadRequest})
		return
	}
	resp := validatePolicyContent(content)
	status := http.StatusOK
	if !resp.Valid {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, resp)
}

func readValidationContent(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxValidationBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading request body: %w", err)
	}
	if len(body) > maxValidationBodyBytes {
		return "", fmt.Errorf("request body exceeds %d bytes", maxValidationBodyBytes)
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var req PolicyValidationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return "", fmt.Errorf("parsing JSON validation request: %w", err)
		}
		if strings.TrimSpace(req.Content) == "" {
			return "", fmt.Errorf("content is required")
		}
		return req.Content, nil
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", fmt.Errorf("request body is required")
	}
	return string(body), nil
}

func validatePolicyContent(content string) PolicyValidationResponse {
	diagnostics := make([]PolicyDiagnostic, 0)
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return PolicyValidationResponse{Valid: false, Diagnostics: []PolicyDiagnostic{{
			Severity: "error",
			Code:     "yaml_parse_error",
			Message:  err.Error(),
		}}}
	}
	doc := documentMapping(&root)
	if doc == nil {
		return PolicyValidationResponse{Valid: false, Diagnostics: []PolicyDiagnostic{{
			Severity: "error",
			Code:     "invalid_document",
			Message:  "trust policy must be a YAML object",
		}}}
	}
	diagnostics = append(diagnostics, lintPolicyShape(doc)...)

	pol, err := policy.ParsePolicy([]byte(content))
	if err != nil {
		diagnostics = append(diagnostics, PolicyDiagnostic{
			Severity: "error",
			Code:     "policy_validation_error",
			Message:  err.Error(),
		})
	}
	valid := true
	for _, d := range diagnostics {
		if d.Severity == "error" {
			valid = false
			break
		}
	}
	resp := PolicyValidationResponse{Valid: valid, Diagnostics: diagnostics}
	if valid && pol != nil {
		if formatted, err := yaml.Marshal(pol); err == nil {
			resp.Formatted = string(formatted)
		}
	}
	return resp
}

func documentMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

// knownPolicyFields is the set of top-level keys lintPolicyShape recognises.
// It must stay in step with the published JSON Schema's top-level properties,
// which a test in this package enforces. repositories is the one deliberate
// difference: it is listed here so the linter can emit a specific diagnostic
// explaining why it is unsupported, rather than the generic unknown-field one.
func knownPolicyFields() map[string]bool {
	return map[string]bool{
		"issuer":          true,
		"subject":         true,
		"subject_pattern": true,
		"claim_pattern":   true,
		"audience":        true,
		"github":          true,
		"repositories":    true,
		"permissions":     true,
	}
}

func lintPolicyShape(doc *yaml.Node) []PolicyDiagnostic {
	known := knownPolicyFields()
	seen := make(map[string]*yaml.Node)
	diagnostics := make([]PolicyDiagnostic, 0)
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i]
		name := key.Value
		if !known[name] {
			diagnostics = append(diagnostics, PolicyDiagnostic{
				Severity: "error",
				Code:     "unknown_field",
				Message:  fmt.Sprintf("unknown trust policy field %q", name),
				Path:     "$.",
				Line:     key.Line,
				Column:   key.Column,
			})
		}
		seen[name] = key
	}
	if _, ok := seen["subject"]; ok {
		if key := seen["subject_pattern"]; key != nil {
			diagnostics = append(diagnostics, PolicyDiagnostic{
				Severity: "error",
				Code:     "subject_conflict",
				Message:  "subject and subject_pattern are mutually exclusive",
				Path:     "$.subject_pattern",
				Line:     key.Line,
				Column:   key.Column,
			})
		}
	}
	if repos := seen["repositories"]; repos != nil {
		diagnostics = append(diagnostics, PolicyDiagnostic{
			Severity: "error",
			Code:     "repositories_unsupported",
			Message:  "repositories is unsupported while organization-level scopes are disabled; use an exact repository scope and github.target binding",
			Path:     "$.repositories",
			Line:     repos.Line,
			Column:   repos.Column,
		})
	}
	return diagnostics
}
