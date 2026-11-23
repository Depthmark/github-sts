package handler

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/depthmark/github-sts/internal/github"
	"github.com/depthmark/github-sts/internal/help"
)

// TestHelp_EveryCodeHasEveryLanguage reads this package's source, so a new
// Code or Diagnostic constant without help text in every language fails here
// instead of reaching a caller with no help.
func TestHelp_EveryCodeHasEveryLanguage(t *testing.T) {
	codes := codeConstants(t)
	for _, name := range []string{"CodeBadRequest", "CodeUpstream", "DiagnosticUnknownField"} {
		if _, ok := codes[name]; !ok {
			t.Fatalf("source scan missed %s; found %v", name, slices.Sorted(maps.Keys(codes)))
		}
	}
	for name, code := range codes {
		for _, lang := range []help.Language{help.English, help.French} {
			if help.For(code, []help.Language{lang})[lang] == "" {
				t.Errorf("%s (%q) has no %s help text in internal/help", name, code, lang)
			}
		}
	}
}

// codeConstants returns every constant named Code* or Diagnostic* in this
// package's non-test files, by name, with its string value.
func codeConstants(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package files: %v", err)
	}
	fset := token.NewFileSet()
	codes := make(map[string]string)
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				values, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range values.Names {
					if !strings.HasPrefix(ident.Name, "Code") && !strings.HasPrefix(ident.Name, "Diagnostic") {
						continue
					}
					if i >= len(values.Values) {
						t.Fatalf("%s: %s has no value of its own", file, ident.Name)
					}
					lit, ok := values.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: %s is not a string literal", file, ident.Name)
					}
					code, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: unquoting %s: %v", file, ident.Name, err)
					}
					codes[ident.Name] = code
				}
			}
		}
	}
	return codes
}

// helpLanguageCases are the Accept-Language values each endpoint is checked
// against, with the languages and Content-Language they must produce.
var helpLanguageCases = []struct {
	name            string
	acceptLanguage  string
	want            []help.Language
	contentLanguage string
}{
	{name: "no header", acceptLanguage: "", want: []help.Language{help.English}, contentLanguage: "en"},
	{name: "wildcard", acceptLanguage: "*", want: []help.Language{help.English}, contentLanguage: "en"},
	{name: "unsupported language", acceptLanguage: "de", want: []help.Language{help.English}, contentLanguage: "en"},
	{name: "French with a region", acceptLanguage: "fr-CA", want: []help.Language{help.French}, contentLanguage: "fr"},
	{name: "bilingual", acceptLanguage: "en, fr", want: []help.Language{help.English, help.French}, contentLanguage: "en, fr"},
	{name: "French preferred", acceptLanguage: "fr, en;q=0.9", want: []help.Language{help.French}, contentLanguage: "fr"},
}

func TestExchange_HelpFollowsAcceptLanguage(t *testing.T) {
	endpoints := []struct {
		name   string
		status int
		code   string
		serve  func(acceptLanguage string) *httptest.ResponseRecorder
	}{
		{
			name: "bad request", status: http.StatusBadRequest, code: CodeBadRequest,
			serve: func(acceptLanguage string) *httptest.ResponseRecorder {
				h, _ := newTestHandler(true, nil, nil, nil)
				req := httptest.NewRequest(http.MethodGet, "/sts/exchange", nil)
				return serveWithLanguage(h, req, acceptLanguage)
			},
		},
		{
			name: "policy denied", status: http.StatusForbidden, code: CodePolicyDenied,
			serve: func(acceptLanguage string) *httptest.ResponseRecorder {
				app := &mockExchangeApp{target: github.TargetIdentity{
					Scope: "org/target", Owner: "org", OwnerID: "1001", Repository: "target", RepositoryID: "3001",
				}}
				loader := &mockPolicyLoader{pol: validExchangePolicy("9999", "3001")}
				h := authorizedExchangeHandler(app, loader, &recordingAuditLogger{})
				return serveWithLanguage(h, authorizedExchangeRequest(), acceptLanguage)
			},
		},
	}
	for _, endpoint := range endpoints {
		baseline := decodeErrorResponse(t, endpoint.serve(""))
		for _, tt := range helpLanguageCases {
			t.Run(endpoint.name+"/"+tt.name, func(t *testing.T) {
				w := endpoint.serve(tt.acceptLanguage)
				assertErrorCode(t, w, endpoint.status, endpoint.code)
				resp := decodeErrorResponse(t, w)
				if resp.Error != baseline.Error || resp.TraceID != baseline.TraceID {
					t.Fatalf("error, trace_id = %q, %q, want %q, %q", resp.Error, resp.TraceID, baseline.Error, baseline.TraceID)
				}
				assertHelp(t, resp.Help, endpoint.code, tt.want)
				assertHelpHeaders(t, w, tt.contentLanguage)
			})
		}
	}
}

func TestPolicyValidation_HelpFollowsAcceptLanguage(t *testing.T) {
	serve := func(acceptLanguage string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sts/v1/trust-policy/validate", bytes.NewReader([]byte("issuer: [")))
		return serveWithLanguage(NewPolicyValidationHandler(), req, acceptLanguage)
	}
	baseline := decodeValidationResponse(t, serve("").Body.Bytes())
	for _, tt := range helpLanguageCases {
		t.Run(tt.name, func(t *testing.T) {
			w := serve(tt.acceptLanguage)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusUnprocessableEntity, w.Body.String())
			}
			resp := decodeValidationResponse(t, w.Body.Bytes())
			if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Code != DiagnosticYAMLParseError {
				t.Fatalf("diagnostics = %+v, want one %s", resp.Diagnostics, DiagnosticYAMLParseError)
			}
			if got, want := resp.Diagnostics[0].Message, baseline.Diagnostics[0].Message; got != want {
				t.Fatalf("message = %q, want %q", got, want)
			}
			assertHelp(t, resp.Diagnostics[0].Help, DiagnosticYAMLParseError, tt.want)
			assertHelpHeaders(t, w, tt.contentLanguage)
		})
	}
}

func TestPolicyValidation_ValidPolicyCarriesNoHelp(t *testing.T) {
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
	w := serveWithLanguage(NewPolicyValidationHandler(), req, "fr")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"help"`) {
		t.Fatalf("body = %s, want no help field", w.Body.String())
	}
	if got := w.Header().Get("Content-Language"); got != "" {
		t.Fatalf("Content-Language = %q, want none", got)
	}
}

func serveWithLanguage(h http.Handler, req *http.Request, acceptLanguage string) *httptest.ResponseRecorder {
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, w.Body.String())
	}
	return resp
}

func assertHelp(t *testing.T, got help.Text, code string, want []help.Language) {
	t.Helper()
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Fatalf("help languages = %v, want %v", keys, want)
	}
	for _, lang := range want {
		if wantText := help.For(code, []help.Language{lang})[lang]; got[lang] != wantText {
			t.Fatalf("help[%s] = %q, want %q", lang, got[lang], wantText)
		}
	}
}

func assertHelpHeaders(t *testing.T, w *httptest.ResponseRecorder, contentLanguage string) {
	t.Helper()
	if got := w.Header().Get("Content-Language"); got != contentLanguage {
		t.Fatalf("Content-Language = %q, want %q", got, contentLanguage)
	}
	if got := w.Header().Values("Vary"); !slices.Contains(got, "Accept-Language") {
		t.Fatalf("Vary = %v, want Accept-Language", got)
	}
}
