package help

import (
	"slices"
	"strings"
	"testing"
)

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []Language
	}{
		{name: "no header defaults to English", header: "", want: []Language{English}},
		{name: "wildcard names no language", header: "*", want: []Language{English}},
		{name: "unsupported language falls back to English", header: "de", want: []Language{English}},
		{name: "English", header: "en", want: []Language{English}},
		{name: "French", header: "fr", want: []Language{French}},
		{name: "region is ignored", header: "fr-CA", want: []Language{French}},
		{name: "case is ignored", header: "FR-ca", want: []Language{French}},
		{name: "equal weights ask for both", header: "en, fr", want: []Language{English, French}},
		{name: "order of a tie does not matter", header: "fr, en", want: []Language{English, French}},
		{name: "explicit equal weights ask for both", header: "fr;q=0.7, en;q=0.7", want: []Language{English, French}},
		{name: "higher weight wins", header: "fr, en;q=0.9", want: []Language{French}},
		{name: "browser style header", header: "fr-CA,fr;q=0.9,en-US;q=0.8,en;q=0.7", want: []Language{French}},
		{name: "best region weight counts", header: "en;q=0.5, en-GB;q=0.9, fr;q=0.8", want: []Language{English}},
		{name: "wildcard does not join a tie", header: "fr, *", want: []Language{French}},
		{name: "unsupported language does not join a tie", header: "de, fr", want: []Language{French}},
		{name: "zero weight refuses a language", header: "en;q=0, fr;q=0.1", want: []Language{French}},
		{name: "only refused languages fall back to English", header: "fr;q=0", want: []Language{English}},
		{name: "weight name is case insensitive", header: "fr;Q=1, en;q=0.5", want: []Language{French}},
		{name: "malformed weight skips the entry", header: "fr;q=high, en;q=0.2", want: []Language{English}},
		{name: "weight above 1 skips the entry", header: "fr;q=2, en;q=0.2", want: []Language{English}},
		{name: "negative weight skips the entry", header: "fr;q=-1, en;q=0.2", want: []Language{English}},
		{name: "NaN weight skips the entry", header: "fr;q=NaN, en;q=0.2", want: []Language{English}},
		{name: "spaces around parts", header: "  fr ; q = 0.4 ,  en ; q = 0.3 ", want: []Language{French}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Negotiate(tt.header); !slices.Equal(got, tt.want) {
				t.Fatalf("Negotiate(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestNegotiate_ReadsABoundedNumberOfEntries(t *testing.T) {
	// French past the bound must not count, even with the highest weight.
	header := strings.Repeat("de, ", maxLanguageRanges-1) + "en;q=0.5, fr"
	if got := Negotiate(header); !slices.Equal(got, []Language{English}) {
		t.Fatalf("Negotiate = %v, want [en]", got)
	}
}

func TestFor(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		langs []Language
		want  []Language
	}{
		{name: "English", code: "policy_denied", langs: []Language{English}, want: []Language{English}},
		{name: "French", code: "policy_denied", langs: []Language{French}, want: []Language{French}},
		{name: "both", code: "policy_denied", langs: []Language{English, French}, want: []Language{English, French}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := For(tt.code, tt.langs)
			if len(got) != len(tt.want) {
				t.Fatalf("For(%q, %v) = %v, want keys %v", tt.code, tt.langs, got, tt.want)
			}
			for _, lang := range tt.want {
				if got[lang] != catalog[tt.code][lang] {
					t.Fatalf("For(%q)[%s] = %q, want %q", tt.code, lang, got[lang], catalog[tt.code][lang])
				}
			}
		})
	}
}

func TestFor_NoHelp(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		langs []Language
	}{
		{name: "empty code", code: "", langs: []Language{English}},
		{name: "unknown code", code: "not_a_code", langs: []Language{English}},
		{name: "no language", code: "policy_denied", langs: nil},
		{name: "language the catalog lacks", code: "policy_denied", langs: []Language{"de"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := For(tt.code, tt.langs); got != nil {
				t.Fatalf("For(%q, %v) = %v, want nil", tt.code, tt.langs, got)
			}
		})
	}
}

// TestCatalog_EveryEntryHasEveryLanguage fails when a code is added in one
// language only.
func TestCatalog_EveryEntryHasEveryLanguage(t *testing.T) {
	for code, entry := range catalog {
		for _, lang := range supported {
			if strings.TrimSpace(entry[lang]) == "" {
				t.Errorf("catalog[%q] has no %s text", code, lang)
			}
		}
		if len(entry) != len(supported) {
			t.Errorf("catalog[%q] has %d languages, want %d", code, len(entry), len(supported))
		}
	}
}

func TestContentLanguage(t *testing.T) {
	tests := []struct {
		langs []Language
		want  string
	}{
		{langs: []Language{English}, want: "en"},
		{langs: []Language{French}, want: "fr"},
		{langs: []Language{English, French}, want: "en, fr"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := ContentLanguage(tt.langs); got != tt.want {
				t.Fatalf("ContentLanguage(%v) = %q, want %q", tt.langs, got, tt.want)
			}
		})
	}
}
