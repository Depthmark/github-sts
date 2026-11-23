// Package help holds the fixed text that tells a caller what to do about each
// error code, in English and French, and picks the languages a request asks
// for with Accept-Language (ADR 0021). The text depends on the code alone, so
// it tells a caller nothing the code does not (ADR 0012).
package help

import (
	"slices"
	"strconv"
	"strings"
)

// Language is a language github-sts writes help text in, named by its
// primary language subtag.
type Language string

// The languages the catalog carries.
const (
	English Language = "en"
	French  Language = "fr"
)

// supported lists every language the catalog carries, in the order a
// response that holds several of them uses.
var supported = []Language{English, French}

// maxLanguageRanges bounds how many Accept-Language entries Negotiate reads,
// so a long header costs a fixed amount of work. Clients send a handful.
const maxLanguageRanges = 32

// Text is help text keyed by language. It encodes as the JSON object a
// response carries in its help field, such as {"en": "...", "fr": "..."}.
type Text map[Language]string

// Negotiate returns the languages an Accept-Language header value picks: the
// supported language with the highest weight, or every supported language
// that shares that weight, so "en, fr" asks for both. A region does not
// matter ("fr-CA" is French), "*" names no language, and an entry with a
// malformed weight is skipped. When no supported language is acceptable the
// answer is English, so a caller who does not ask sees no new language.
func Negotiate(header string) []Language {
	weights := make(map[Language]float64, len(supported))
	read := 0
	for part := range strings.SplitSeq(header, ",") {
		if read == maxLanguageRanges {
			break
		}
		read++
		lang, weight, ok := parseRange(part)
		if ok && weight > weights[lang] {
			weights[lang] = weight
		}
	}

	var best float64
	for _, weight := range weights {
		best = max(best, weight)
	}
	if best == 0 {
		return []Language{English}
	}
	langs := make([]Language, 0, len(supported))
	for _, lang := range supported {
		if weights[lang] == best {
			langs = append(langs, lang)
		}
	}
	return langs
}

// parseRange reads one Accept-Language entry, such as "fr-CA;q=0.8". It
// reports false for "*", for a language the catalog does not carry and for
// a weight outside 0 to 1, which RFC 9110 does not allow.
func parseRange(part string) (Language, float64, bool) {
	tag, params, _ := strings.Cut(part, ";")
	primary, _, _ := strings.Cut(strings.TrimSpace(tag), "-")
	lang := Language(strings.ToLower(primary))
	if !slices.Contains(supported, lang) {
		return "", 0, false
	}

	weight := 1.0
	for param := range strings.SplitSeq(params, ";") {
		name, value, found := strings.Cut(param, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		// Written as a range check so NaN fails it too.
		if err != nil || !(q >= 0 && q <= 1) {
			return "", 0, false
		}
		weight = q
	}
	return lang, weight, true
}

// For returns the help for code in langs, or nil when code has none.
func For(code string, langs []Language) Text {
	entry, ok := catalog[code]
	if !ok {
		return nil
	}
	text := make(Text, len(langs))
	for _, lang := range langs {
		if s := entry[lang]; s != "" {
			text[lang] = s
		}
	}
	if len(text) == 0 {
		return nil
	}
	return text
}

// ContentLanguage formats langs as a Content-Language header value, such as
// "en, fr".
func ContentLanguage(langs []Language) string {
	names := make([]string, len(langs))
	for i, lang := range langs {
		names[i] = string(lang)
	}
	return strings.Join(names, ", ")
}
