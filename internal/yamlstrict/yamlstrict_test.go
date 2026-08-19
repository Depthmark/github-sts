package yamlstrict

import (
	"strings"
	"testing"
)

type testConfig struct {
	Nested struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"nested"`
}

func TestDecode(t *testing.T) {
	var config testConfig
	if err := Decode([]byte("nested:\n  enabled: true\n"), &config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !config.Nested.Enabled {
		t.Fatal("enabled was not decoded")
	}
}

func TestDecodeRejectsUnsafeShapes(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "unknown top level", content: "typo: true\n", want: "field typo not found"},
		{name: "unknown nested", content: "nested:\n  typo: true\n", want: "field typo not found"},
		{name: "duplicate", content: "nested:\n  enabled: true\n  enabled: false\n", want: "already defined"},
		{name: "multiple documents", content: "nested: {}\n---\nnested: {}\n", want: "multiple YAML documents"},
		{name: "empty", content: "", want: "document is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config testConfig
			err := Decode([]byte(tt.content), &config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
