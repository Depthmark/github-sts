package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCheckPromotion(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name:    "release allowed",
			args:    []string{"check-promotion", "--mode=release", "--current-revision=41", "--current-digest=" + digestA, "--candidate-revision=42", "--candidate-digest=" + digestB},
			wantOut: `"allowed":true`,
		},
		{
			name:    "deployment no-op allowed",
			args:    []string{"check-promotion", "--mode=deployment", "--current-revision=41", "--current-digest=" + digestA, "--candidate-revision=41", "--candidate-digest=" + digestA},
			wantOut: `"allowed":true`,
		},
		{
			name:     "rollback rejected",
			args:     []string{"check-promotion", "--mode=deployment", "--current-revision=41", "--current-digest=" + digestA, "--candidate-revision=40", "--candidate-digest=" + digestB},
			wantCode: 1,
			wantErr:  "rollback",
		},
		{
			name:     "usage",
			wantCode: 2,
			wantErr:  "usage:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr=%s", code, tt.wantCode, stderr.String())
			}
			if tt.wantOut != "" && !strings.Contains(stdout.String(), tt.wantOut) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if tt.wantErr != "" && !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}
