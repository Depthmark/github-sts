package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLogger_WritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	fl, err := NewFileLogger(path, 10, nil)
	if err != nil {
		t.Fatal(err)
	}

	fl.Log(Event{
		Scope:    "myorg/myrepo",
		AppName:  "default",
		Identity: "ci",
		Issuer:   "https://token.actions.githubusercontent.com",
		Subject:  "repo:myorg/myrepo:ref:refs/heads/main",
		Result:   ResultSuccess,
	})

	if err := fl.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("JSON unmarshal error: %v\ndata: %s", err, data)
	}
	if event.Scope != "myorg/myrepo" {
		t.Errorf("scope = %q, want myorg/myrepo", event.Scope)
	}
	if event.Result != ResultSuccess {
		t.Errorf("result = %q, want success", event.Result)
	}
	if event.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

func TestFileLogger_OmitEmptyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	fl, err := NewFileLogger(path, 10, nil)
	if err != nil {
		t.Fatal(err)
	}

	fl.Log(Event{
		Scope:   "org",
		Result:  ResultPolicyDenied,
		Issuer:  "x",
		Subject: "y",
	})
	_ = fl.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// error_reason should not appear in JSON when empty.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}
	if _, ok := raw["error_reason"]; ok {
		t.Error("error_reason should be omitted when empty")
	}
}

func TestFileLogger_NonBlockingOnFullChannel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	// Buffer size of 1 — second event should be dropped without blocking.
	fl, err := NewFileLogger(path, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Fill the channel.
	fl.Log(Event{Scope: "first", Result: ResultSuccess, Issuer: "a", Subject: "b"})

	// This should not block — dropped if channel is full.
	done := make(chan struct{})
	go func() {
		fl.Log(Event{Scope: "second", Result: ResultSuccess, Issuer: "a", Subject: "b"})
		close(done)
	}()

	select {
	case <-done:
		// Good — non-blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Log() blocked on full channel")
	}

	_ = fl.Close()
}

func TestFileLogger_CloseDrains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	fl, err := NewFileLogger(path, 100, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		fl.Log(Event{Scope: "test", Result: ResultSuccess, Issuer: "i", Subject: "s"})
	}

	if err := fl.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Count JSON lines.
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 5 {
		t.Errorf("expected 5 JSON lines, got %d", lines)
	}
}

func TestFileLogger_NilPath(t *testing.T) {
	// No file — events only go to slog.
	fl, err := NewFileLogger("", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	fl.Log(Event{Scope: "test", Result: ResultSuccess, Issuer: "i", Subject: "s"})
	if err := fl.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTruncateJTI(t *testing.T) {
	if got := TruncateJTI("short", 50); got != "short" {
		t.Errorf("short JTI unchanged: got %q", got)
	}
	long := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	if got := TruncateJTI(long, 50); len(got) != 50 {
		t.Errorf("long JTI truncated: got len %d, want 50", len(got))
	}
}

func TestTruncateUserAgent(t *testing.T) {
	if got := TruncateUserAgent("curl/7.88", 100); got != "curl/7.88" {
		t.Errorf("short UA unchanged: got %q", got)
	}
	long := ""
	for i := 0; i < 120; i++ {
		long += "x"
	}
	if got := TruncateUserAgent(long, 100); len(got) != 100 {
		t.Errorf("long UA truncated: got len %d, want 100", len(got))
	}
}
