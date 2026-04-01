package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeToken_204Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/installation/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer ghs_test" {
			t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("unexpected Accept: %s", r.Header.Get("Accept"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := RevokeToken(context.Background(), "ghs_test", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevokeToken_401AlreadyRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := RevokeToken(context.Background(), "ghs_expired", srv.URL)
	if err != nil {
		t.Fatalf("expected nil error for 401, got: %v", err)
	}
}

func TestRevokeToken_404AlreadyRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := RevokeToken(context.Background(), "ghs_gone", srv.URL)
	if err != nil {
		t.Fatalf("expected nil error for 404, got: %v", err)
	}
}

func TestRevokeToken_500Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := RevokeToken(context.Background(), "ghs_test", srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "returned 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevokeToken_NetworkError(t *testing.T) {
	// Use a server that's already closed to force a connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	err := RevokeToken(context.Background(), "ghs_test", srv.URL)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}
