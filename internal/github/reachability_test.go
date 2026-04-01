package github

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestClassifyNetError_Timeout(t *testing.T) {
	err := context.DeadlineExceeded
	if got := classifyNetError(err); got != "timeout" {
		t.Errorf("expected timeout, got %s", got)
	}
}

func TestClassifyNetError_ConnectionError(t *testing.T) {
	err := errors.New("connection refused")
	if got := classifyNetError(err); got != "connection_error" {
		t.Errorf("expected connection_error, got %s", got)
	}
}

func TestClassifyNetError_NetTimeout(t *testing.T) {
	err := &net.DNSError{IsTimeout: true}
	if got := classifyNetError(err); got != "timeout" {
		t.Errorf("expected timeout, got %s", got)
	}
}

func TestReachabilityProber_StartStop(t *testing.T) {
	prober := NewReachabilityProber(nil, "http://localhost", 10*60*1e9)
	prober.Start()
	prober.Stop()
}
