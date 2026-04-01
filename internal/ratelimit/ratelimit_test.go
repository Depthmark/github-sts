package ratelimit

import (
	"testing"
)

func TestAllow_BelowBurst(t *testing.T) {
	l, err := New(10, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed (within burst)", i)
		}
	}
}

func TestAllow_ExceedsBurst(t *testing.T) {
	l, err := New(1, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	l.Allow("1.2.3.4") // 1
	l.Allow("1.2.3.4") // 2 (burst exhausted)

	if l.Allow("1.2.3.4") {
		t.Fatal("third request should be rate limited")
	}
}

func TestAllow_ExemptCIDR(t *testing.T) {
	l, err := New(1, 1, []string{"10.0.0.0/8", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// Exhaust the bucket for a non-exempt IP.
	l.Allow("1.2.3.4")
	if l.Allow("1.2.3.4") {
		t.Fatal("non-exempt IP should be rate limited")
	}

	// Exempt IP is always allowed.
	for i := 0; i < 100; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("exempt IP should never be rate limited (iteration %d)", i)
		}
	}
}

func TestAllow_ExemptCIDR_IPv6(t *testing.T) {
	l, err := New(1, 1, []string{"fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	for i := 0; i < 100; i++ {
		if !l.Allow("fd12::1") {
			t.Fatalf("exempt IPv6 should never be rate limited (iteration %d)", i)
		}
	}
}

func TestAllow_DifferentIPsIndependent(t *testing.T) {
	l, err := New(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// Exhaust bucket for IP A.
	l.Allow("1.1.1.1")
	if l.Allow("1.1.1.1") {
		t.Fatal("IP A should be rate limited")
	}

	// IP B should still be allowed (separate bucket).
	if !l.Allow("2.2.2.2") {
		t.Fatal("IP B should not be affected by IP A's limit")
	}
}

func TestNew_InvalidCIDR(t *testing.T) {
	_, err := New(10, 5, []string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestAllow_UnparseableIP(t *testing.T) {
	l, err := New(10, 5, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// Unparseable IP should not be exempt.
	if !l.Allow("not-an-ip") {
		t.Fatal("unparseable IP should still go through rate limiter (within burst)")
	}
}
