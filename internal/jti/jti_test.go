package jti

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestInMemoryCache_NewJTI(t *testing.T) {
	c := NewInMemoryCache(5 * time.Minute)
	ctx := context.Background()
	exp := time.Now().Add(10 * time.Minute)

	ok, err := c.Reserve(ctx, "jti-1", exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected new JTI to be accepted")
	}
}

func TestInMemoryCache_ReplayDetection(t *testing.T) {
	c := NewInMemoryCache(5 * time.Minute)
	ctx := context.Background()
	exp := time.Now().Add(10 * time.Minute)

	// Reserve — should be new.
	ok, _ := c.Reserve(ctx, "jti-dup", exp)
	if !ok {
		t.Fatal("first reserve should report new")
	}

	// Second reserve is replay (atomically stored by first Reserve).
	ok, err := c.Reserve(ctx, "jti-dup", exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("replay should be detected")
	}
}

func TestInMemoryCache_OpportunisticCleanup(t *testing.T) {
	c := NewInMemoryCache(1 * time.Millisecond)
	ctx := context.Background()

	// Reserve a JTI with very short TTL.
	_, _ = c.Reserve(ctx, "old-jti", time.Now().Add(-1*time.Second))

	// Wait for it to expire.
	time.Sleep(5 * time.Millisecond)

	// Next call should clean up expired entry.
	_, _ = c.Reserve(ctx, "new-jti", time.Now().Add(10*time.Minute))

	c.mu.Lock()
	_, oldExists := c.entries["old-jti"]
	c.mu.Unlock()

	if oldExists {
		t.Fatal("expired entry should have been cleaned up")
	}
}

func TestInMemoryCache_TTLComputation(t *testing.T) {
	c := NewInMemoryCache(1 * time.Minute)
	ctx := context.Background()

	// Token expires in 10 minutes — cache entry should use token expiry + 1s.
	tokenExpiry := time.Now().Add(10 * time.Minute)
	_, _ = c.Reserve(ctx, "jti-ttl", tokenExpiry)

	c.mu.Lock()
	deadline := c.entries["jti-ttl"]
	c.mu.Unlock()

	// Deadline should be close to tokenExpiry + 1s (not configuredTTL of 1min).
	expected := tokenExpiry.Add(1 * time.Second)
	diff := deadline.Sub(expected)
	if diff < -100*time.Millisecond || diff > 100*time.Millisecond {
		t.Fatalf("deadline %v should be close to %v (diff: %v)", deadline, expected, diff)
	}
}

func TestInMemoryCache_ReserveAndRelease(t *testing.T) {
	c := NewInMemoryCache(5 * time.Minute)
	ctx := context.Background()
	exp := time.Now().Add(10 * time.Minute)

	// Reserve the JTI.
	ok, _ := c.Reserve(ctx, "jti-retry", exp)
	if !ok {
		t.Fatal("first reserve should report new")
	}

	// Second reserve should detect replay (atomic reservation).
	ok, _ = c.Reserve(ctx, "jti-retry", exp)
	if ok {
		t.Fatal("second reserve should detect replay")
	}

	// Release allows retrying with the same JTI.
	if err := c.Release(ctx, "jti-retry"); err != nil {
		t.Fatalf("unexpected release error: %v", err)
	}

	// After release, the JTI should be new again.
	ok, _ = c.Reserve(ctx, "jti-retry", exp)
	if !ok {
		t.Fatal("reserve after release should report new")
	}
}

func TestInMemoryCache_ConcurrentAccess(t *testing.T) {
	c := NewInMemoryCache(5 * time.Minute)
	ctx := context.Background()
	exp := time.Now().Add(10 * time.Minute)

	const goroutines = 100
	results := make([]bool, goroutines)
	var wg sync.WaitGroup

	// All goroutines try to reserve the same JTI.
	// With atomic Reserve, exactly one should succeed.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			ok, err := c.Reserve(ctx, "same-jti", exp)
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", idx, err)
				return
			}
			results[idx] = ok
		}(i)
	}
	wg.Wait()

	// Exactly one goroutine should have succeeded.
	successCount := 0
	for _, ok := range results {
		if ok {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successCount)
	}
}

func TestCacheError_Wrapping(t *testing.T) {
	inner := errors.New("connection refused")
	ce := &CacheError{Err: inner}

	if ce.Error() != "jti cache error: connection refused" {
		t.Fatalf("unexpected error message: %s", ce.Error())
	}

	if !errors.Is(ce, inner) {
		t.Fatal("CacheError should unwrap to inner error")
	}
}
