// Package jti provides JTI (JWT ID) replay prevention caches.
//
// Two backends are supported: in-memory (for single-instance deployments)
// and Redis (for multi-instance deployments). Both implement the Cache
// interface with atomic reserve semantics.
package jti

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache is the interface for JTI replay prevention.
//
// Reserve atomically checks whether the JTI has been seen and, if new,
// stores it so concurrent requests with the same JTI are rejected.
// Returns (true, nil) if the JTI is new and has been reserved,
// (false, nil) if already seen, or (false, error) on backend failure
// (fail-closed).
//
// Release removes a previously reserved JTI from the cache. This should
// be called when a downstream operation fails after a successful Reserve,
// allowing the client to retry with the same OIDC token.
type Cache interface {
	Reserve(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
	Release(ctx context.Context, jti string) error
}

// CacheError wraps backend errors (Redis connection failures, etc.).
type CacheError struct {
	Err error
}

func (e *CacheError) Error() string {
	return fmt.Sprintf("jti cache error: %v", e.Err)
}

func (e *CacheError) Unwrap() error {
	return e.Err
}

// InMemoryCache stores JTIs in a map protected by sync.Mutex.
// Suitable for single-instance deployments.
type InMemoryCache struct {
	ttl     time.Duration
	entries map[string]time.Time // jti → expiresAt
	mu      sync.Mutex
}

// NewInMemoryCache creates an in-memory JTI cache with the given default TTL.
func NewInMemoryCache(ttl time.Duration) *InMemoryCache {
	return &InMemoryCache{
		ttl:     ttl,
		entries: make(map[string]time.Time),
	}
}

// Reserve atomically checks whether the JTI has been seen and stores it
// if new. Performs opportunistic cleanup of expired entries on each call.
func (c *InMemoryCache) Reserve(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Opportunistic cleanup of expired entries.
	for k, exp := range c.entries {
		if exp.Before(now) {
			delete(c.entries, k)
		}
	}

	if _, exists := c.entries[jti]; exists {
		return false, nil
	}

	// Store immediately to prevent concurrent duplicates.
	deadline := now.Add(c.ttl)
	tokenDeadline := expiresAt.Add(1 * time.Second)
	if tokenDeadline.After(deadline) {
		deadline = tokenDeadline
	}
	c.entries[jti] = deadline
	return true, nil
}

// Release removes a previously reserved JTI, allowing the OIDC token
// to be retried after a transient downstream failure.
func (c *InMemoryCache) Release(_ context.Context, jti string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, jti)
	return nil
}

// RedisCache stores JTIs in Redis using SET NX EX for atomic check-and-store.
// Suitable for multi-instance deployments. Fail-closed on errors.
type RedisCache struct {
	client    *redis.Client
	ttl       time.Duration
	keyPrefix string
}

// NewRedisCache creates a Redis-backed JTI cache.
func NewRedisCache(client *redis.Client, ttl time.Duration) *RedisCache {
	return &RedisCache{
		client:    client,
		ttl:       ttl,
		keyPrefix: "sts:jti:",
	}
}

// Reserve atomically checks and stores the JTI using Redis SETNX.
// Fail-closed on errors.
func (c *RedisCache) Reserve(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	key := c.keyPrefix + jti

	// Compute TTL: max(configuredTTL, tokenExpiry - now + 1s).
	ttl := c.ttl
	tokenTTL := time.Until(expiresAt) + 1*time.Second
	if tokenTTL > ttl {
		ttl = tokenTTL
	}

	ok, err := c.client.SetNX(ctx, key, "1", ttl).Result() //nolint:staticcheck // SetNX is clear and works; migrate to Set+NX later
	if err != nil {
		return false, &CacheError{Err: err}
	}
	return ok, nil
}

// Release removes a previously reserved JTI from Redis, allowing the
// OIDC token to be retried after a transient downstream failure.
func (c *RedisCache) Release(ctx context.Context, jti string) error {
	key := c.keyPrefix + jti
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return &CacheError{Err: err}
	}
	return nil
}
