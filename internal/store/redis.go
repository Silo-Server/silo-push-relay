package store

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// OpenRedis parses a redis:// (or rediss://) URL and returns a client. Like the
// pgx pool it connects lazily; use the returned client's Ping for readiness.
//
// Operational note (spec §9.1): idempotency requires a non-evicting keyspace so
// an in-flight lock is never silently evicted. In production, point the relay at
// a Redis configured with maxmemory-policy noeviction (or a dedicated DB for the
// idempotency keyspace). The client does not enforce this; it is a deployment
// requirement.
func OpenRedis(ctx context.Context, url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("store: parse redis url: %w", err)
	}
	return redis.NewClient(opt), nil
}
