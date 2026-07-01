package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func uid() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("RELAY_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set RELAY_TEST_REDIS_URL to run ratelimit Redis tests")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	c := redis.NewClient(opt)
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestFallbackOnRedisDown(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	// Tiny refill rate so the burst-exhaustion assertion is deterministic even
	// though slow Redis dial failures add wall-clock time between calls.
	l := New(rdb, Config{Rate: 0.001, Burst: 2, DailyQuota: 100, CoarseRate: 1, CoarseBurst: 1, BucketIdleTTL: time.Minute})
	acct := "acct-" + uid()
	ctx := context.Background()

	r1 := l.CheckAccount(ctx, acct)
	if !r1.Allowed || !r1.Degraded {
		t.Fatalf("first fallback call = %+v, want allowed+degraded", r1)
	}
	if !l.CheckAccount(ctx, acct).Allowed {
		t.Fatal("second fallback call should be allowed (burst 2)")
	}
	r3 := l.CheckAccount(ctx, acct)
	if r3.Allowed {
		t.Fatalf("third fallback call should be denied (burst exhausted): %+v", r3)
	}
	if !r3.Degraded {
		t.Error("denied fallback should still report degraded")
	}
}

func TestTokenBucketRedis(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, Config{Rate: 1, Burst: 2, DailyQuota: 1000, CoarseRate: 1, CoarseBurst: 1, BucketIdleTTL: time.Minute})
	acct := "acct-" + uid()
	ctx := context.Background()

	if !l.CheckAccount(ctx, acct).Allowed {
		t.Fatal("call 1 should be allowed")
	}
	if !l.CheckAccount(ctx, acct).Allowed {
		t.Fatal("call 2 should be allowed (burst 2)")
	}
	r := l.CheckAccount(ctx, acct)
	if r.Allowed {
		t.Fatalf("call 3 should be denied: %+v", r)
	}
	if r.Limit != "account" {
		t.Errorf("limit = %q, want account", r.Limit)
	}
	if r.RetryAfter <= 0 {
		t.Error("expected a positive Retry-After on denial")
	}
}

func TestDailyQuotaRedis(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, Config{Rate: 1000, Burst: 1000, DailyQuota: 3, CoarseRate: 1, CoarseBurst: 1, BucketIdleTTL: time.Minute})
	acct := "acct-" + uid()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if !l.CheckAccount(ctx, acct).Allowed {
			t.Fatalf("call %d should be within daily quota", i+1)
		}
	}
	r := l.CheckAccount(ctx, acct)
	if r.Allowed || r.Limit != "daily" {
		t.Fatalf("4th call should be daily-denied: %+v", r)
	}
}

func TestCheckTokenRedis(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, DefaultConfig()) // coarse: 1 per 3s, burst 1
	acct := "acct-" + uid()
	th := "tok-" + uid()
	ctx := context.Background()

	if !l.CheckToken(ctx, acct, th).Allowed {
		t.Fatal("first per-token call should be allowed")
	}
	if l.CheckToken(ctx, acct, th).Allowed {
		t.Fatal("second per-token call within the window should be denied")
	}
}
