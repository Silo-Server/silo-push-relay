package idempotency

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
		t.Skip("set RELAY_TEST_REDIS_URL to run idempotency Redis tests")
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

func TestLifecycle(t *testing.T) {
	s := New(testRedis(t), 30*time.Second, time.Hour)
	ctx := context.Background()
	acct, key := "acct-"+uid(), "k-"+uid()

	b, err := s.Begin(ctx, acct, key, "hashA")
	if err != nil || b.Outcome != Proceed || b.Nonce == "" {
		t.Fatalf("first Begin = %+v, err %v; want Proceed with nonce", b, err)
	}

	if b2, _ := s.Begin(ctx, acct, key, "hashA"); b2.Outcome != Conflict {
		t.Fatalf("in-flight Begin = %v, want Conflict", b2.Outcome)
	}

	if persisted, err := s.Complete(ctx, acct, key, b.Nonce, "hashA", Stored{Status: 200, Body: []byte(`{"ok":true}`), UpstreamID: "u1"}); err != nil || !persisted {
		t.Fatalf("Complete: %v", err)
	}

	b3, _ := s.Begin(ctx, acct, key, "hashA")
	if b3.Outcome != Replay || b3.Stored == nil {
		t.Fatalf("completed Begin = %+v, want Replay", b3)
	}
	if b3.Stored.Status != 200 || string(b3.Stored.Body) != `{"ok":true}` || b3.Stored.UpstreamID != "u1" {
		t.Errorf("replayed stored = %+v", b3.Stored)
	}

	if b4, _ := s.Begin(ctx, acct, key, "hashB"); b4.Outcome != Mismatch {
		t.Fatalf("different payload = %v, want Mismatch", b4.Outcome)
	}
}

func TestCompleteCASRejectsStolenLock(t *testing.T) {
	s := New(testRedis(t), 30*time.Second, time.Hour)
	ctx := context.Background()
	acct, key := "acct-"+uid(), "k-"+uid()

	b, _ := s.Begin(ctx, acct, key, "h")

	// A Complete with the wrong nonce must not overwrite the in-flight marker.
	persisted, err := s.Complete(ctx, acct, key, "wrong-nonce", "h", Stored{Status: 200, Body: []byte("x"), UpstreamID: "u"})
	if err != nil {
		t.Fatalf("Complete (wrong nonce): %v", err)
	}
	if persisted {
		t.Fatal("Complete (wrong nonce) persisted, want false")
	}
	if b2, _ := s.Begin(ctx, acct, key, "h"); b2.Outcome != Conflict {
		t.Fatalf("after wrong-nonce Complete, Begin = %v, want still Conflict", b2.Outcome)
	}

	// The real owner completes successfully.
	if persisted, err := s.Complete(ctx, acct, key, b.Nonce, "h", Stored{Status: 200, Body: []byte("y"), UpstreamID: "u2"}); err != nil || !persisted {
		t.Fatalf("Complete (real nonce): %v", err)
	}
	b3, _ := s.Begin(ctx, acct, key, "h")
	if b3.Outcome != Replay || string(b3.Stored.Body) != "y" {
		t.Fatalf("after real Complete, Begin = %+v, want Replay body y", b3)
	}
}

func TestReleaseAllowsRetry(t *testing.T) {
	s := New(testRedis(t), 30*time.Second, time.Hour)
	ctx := context.Background()
	acct, key := "acct-"+uid(), "k-"+uid()

	b, _ := s.Begin(ctx, acct, key, "h")
	s.Release(ctx, acct, key, b.Nonce)
	if b2, _ := s.Begin(ctx, acct, key, "h"); b2.Outcome != Proceed {
		t.Fatalf("after Release, Begin = %v, want Proceed", b2.Outcome)
	}
}

func TestFailClosed(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	s := New(rdb, 30*time.Second, time.Hour)
	if _, err := s.Begin(context.Background(), "a", "k", "h"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Begin with Redis down = %v, want ErrUnavailable", err)
	}
}
