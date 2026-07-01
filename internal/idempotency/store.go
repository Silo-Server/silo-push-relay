// Package idempotency provides at-most-once protection for send requests using a
// Redis lock keyed per (account, Idempotency-Key). It fails closed: if Redis is
// unavailable, Begin returns ErrUnavailable so the caller returns 503 rather
// than risk a double upstream send (spec §10).
package idempotency

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrUnavailable signals the store could not be reached; map it to 503.
var ErrUnavailable = errors.New("idempotency: store unavailable")

// Outcome is the result of Begin.
type Outcome int

const (
	// Proceed: first request for this key; caller must Complete or Release.
	Proceed Outcome = iota
	// Replay: a completed result exists; return Stored verbatim.
	Replay
	// Conflict: the original request is still in flight (409).
	Conflict
	// Mismatch: same key, different payload (422).
	Mismatch
)

// Stored is a recorded response for replay.
type Stored struct {
	Status     int    `json:"status"`
	Body       []byte `json:"body"`
	UpstreamID string `json:"upstream_id"`
}

// BeginResult is returned by Begin.
type BeginResult struct {
	Outcome Outcome
	Nonce   string  // ownership token for Complete/Release (Proceed only)
	Stored  *Stored // populated for Replay
}

// completeScript overwrites the key with the completed result only if it still
// holds this request's in-flight marker (compare-and-set), so a lock stolen
// after a TTL expiry cannot have its result clobbered.
const completeScript = `
local cur = redis.call('GET', KEYS[1])
if cur == false then return 0 end
local ok, obj = pcall(cjson.decode, cur)
if not ok then return 0 end
if obj.state == 'inflight' and obj.nonce == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
  return 1
end
return 0
`

// releaseScript deletes the in-flight marker only if we still own it, so a
// drained/cancelled request does not block an immediate retry for the full lock TTL.
const releaseScript = `
local cur = redis.call('GET', KEYS[1])
if cur == false then return 0 end
local ok, obj = pcall(cjson.decode, cur)
if not ok then return 0 end
if obj.state == 'inflight' and obj.nonce == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`

type value struct {
	State         string `json:"state"` // "inflight" | "done"
	Nonce         string `json:"nonce,omitempty"`
	Status        int    `json:"status,omitempty"`
	Body          []byte `json:"body,omitempty"`
	UpstreamID    string `json:"upstream_id,omitempty"`
	CanonicalHash string `json:"canonical_hash,omitempty"`
}

// Store is the Redis-backed idempotency store.
type Store struct {
	rdb       *redis.Client
	lockTTL   time.Duration
	resultTTL time.Duration
	complete  *redis.Script
	release   *redis.Script
	newNonce  func() string
}

// New builds a Store. lockTTL must be strictly longer than the upstream call
// deadline (spec §10.2 lock-TTL invariant); resultTTL ~24h.
func New(rdb *redis.Client, lockTTL, resultTTL time.Duration) *Store {
	return &Store{
		rdb:       rdb,
		lockTTL:   lockTTL,
		resultTTL: resultTTL,
		complete:  redis.NewScript(completeScript),
		release:   redis.NewScript(releaseScript),
		newNonce:  defaultNonce,
	}
}

func key(account, idemKey string) string { return "idem:" + account + ":" + idemKey }

// Begin attempts to acquire the in-flight lock for (account, idemKey).
// canonicalHash identifies the request payload (with the device token replaced
// by its hash — never the raw token) for reuse detection.
func (s *Store) Begin(ctx context.Context, account, idemKey, canonicalHash string) (BeginResult, error) {
	nonce := s.newNonce()
	marker, _ := json.Marshal(value{State: "inflight", Nonce: nonce})

	ok, err := s.rdb.SetNX(ctx, key(account, idemKey), marker, s.lockTTL).Result()
	if err != nil {
		return BeginResult{}, ErrUnavailable
	}
	if ok {
		return BeginResult{Outcome: Proceed, Nonce: nonce}, nil
	}

	raw, err := s.rdb.Get(ctx, key(account, idemKey)).Bytes()
	if errors.Is(err, redis.Nil) {
		// Lock expired between SetNX and Get; tell the caller to retry.
		return BeginResult{Outcome: Conflict}, nil
	}
	if err != nil {
		return BeginResult{}, ErrUnavailable
	}

	var v value
	if json.Unmarshal(raw, &v) != nil {
		return BeginResult{Outcome: Conflict}, nil
	}
	switch v.State {
	case "done":
		if v.CanonicalHash != canonicalHash {
			return BeginResult{Outcome: Mismatch}, nil
		}
		return BeginResult{Outcome: Replay, Stored: &Stored{Status: v.Status, Body: v.Body, UpstreamID: v.UpstreamID}}, nil
	default:
		return BeginResult{Outcome: Conflict}, nil
	}
}

// Complete records the final result, compare-and-set against our own nonce.
// It returns false when the in-flight marker no longer belongs to this request.
func (s *Store) Complete(ctx context.Context, account, idemKey, nonce, canonicalHash string, res Stored) (bool, error) {
	done, _ := json.Marshal(value{
		State:         "done",
		Status:        res.Status,
		Body:          res.Body,
		UpstreamID:    res.UpstreamID,
		CanonicalHash: canonicalHash,
	})
	persisted, err := s.complete.Run(ctx, s.rdb, []string{key(account, idemKey)}, nonce, done, s.resultTTL.Milliseconds()).Int()
	if err != nil {
		return false, ErrUnavailable
	}
	return persisted == 1, nil
}

// Release drops our in-flight marker (best effort) so a retry is not blocked
// after a cancellation/drain.
func (s *Store) Release(ctx context.Context, account, idemKey, nonce string) {
	_, _ = s.release.Run(ctx, s.rdb, []string{key(account, idemKey)}, nonce).Int()
}

func defaultNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
