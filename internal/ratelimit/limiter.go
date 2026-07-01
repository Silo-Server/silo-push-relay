// Package ratelimit implements the relay's per-account rate limiting: a Redis
// token bucket plus a fixed-UTC-day quota counter and a coarse per-(account,
// token) cap, with a bounded in-process fail-open fallback when Redis is
// unreachable (spec §9).
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// tokenBucketScript performs refill -> check -> consume atomically.
// KEYS[1] = bucket hash; ARGV = rate(tokens/s), capacity, now_ms, cost, ttl_ms.
// Returns {allowed(0|1), retry_after_ms}.
const tokenBucketScript = `
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  ts = now_ms
end
local elapsed = now_ms - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + (elapsed / 1000.0) * rate)
local allowed = 0
local retry_after_ms = 0
if tokens >= cost then
  allowed = 1
  tokens = tokens - cost
else
  retry_after_ms = math.ceil(((cost - tokens) / rate) * 1000)
end
redis.call('HSET', key, 'tokens', tokens, 'ts', now_ms)
redis.call('PEXPIRE', key, ttl_ms)
return {allowed, retry_after_ms}
`

// dailyScript increments a per-UTC-day counter and denies past the quota
// without leaving the counter inflated on denial.
// KEYS[1] = counter; ARGV = quota, ttl_seconds. Returns 1 (allowed) or 0.
const dailyScript = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
if c > tonumber(ARGV[1]) then
  redis.call('DECR', KEYS[1])
  return 0
end
return 1
`

// Config holds the limiter's tunable defaults (spec §9.2).
type Config struct {
	Rate          float64 // per-account tokens/sec
	Burst         int     // per-account bucket capacity
	DailyQuota    int64   // per-account fixed-UTC-day cap
	CoarseRate    float64 // per-(account,token) tokens/sec
	CoarseBurst   int     // per-(account,token) capacity
	BucketIdleTTL time.Duration
}

// DefaultConfig is the spec §9.2 default: ~10 req/s burst 20, 50k/day, ~1 req/3s per token.
func DefaultConfig() Config {
	return Config{
		Rate:          10,
		Burst:         20,
		DailyQuota:    50_000,
		CoarseRate:    1.0 / 3.0,
		CoarseBurst:   1,
		BucketIdleTTL: 10 * time.Minute,
	}
}

// Result is the outcome of a limit check.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration
	Degraded   bool   // true when the in-process fallback was used (Redis down)
	Limit      string // which limit denied: "account" | "token" | "daily" | "fallback"
}

// Limiter enforces per-account limits against Redis with an in-process fallback.
type Limiter struct {
	rdb    *redis.Client
	bucket *redis.Script
	daily  *redis.Script
	cfg    Config

	now func() time.Time

	mu       sync.Mutex
	fallback map[string]*rate.Limiter
}

// New builds a Limiter.
func New(rdb *redis.Client, cfg Config) *Limiter {
	return &Limiter{
		rdb:      rdb,
		bucket:   redis.NewScript(tokenBucketScript),
		daily:    redis.NewScript(dailyScript),
		cfg:      cfg,
		now:      time.Now,
		fallback: make(map[string]*rate.Limiter),
	}
}

// CheckAccount applies the per-account token bucket and the daily quota. It runs
// in the request middleware before the body is decoded. On any Redis error it
// degrades to a bounded in-process per-account limiter rather than removing the
// cap (spec §9.4).
func (l *Limiter) CheckAccount(ctx context.Context, accountID string) Result {
	res := l.CheckAccountBurst(ctx, accountID)
	if !res.Allowed {
		return res
	}

	daily := l.ChargeDaily(ctx, accountID)
	if !daily.Allowed {
		return daily
	}
	if daily.Degraded {
		res.Degraded = true
	}
	return res
}

// CheckAccountBurst applies only the per-account token bucket. It is safe to run
// before idempotency because it protects the relay from request floods without
// consuming the daily delivery quota.
func (l *Limiter) CheckAccountBurst(ctx context.Context, accountID string) Result {
	d, err := l.runBucket(ctx, "rl:"+accountID, l.cfg.Rate, l.cfg.Burst)
	if err != nil {
		return l.fallbackCheck(accountID)
	}
	if !d.Allowed {
		return Result{Allowed: false, RetryAfter: d.RetryAfter, Limit: "account"}
	}
	return Result{Allowed: true}
}

// ChargeDaily consumes one fixed-UTC-day quota unit for a genuinely new send.
// When Redis is unavailable, the earlier per-account fallback bucket still
// bounds request volume, so daily quota degrades open rather than blocking sends.
func (l *Limiter) ChargeDaily(ctx context.Context, accountID string) Result {
	ok, err := l.runDaily(ctx, accountID)
	if err != nil {
		return Result{Allowed: true, Degraded: true, Limit: "daily"}
	}
	if !ok {
		return Result{Allowed: false, RetryAfter: l.untilMidnightUTC(), Limit: "daily"}
	}
	return Result{Allowed: true}
}

// CheckToken applies the coarse per-(account, token) cap. It runs in the handler
// after decoding, where the device token (hashed) is known. A Redis error
// degrades to allow — the per-account fallback already bounds spend.
func (l *Limiter) CheckToken(ctx context.Context, accountID, tokenHash string) Result {
	d, err := l.runBucket(ctx, "rlt:"+accountID+":"+tokenHash, l.cfg.CoarseRate, l.cfg.CoarseBurst)
	if err != nil {
		return Result{Allowed: true, Degraded: true, Limit: "token"}
	}
	if !d.Allowed {
		return Result{Allowed: false, RetryAfter: d.RetryAfter, Limit: "token"}
	}
	return Result{Allowed: true}
}

type bucketResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

func (l *Limiter) runBucket(ctx context.Context, key string, ratePerSec float64, capacity int) (bucketResult, error) {
	nowMS := l.now().UnixMilli()
	ttlMS := l.cfg.BucketIdleTTL.Milliseconds()
	res, err := l.bucket.Run(ctx, l.rdb, []string{key}, ratePerSec, capacity, nowMS, 1, ttlMS).Slice()
	if err != nil {
		return bucketResult{}, err
	}
	allowed, _ := res[0].(int64)
	retryMS, _ := res[1].(int64)
	return bucketResult{Allowed: allowed == 1, RetryAfter: time.Duration(retryMS) * time.Millisecond}, nil
}

func (l *Limiter) runDaily(ctx context.Context, accountID string) (bool, error) {
	day := l.now().UTC().Format("20060102")
	key := "rl:day:" + accountID + ":" + day
	ttl := int64(l.untilMidnightUTC()/time.Second) + 60
	res, err := l.daily.Run(ctx, l.rdb, []string{key}, l.cfg.DailyQuota, ttl).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (l *Limiter) fallbackCheck(accountID string) Result {
	lim := l.fallbackLimiter(accountID)
	if lim.Allow() {
		return Result{Allowed: true, Degraded: true, Limit: "fallback"}
	}
	retry := time.Duration(float64(time.Second) / l.cfg.Rate)
	return Result{Allowed: false, RetryAfter: retry, Degraded: true, Limit: "fallback"}
}

func (l *Limiter) fallbackLimiter(accountID string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.fallback[accountID]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(l.cfg.Rate), l.cfg.Burst)
		l.fallback[accountID] = lim
	}
	return lim
}

func (l *Limiter) untilMidnightUTC() time.Duration {
	now := l.now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	return next.Sub(now)
}
