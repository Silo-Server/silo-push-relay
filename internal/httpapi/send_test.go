package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/apns"
	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/idempotency"
	"github.com/Silo-Server/silo-push-relay/internal/observability"
	"github.com/Silo-Server/silo-push-relay/internal/ratelimit"
	"github.com/Silo-Server/silo-push-relay/internal/store"
)

type fakeAPNsSender struct {
	result apns.Result
	err    error
	calls  int
}

func (f *fakeAPNsSender) Send(context.Context, apns.Request) (apns.Result, error) {
	f.calls++
	return f.result, f.err
}

type sequenceAPNsSender struct {
	results []apns.Result
	errs    []error
	calls   int
}

func (s *sequenceAPNsSender) Send(context.Context, apns.Request) (apns.Result, error) {
	idx := s.calls
	s.calls++
	if idx >= len(s.results) {
		idx = len(s.results) - 1
	}
	var err error
	if idx < len(s.errs) {
		err = s.errs[idx]
	}
	return s.results[idx], err
}

// lenientLimits removes rate limiting from the integration test so it exercises
// auth/decode/allowlist/idempotency; rate limiting is covered in the ratelimit package.
func lenientLimits() ratelimit.Config {
	return ratelimit.Config{
		Rate: 1e6, Burst: 1_000_000, DailyQuota: 1_000_000_000,
		CoarseRate: 1e6, CoarseBurst: 1_000_000, BucketIdleTTL: time.Minute,
	}
}

func sendTestEnv(t *testing.T) (h http.Handler, token, badToken string) {
	h, token, badToken, _, _ = sendTestEnvWith(t, &fakeAPNsSender{result: apns.Result{APNsID: "apns-test-id", StatusCode: http.StatusOK}}, lenientLimits())
	return h, token, badToken
}

func sendTestEnvWith(t *testing.T, sender APNsSender, limits ratelimit.Config) (h http.Handler, token, badToken string, as *accounts.Store, accountID string) {
	t.Helper()
	dsn := os.Getenv("RELAY_TEST_DATABASE_URL")
	redisURL := os.Getenv("RELAY_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set RELAY_TEST_DATABASE_URL and RELAY_TEST_REDIS_URL to run send pipeline tests")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pg pool: %v", err)
	}
	t.Cleanup(pool.Close)

	opt, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	pepper := []byte("send-test-pepper-of-good-length")
	as = accounts.New(pool, pepper)
	a, err := as.CreateAccount(ctx, "Send Test", "")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	accountID = a.ID
	token, _, err = as.IssueKey(ctx, a.ID, "live", nil)
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	if err := as.SetAPNsAllowlist(ctx, a.ID, []string{"com.continuum.app.ios"}); err != nil {
		t.Fatalf("set allowlist: %v", err)
	}

	cfg := &config.Config{
		ListenAddr: ":0", Environment: "development", LogLevel: "error",
		ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
		IdleTimeout: time.Second, ShutdownTimeout: time.Second, MaxHeaderBytes: 1 << 20, MaxBodyBytes: 16 << 10,
	}
	d := Deps{
		Config:      cfg,
		Logger:      observability.NewLogger("error", io.Discard),
		Accounts:    as,
		Redis:       rdb,
		Pepper:      pepper,
		Limiter:     ratelimit.New(rdb, limits),
		Idempotency: idempotency.New(rdb, 30*time.Second, time.Hour),
		APNs:        sender,
	}
	// A syntactically valid but unknown key (prefix won't be found).
	badToken = "rk_live_deadbeefDEADBEEF01"
	return newRouter(d), token, badToken, as, accountID
}

func postApple(h http.Handler, token, idemKey, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/apple/send", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if idemKey != "" {
		r.Header.Set("Idempotency-Key", idemKey)
	}
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func errCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return e.Error.Code
}

func TestSendPipeline(t *testing.T) {
	h, token, badToken := sendTestEnv(t)
	valid := appleBody(nil)

	t.Run("valid", func(t *testing.T) {
		rr := postApple(h, token, "k-"+idSuffix(), valid)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (%s), want 200", rr.Code, rr.Body.String())
		}
		var resp appleSendResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Status != "accepted" || resp.APNsID == "" {
			t.Errorf("response = %+v", resp)
		}
	})

	t.Run("bad key 401", func(t *testing.T) {
		rr := postApple(h, badToken, "k-"+idSuffix(), valid)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
		if c := errCode(t, rr); c != "unauthorized" {
			t.Errorf("code = %q, want unauthorized", c)
		}
	})

	t.Run("unknown field 400", func(t *testing.T) {
		rr := postApple(h, token, "k-"+idSuffix(), appleBody(map[string]any{"title": "x"}))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if c := errCode(t, rr); c != "unexpected_field" {
			t.Errorf("code = %q, want unexpected_field", c)
		}
	})

	t.Run("topic not allowed 403", func(t *testing.T) {
		rr := postApple(h, token, "k-"+idSuffix(), appleBody(map[string]any{"topic": "com.evil.app"}))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
		if c := errCode(t, rr); c != "topic_not_allowed" {
			t.Errorf("code = %q, want topic_not_allowed", c)
		}
	})

	t.Run("missing idempotency key 400", func(t *testing.T) {
		rr := postApple(h, token, "", valid)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if c := errCode(t, rr); c != "missing_idempotency_key" {
			t.Errorf("code = %q, want missing_idempotency_key", c)
		}
	})

	t.Run("duplicate replays then mismatch 422", func(t *testing.T) {
		key := "k-" + idSuffix()
		r1 := postApple(h, token, key, valid)
		if r1.Code != http.StatusOK {
			t.Fatalf("first = %d", r1.Code)
		}
		r2 := postApple(h, token, key, valid)
		if r2.Code != http.StatusOK || r2.Body.String() != r1.Body.String() {
			t.Fatalf("replay mismatch: first=%q second=%q", r1.Body.String(), r2.Body.String())
		}
		// Same key, different payload → 422.
		r3 := postApple(h, token, key, appleBody(map[string]any{"server_device_id": "02DIFFERENT"}))
		if r3.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", r3.Code)
		}
		if c := errCode(t, r3); c != "idempotency_key_reuse" {
			t.Errorf("code = %q, want idempotency_key_reuse", c)
		}
	})
}

func TestRetryableAPNsFailureReleasesIdempotency(t *testing.T) {
	retryable := apns.Result{StatusCode: http.StatusServiceUnavailable, Reason: "ServiceUnavailable"}
	sender := &sequenceAPNsSender{
		results: []apns.Result{
			retryable,
			{APNsID: "apns-retry-ok", StatusCode: http.StatusOK},
		},
		errs: []error{
			&apns.Error{Result: retryable},
			nil,
		},
	}
	h, token, _, _, _ := sendTestEnvWith(t, sender, lenientLimits())
	key := "k-" + idSuffix()
	body := appleBody(nil)

	first := postApple(h, token, key, body)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first status = %d (%s), want 503", first.Code, first.Body.String())
	}
	second := postApple(h, token, key, body)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d (%s), want 200", second.Code, second.Body.String())
	}
	if sender.calls != 2 {
		t.Fatalf("APNs calls = %d, want 2", sender.calls)
	}
}

func TestReplaySkipsAllowlistAndDailyQuota(t *testing.T) {
	limits := lenientLimits()
	limits.DailyQuota = 2
	sender := &fakeAPNsSender{result: apns.Result{APNsID: "apns-quota-ok", StatusCode: http.StatusOK}}
	h, token, _, as, accountID := sendTestEnvWith(t, sender, limits)
	ctx := context.Background()
	body := appleBody(nil)
	key := "k-" + idSuffix()

	first := postApple(h, token, key, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d (%s), want 200", first.Code, first.Body.String())
	}
	if err := as.SetAPNsAllowlist(ctx, accountID, []string{"com.continuum.other"}); err != nil {
		t.Fatalf("change allowlist: %v", err)
	}
	replay := postApple(h, token, key, body)
	if replay.Code != http.StatusOK || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay = %d %q, want original 200 %q", replay.Code, replay.Body.String(), first.Body.String())
	}
	if err := as.SetAPNsAllowlist(ctx, accountID, []string{"com.continuum.app.ios"}); err != nil {
		t.Fatalf("restore allowlist: %v", err)
	}
	secondNew := postApple(h, token, "k-"+idSuffix(), body)
	if secondNew.Code != http.StatusOK {
		t.Fatalf("second new status = %d (%s), want 200", secondNew.Code, secondNew.Body.String())
	}
	thirdNew := postApple(h, token, "k-"+idSuffix(), body)
	if thirdNew.Code != http.StatusTooManyRequests {
		t.Fatalf("third new status = %d (%s), want 429 daily quota", thirdNew.Code, thirdNew.Body.String())
	}
}

func TestCanonicalHashEscapesSeparatorAmbiguity(t *testing.T) {
	if canonicalHash("x", "y\x1fz") == canonicalHash("x\x1fy", "z") {
		t.Fatal("canonicalHash collided for separator-containing opaque IDs")
	}
}

func idSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
