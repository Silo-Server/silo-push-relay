package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
)

const (
	authFailWindow    = 5 * time.Minute
	authFailThreshold = 20 // soft-lock after this many failures per IP in the window
)

const authFailureRecordScript = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
`

const authFailureReadScript = `
local raw = redis.call('GET', KEYS[1])
if raw == false then return 0 end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return tonumber(raw)
`

var (
	authFailureRecord = redis.NewScript(authFailureRecordScript)
	authFailureRead   = redis.NewScript(authFailureReadScript)
)

type authCtxKey struct{}

// authInfo is the authenticated identity carried to send handlers.
type authInfo struct {
	AccountID string
	KeyPrefix string
	Env       string
	ClientIP  string
}

func authFromContext(ctx context.Context) (authInfo, bool) {
	v, ok := ctx.Value(authCtxKey{}).(authInfo)
	return v, ok
}

// authenticator enforces bearer-key auth (spec §8.2): bearer parse, prefix
// lookup, always-constant-time HMAC compare (decoy on miss), revoked/expired/
// disabled rejection, throttled last_used_at, and a soft per-IP brute-force cap.
type authenticator struct {
	accounts *accounts.Store
	rdb      *redis.Client
	pepper   []byte
	decoy    []byte
	trusted  []netip.Prefix
	logger   *slog.Logger
}

func newAuthenticator(d Deps) *authenticator {
	return &authenticator{
		accounts: d.Accounts,
		rdb:      d.Redis,
		pepper:   d.Pepper,
		// Fixed decoy hash so an unknown prefix costs the same HMAC+compare as a
		// known prefix with a wrong secret (no enumeration timing oracle).
		decoy:   accounts.HashToken(d.Pepper, "\x00silo-relay-auth-decoy\x00"),
		trusted: d.TrustedProxies,
		logger:  d.Logger,
	}
}

func (a *authenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := RequestIDFromContext(r.Context())
		ip := resolveClientIP(r, a.trusted)

		if a.tooManyAuthFailures(r.Context(), ip) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many authentication failures", rid)
			return
		}

		token, ok := bearerToken(r)
		if !ok {
			a.reject(r.Context(), w, ip, rid, "malformed_header")
			return
		}
		prefix, err := accounts.PrefixOf(token)
		if err != nil {
			a.reject(r.Context(), w, ip, rid, "malformed_token")
			return
		}

		rec, lookupErr := a.accounts.AuthLookup(r.Context(), prefix)
		if lookupErr != nil && !errors.Is(lookupErr, accounts.ErrNotFound) {
			// A real DB error (not "unknown prefix") — fail closed with 503.
			a.logger.Error("auth lookup failed", "request_id", rid, "err", lookupErr)
			writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "auth backend unavailable", rid)
			return
		}

		// Always compute HMAC + constant-time compare, against the real hash or
		// the decoy, so timing does not reveal whether the prefix exists.
		storedHash := a.decoy
		if rec != nil {
			storedHash = rec.KeyHash
		}
		match := accounts.VerifyToken(a.pepper, token, storedHash)

		if rec == nil || !match {
			a.reject(r.Context(), w, ip, rid, "unknown_or_mismatch")
			return
		}
		if rec.RevokedAt != nil {
			a.reject(r.Context(), w, ip, rid, "revoked")
			return
		}
		if rec.ExpiresAt != nil && !rec.ExpiresAt.After(time.Now()) {
			a.reject(r.Context(), w, ip, rid, "expired")
			return
		}
		if rec.AccountStatus != "active" {
			a.reject(r.Context(), w, ip, rid, "account_disabled")
			return
		}

		a.touchLastUsed(r.Context(), prefix)
		ctx := context.WithValue(r.Context(), authCtxKey{}, authInfo{
			AccountID: rec.AccountID, KeyPrefix: prefix, Env: rec.Env, ClientIP: ip,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// reject records the failure (for the per-IP limiter) and returns a uniform 401.
// The fine-grained reason stays in internal logs only (spec §8.2).
func (a *authenticator) reject(ctx context.Context, w http.ResponseWriter, ip, rid, reason string) {
	a.recordAuthFailure(ctx, ip)
	a.logger.Debug("auth rejected", "reason", reason, "client_ip", ip, "request_id", rid)
	writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized", rid)
}

func (a *authenticator) tooManyAuthFailures(ctx context.Context, ip string) bool {
	if a.rdb == nil {
		return false
	}
	n, err := authFailureRead.Run(ctx, a.rdb, []string{"authfail:" + ip}, int64(authFailWindow/time.Second)).Int()
	if err != nil {
		return false // fail open on Redis trouble
	}
	return n > authFailThreshold
}

func (a *authenticator) recordAuthFailure(ctx context.Context, ip string) {
	if a.rdb == nil {
		return
	}
	_, _ = authFailureRecord.Run(ctx, a.rdb, []string{"authfail:" + ip}, int64(authFailWindow/time.Second)).Int()
}

// touchLastUsed updates last_used_at at most once per minute per key; the
// throttle clock lives in Redis so the bound holds across replicas (spec §8.2).
func (a *authenticator) touchLastUsed(ctx context.Context, prefix string) {
	if a.rdb == nil {
		_ = a.accounts.TouchKeyLastUsed(ctx, prefix)
		return
	}
	ok, err := a.rdb.SetNX(ctx, "lastused:"+prefix, "1", time.Minute).Result()
	if err == nil && ok {
		_ = a.accounts.TouchKeyLastUsed(ctx, prefix)
	}
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	token := strings.TrimSpace(h[len(p):])
	if token == "" {
		return "", false
	}
	return token, true
}
