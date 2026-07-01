package httpapi

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/Silo-Server/silo-push-relay/internal/ratelimit"
)

// rateLimiter applies the per-account token bucket before the body is decoded
// (spec §9). Daily quota and the coarse per-token cap run later, after
// idempotency confirms the request is a genuinely new send.
type rateLimiter struct {
	limiter *ratelimit.Limiter
	logger  *slog.Logger
}

func (m *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := RequestIDFromContext(r.Context())
		info, ok := authFromContext(r.Context())
		if !ok {
			// auth must run first; this is a wiring bug, fail safe.
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized", rid)
			return
		}

		res := m.limiter.CheckAccountBurst(r.Context(), info.AccountID)
		if res.Degraded {
			m.logger.Warn("rate_limit.degraded", "account", info.AccountID, "request_id", rid)
		}
		if !res.Allowed {
			writeRetryAfter(w, res.RetryAfter.Seconds())
			writeError(w, http.StatusTooManyRequests, "rate_limited", "account rate limit exceeded", rid)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeRetryAfter sets a relative delay-seconds Retry-After header (never an
// absolute epoch — reference §4.2), with a floor of 1 second.
func writeRetryAfter(w http.ResponseWriter, seconds float64) {
	s := int(math.Ceil(seconds))
	if s < 1 {
		s = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(s))
}
