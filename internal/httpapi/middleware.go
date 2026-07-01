package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Silo-Server/silo-push-relay/internal/id"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request ID assigned by the requestID
// middleware, or "" if none is present.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// requestID assigns a ULID to each request, exposes it on the X-Request-Id
// response header, and stores it in the request context for downstream use.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := id.New()
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), requestIDKey, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// statusRecorder captures the response status code for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter so http.ResponseController
// (Go 1.20+) can reach Flush / SetReadDeadline / SetWriteDeadline through this
// wrapper. Without it those controls fail with ErrNotSupported.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// logging emits one structured access-log line per request. It deliberately
// logs only method, path, status, duration, and request ID — never request
// bodies, query strings, headers, or tokens (redaction discipline, spec §13).
func logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", RequestIDFromContext(r.Context())),
			)
		})
	}
}

// recoverer converts a panic in a downstream handler into a 500 using the
// standard error envelope, so a single bad request cannot crash the process.
func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					rid := RequestIDFromContext(r.Context())
					logger.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
						slog.String("panic", fmt.Sprint(rec)),
						slog.String("request_id", rid),
					)
					writeError(w, http.StatusInternalServerError, "internal", "internal server error", rid)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// maxBytes caps the request body size to guard against oversized payloads. The
// limit is well above any legitimate send body; the real send endpoints add
// schema-level validation on top.
func maxBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
