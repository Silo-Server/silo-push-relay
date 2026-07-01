package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/apns"
	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/idempotency"
	"github.com/Silo-Server/silo-push-relay/internal/ratelimit"
)

// ReadyFunc reports whether the relay's dependencies are healthy. A nil ReadyFunc
// means /readyz always reports ready (Phase 0 had no dependencies).
type ReadyFunc func(ctx context.Context) error

// Deps is the set of collaborators the HTTP layer needs. It grows by phase
// (auth store, rate limiter, push clients) without re-threading every signature.
// The send endpoints are mounted only when Accounts is non-nil, so health-only
// configurations (and Phase 0/1 tests) need not supply the Phase 2 collaborators.
type Deps struct {
	Config *config.Config
	Logger *slog.Logger
	Ready  ReadyFunc

	// Phase 2 send-path collaborators (all required together to mount /v1/*).
	Accounts       *accounts.Store
	Redis          *redis.Client
	Pepper         []byte
	Limiter        *ratelimit.Limiter
	Idempotency    *idempotency.Store
	TrustedProxies []netip.Prefix
	APNs           APNsSender
}

type APNsSender interface {
	Send(ctx context.Context, req apns.Request) (apns.Result, error)
}

// NewServer builds the relay's HTTP server with mandatory timeouts. A zero value
// for any of these means "no timeout", which is unsafe for an internet-facing
// service (reference §3.3), so they are always set from config.
func NewServer(d Deps) *http.Server {
	return &http.Server{
		Addr:              d.Config.ListenAddr,
		Handler:           newRouter(d),
		ReadHeaderTimeout: d.Config.ReadHeaderTimeout,
		ReadTimeout:       d.Config.ReadTimeout,
		WriteTimeout:      d.Config.WriteTimeout,
		IdleTimeout:       d.Config.IdleTimeout,
		MaxHeaderBytes:    d.Config.MaxHeaderBytes,
	}
}

// Run starts srv and blocks until ctx is cancelled (SIGINT/SIGTERM) or the
// server fails to listen. On cancellation it drains in-flight requests within
// shutdownTimeout before returning.
func Run(ctx context.Context, srv *http.Server, logger *slog.Logger, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining", "timeout", shutdownTimeout)
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
