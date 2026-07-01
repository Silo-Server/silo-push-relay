// Command relay is the Silo push relay HTTP service entrypoint. It loads
// configuration, opens the datastores, builds the logger and HTTP server, serves
// until it receives SIGINT/SIGTERM, then drains in-flight requests and exits.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/apns"
	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/httpapi"
	"github.com/Silo-Server/silo-push-relay/internal/idempotency"
	"github.com/Silo-Server/silo-push-relay/internal/observability"
	"github.com/Silo-Server/silo-push-relay/internal/ratelimit"
	"github.com/Silo-Server/silo-push-relay/internal/store"
)

const (
	idempotencyLockTTL   = 30 * time.Second
	idempotencyResultTTL = 24 * time.Hour
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	migrateOnStart := fs.Bool("migrate", false, "apply database migrations on startup before serving")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}
	logger := observability.NewLogger(cfg.LogLevel, os.Stdout)

	dsn, err := config.DatabaseURL()
	if err != nil {
		return err
	}
	redisURL, err := config.RedisURL()
	if err != nil {
		return err
	}
	pepper, err := config.APIKeyPepper()
	if err != nil {
		return err
	}
	trusted, err := config.TrustedProxies()
	if err != nil {
		return err
	}

	if *migrateOnStart {
		logger.Info("applying database migrations")
		if err := store.Migrate(ctx, dsn); err != nil {
			return err
		}
		logger.Info("database migrations applied")
	}

	// Both clients connect lazily; /readyz reflects datastore health while
	// /healthz stays a pure liveness probe.
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	rdb, err := store.OpenRedis(ctx, redisURL)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	logger.Info("starting silo-push-relay",
		"environment", cfg.Environment,
		"listen_addr", cfg.ListenAddr,
		"trusted_proxies", len(trusted),
	)

	var apnsClient httpapi.APNsSender
	if cfg.APNsConfigured() {
		apnsClient, err = apns.New(apns.Config{
			TeamID:        cfg.APNsTeamID,
			KeyID:         cfg.APNsKeyID,
			KeyPath:       cfg.APNsKeyPath,
			ExpirationTTL: cfg.APNsExpirationTTL,
		})
		if err != nil {
			return err
		}
		logger.Info("apns upstream configured")
	} else {
		logger.Warn("apns upstream is not configured; /v1/apple/send will return 503")
	}

	srv := httpapi.NewServer(httpapi.Deps{
		Config:         cfg,
		Logger:         logger,
		Accounts:       accounts.New(db.Pool, pepper),
		Redis:          rdb,
		Pepper:         pepper,
		Limiter:        ratelimit.New(rdb, ratelimit.DefaultConfig()),
		Idempotency:    idempotency.New(rdb, idempotencyLockTTL, idempotencyResultTTL),
		TrustedProxies: trusted,
		APNs:           apnsClient,
		Ready: func(ctx context.Context) error {
			if err := db.Ping(ctx); err != nil {
				return err
			}
			return rdb.Ping(ctx).Err()
		},
	})
	if err := httpapi.Run(ctx, srv, logger, cfg.ShutdownTimeout); err != nil {
		return err
	}

	logger.Info("shutdown complete")
	return nil
}
