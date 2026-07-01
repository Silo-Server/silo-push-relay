// Package store bootstraps the relay's datastores and owns the migration
// runner. Phase 1 wires PostgreSQL (pgxpool); Redis is added in Phase 2.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the PostgreSQL connection pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Open parses the DSN and creates a connection pool. pgxpool connects lazily, so
// this does not fail if the database is momentarily unreachable; use Ping (e.g.
// from /readyz) to check liveness.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Ping verifies a working connection to PostgreSQL.
func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}

// Close releases all pooled connections.
func (d *DB) Close() {
	d.Pool.Close()
}
