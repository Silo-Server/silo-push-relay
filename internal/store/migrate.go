package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	// Registers the "pgx" database/sql driver used by the goose migration runner.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Silo-Server/silo-push-relay/migrations"
)

const migrationsDir = "sql"

func init() {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		// "postgres" is a built-in dialect; this can only fail on a typo.
		panic(fmt.Sprintf("store: set goose dialect: %v", err))
	}
}

// openSQL opens a database/sql handle for the goose runner. The app itself uses
// pgxpool; goose needs a *sql.DB, so migrations run over the pgx stdlib driver.
func openSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sql for migrations: %w", err)
	}
	return db, nil
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, dsn string) (err error) {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("store: close migration db: %w", closeErr)
		}
	}()
	if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("store: migrate up: %w", err)
	}
	return nil
}

// MigrationStatus prints the migration state to goose's logger (stdout).
func MigrationStatus(ctx context.Context, dsn string) (err error) {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("store: close migration db: %w", closeErr)
		}
	}()
	if err := goose.StatusContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("store: migrate status: %w", err)
	}
	return nil
}
