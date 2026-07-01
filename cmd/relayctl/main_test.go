package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/store"
)

func TestKeyRevokeAuditIncludesAccountID(t *testing.T) {
	dsn := os.Getenv("RELAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RELAY_TEST_DATABASE_URL to run relayctl DB tests")
	}
	t.Setenv("RELAY_DATABASE_URL", dsn)
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx,
		`TRUNCATE relay_op_logs, relay_fcm_allowlist, relay_apns_allowlist, relay_api_keys, relay_accounts RESTART IDENTITY CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	s := accounts.New(pool, []byte("relayctl-test-pepper"))
	account, err := s.CreateAccount(ctx, "Relayctl Test", "")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	_, key, err := s.IssueKey(ctx, account.ID, "live", nil)
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}

	if err := run([]string{"key", "revoke", "--key-prefix", key.KeyPrefix, "--actor", "test"}); err != nil {
		t.Fatalf("run key revoke: %v", err)
	}
	var loggedAccount string
	if err := pool.QueryRow(ctx,
		`SELECT account_id FROM relay_op_logs WHERE event = 'admin.key_revoke' ORDER BY id DESC LIMIT 1`,
	).Scan(&loggedAccount); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if loggedAccount != account.ID {
		t.Fatalf("audit account_id = %q, want %q", loggedAccount, account.ID)
	}
}
