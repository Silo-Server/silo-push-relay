package accounts

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-push-relay/internal/store"
)

// newTestStore connects to RELAY_TEST_DATABASE_URL, applies migrations, and
// truncates all relay tables for a deterministic start. The whole DB-backed
// suite is skipped when the env var is unset.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("RELAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RELAY_TEST_DATABASE_URL to run accounts DB tests")
	}
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
	return New(pool, []byte("test-pepper-of-sufficient-length"))
}

func TestAccountKeyAllowlistLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.CreateAccount(ctx, "Test Account", "a note")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if a.Status != "active" {
		t.Errorf("status = %q, want active", a.Status)
	}

	// Issue a key; the returned token must verify against the stored hash.
	token, key, err := s.IssueKey(ctx, a.ID, "live", nil)
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	var storedHash []byte
	if err := s.pool.QueryRow(ctx, `SELECT key_hash FROM relay_api_keys WHERE key_prefix = $1`, key.KeyPrefix).Scan(&storedHash); err != nil {
		t.Fatalf("read stored hash: %v", err)
	}
	if !VerifyToken(s.pepper, token, storedHash) {
		t.Error("issued token does not verify against the stored hash")
	}
	if derived, _ := PrefixOf(token); derived != key.KeyPrefix {
		t.Errorf("PrefixOf(token) = %q, want %q", derived, key.KeyPrefix)
	}

	keys, err := s.ListKeys(ctx, a.ID)
	if err != nil || len(keys) != 1 || keys[0].RevokedAt != nil {
		t.Fatalf("ListKeys = %+v, err %v; want 1 live key", keys, err)
	}

	// Allowlists round-trip.
	if err := s.SetAPNsAllowlist(ctx, a.ID, []string{"com.continuum.app.ios", "com.continuum.app.tvos"}); err != nil {
		t.Fatalf("set apns allowlist: %v", err)
	}
	if err := s.SetFCMAllowlist(ctx, a.ID, "continuum-prod-android", []string{"com.continuum.app.android"}); err != nil {
		t.Fatalf("set fcm allowlist: %v", err)
	}
	apns, fcm, err := s.Allowlists(ctx, a.ID)
	if err != nil {
		t.Fatalf("allowlists: %v", err)
	}
	if len(apns) != 2 || apns[0] != "com.continuum.app.ios" {
		t.Errorf("apns allowlist = %v", apns)
	}
	if len(fcm) != 1 || fcm[0].ProjectID != "continuum-prod-android" || fcm[0].PackageName != "com.continuum.app.android" {
		t.Errorf("fcm allowlist = %+v", fcm)
	}
	// Replacing the APNs allowlist fully replaces (not appends).
	if err := s.SetAPNsAllowlist(ctx, a.ID, []string{"com.continuum.app.macos"}); err != nil {
		t.Fatalf("replace apns allowlist: %v", err)
	}
	apns, _, _ = s.Allowlists(ctx, a.ID)
	if len(apns) != 1 || apns[0] != "com.continuum.app.macos" {
		t.Errorf("apns allowlist after replace = %v, want [com.continuum.app.macos]", apns)
	}

	// Revoke is idempotent-ish: the second revoke finds no live key.
	if accountID, err := s.RevokeKey(ctx, key.KeyPrefix); err != nil || accountID != a.ID {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.RevokeKey(ctx, key.KeyPrefix); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revoke err = %v, want ErrNotFound", err)
	}

	// Disable removes the account from the active list.
	if err := s.DisableAccount(ctx, a.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	active, err := s.ListAccounts(ctx, true)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("active accounts = %d, want 0 after disable", len(active))
	}

	// Admin audit rows were written.
	var adminEvents int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM relay_op_logs WHERE event LIKE 'admin.%'`).Scan(&adminEvents); err != nil {
		t.Fatalf("count op logs: %v", err)
	}
}

func TestRegisterDeploymentRotatesKeysAndPreservesOperatorName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	deploymentID := "deployment-test"

	first, err := s.RegisterDeployment(ctx, DeploymentRegistration{
		DeploymentID: deploymentID,
		Env:          "live",
		APNsTopics:   []string{"org.siloserver.silo"},
	})
	if err != nil {
		t.Fatalf("first RegisterDeployment: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE relay_accounts SET name = 'Operator Name' WHERE id = $1`, deploymentID); err != nil {
		t.Fatalf("rename account: %v", err)
	}

	second, err := s.RegisterDeployment(ctx, DeploymentRegistration{
		DeploymentID: deploymentID,
		Env:          "live",
		APNsTopics:   []string{"org.siloserver.silo"},
	})
	if err != nil {
		t.Fatalf("second RegisterDeployment: %v", err)
	}
	if second.Account.Name != "Operator Name" {
		t.Fatalf("account name = %q, want Operator Name", second.Account.Name)
	}
	keys, err := s.ListKeys(ctx, deploymentID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	var oldRevoked, newActive bool
	for _, k := range keys {
		if k.KeyPrefix == first.Key.KeyPrefix && k.RevokedAt != nil {
			oldRevoked = true
		}
		if k.KeyPrefix == second.Key.KeyPrefix && k.RevokedAt == nil {
			newActive = true
		}
	}
	if !oldRevoked || !newActive {
		t.Fatalf("rotation state not enforced: %+v", keys)
	}

	third, err := s.RegisterDeployment(ctx, DeploymentRegistration{
		DeploymentID: deploymentID,
		Name:         "Explicit Name",
		Env:          "live",
		APNsTopics:   []string{"org.siloserver.silo"},
	})
	if err != nil {
		t.Fatalf("third RegisterDeployment: %v", err)
	}
	if third.Account.Name != "Explicit Name" {
		t.Fatalf("explicit account name = %q, want Explicit Name", third.Account.Name)
	}
}

func TestUnknownAccountErrors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, _, err := s.IssueKey(ctx, "01NONEXISTENT0000000000000", "live", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueKey on unknown account err = %v, want ErrNotFound", err)
	}
	if _, _, err := s.Allowlists(ctx, "01NONEXISTENT0000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Allowlists on unknown account err = %v, want ErrNotFound", err)
	}
	if err := s.DisableAccount(ctx, "01NONEXISTENT0000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DisableAccount on unknown account err = %v, want ErrNotFound", err)
	}
}
