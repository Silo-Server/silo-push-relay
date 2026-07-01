// Package accounts is the shared data-access layer for relay accounts, API keys,
// and per-account allowlists. Both the HTTP service (request-time auth, later
// phases) and the relayctl admin CLI use it so schema and constraints live in
// one place (spec §5.6).
package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-push-relay/internal/id"
)

// ErrNotFound is returned when a targeted account or key does not exist.
var ErrNotFound = errors.New("accounts: not found")

// ErrDisabled is returned when an existing relay account is disabled.
var ErrDisabled = errors.New("accounts: disabled")

// Store provides data access over a pgx pool plus the API-key pepper.
type Store struct {
	pool   *pgxpool.Pool
	pepper []byte
}

// New constructs a Store. pepper may be nil for read-only/admin operations that
// do not mint keys; IssueKey requires a non-empty pepper.
func New(pool *pgxpool.Pool, pepper []byte) *Store {
	return &Store{pool: pool, pepper: pepper}
}

// Account is a relay account row.
type Account struct {
	ID        string
	Name      string
	Status    string
	Note      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccountSummary is a list row with derived key activity.
type AccountSummary struct {
	ID         string
	Name       string
	Status     string
	CreatedAt  time.Time
	ActiveKeys int
	LastUsed   *time.Time
}

// APIKey is a relay_api_keys row (never carries the secret).
type APIKey struct {
	ID         string
	AccountID  string
	KeyPrefix  string
	Env        string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
}

// DeploymentRegistration describes a relay self-registration request. The
// account ID doubles as the opaque deployment_id Silo stores for later key
// rotation. The returned Token is the only copy of the raw API key.
type DeploymentRegistration struct {
	DeploymentID string
	Name         string
	Note         string
	Env          string
	APNsTopics   []string
}

type DeploymentRegistrationResult struct {
	Account Account
	Key     APIKey
	Token   string
}

// FCMAllow is one (project, package) allowlist entry.
type FCMAllow struct {
	ProjectID   string
	PackageName string
}

// RegisterDeployment creates or reuses a relay account for one Silo deployment,
// replaces its APNs topic allowlist, and issues a fresh API key. It never stores
// the raw key, only the HMAC hash used by send-path auth.
func (s *Store) RegisterDeployment(ctx context.Context, input DeploymentRegistration) (DeploymentRegistrationResult, error) {
	if len(s.pepper) == 0 {
		return DeploymentRegistrationResult{}, errors.New("accounts: api-key pepper is not configured")
	}
	accountID := strings.TrimSpace(input.DeploymentID)
	if accountID == "" {
		accountID = id.New()
	}
	inputName := strings.TrimSpace(input.Name)
	name := inputName
	nameExplicit := inputName != ""
	if !nameExplicit {
		name = "Silo Server"
	}
	env := strings.TrimSpace(input.Env)
	if env == "" {
		env = "live"
	}
	if env != "live" && env != "test" {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: invalid env %q (want live|test)", env)
	}
	if len(input.APNsTopics) == 0 {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: apns topics are required")
	}

	token, prefix, err := GenerateToken(env)
	if err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: generate token: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: begin deployment registration: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op

	account := Account{ID: accountID, Name: name, Note: input.Note}
	err = tx.QueryRow(ctx,
		`INSERT INTO relay_accounts (id, name, note)
			 VALUES ($1, $2, NULLIF($3, ''))
			 ON CONFLICT (id) DO UPDATE SET
			   name = CASE WHEN $4 THEN EXCLUDED.name ELSE relay_accounts.name END,
			   note = COALESCE(EXCLUDED.note, relay_accounts.note),
			   updated_at = now()
			 RETURNING name, status, COALESCE(note, ''), created_at, updated_at`,
		account.ID, account.Name, input.Note, nameExplicit,
	).Scan(&account.Name, &account.Status, &account.Note, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: upsert deployment account: %w", err)
	}
	if account.Status != "active" {
		return DeploymentRegistrationResult{}, ErrDisabled
	}

	if _, err := tx.Exec(ctx, `DELETE FROM relay_apns_allowlist WHERE account_id = $1`, account.ID); err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: clear deployment allowlist: %w", err)
	}
	for _, topic := range input.APNsTopics {
		topic = strings.TrimSpace(topic)
		if topic == "" {
			return DeploymentRegistrationResult{}, fmt.Errorf("accounts: apns topics contain an empty value")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO relay_apns_allowlist (account_id, topic) VALUES ($1, $2)`,
			account.ID, topic,
		); err != nil {
			return DeploymentRegistrationResult{}, fmt.Errorf("accounts: insert deployment allowlist: %w", err)
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE relay_api_keys SET revoked_at = now()
		 WHERE account_id = $1 AND env = $2 AND revoked_at IS NULL`,
		account.ID, env,
	); err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: revoke previous deployment keys: %w", err)
	}

	key := APIKey{ID: id.New(), AccountID: account.ID, KeyPrefix: prefix, Env: env}
	err = tx.QueryRow(ctx,
		`INSERT INTO relay_api_keys (id, account_id, key_prefix, key_hash, env)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING created_at`,
		key.ID, account.ID, prefix, HashToken(s.pepper, token), env,
	).Scan(&key.CreatedAt)
	if err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: insert deployment key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return DeploymentRegistrationResult{}, fmt.Errorf("accounts: commit deployment registration: %w", err)
	}
	return DeploymentRegistrationResult{Account: account, Key: key, Token: token}, nil
}

// CreateAccount inserts a new account and returns it.
func (s *Store) CreateAccount(ctx context.Context, name, note string) (Account, error) {
	a := Account{ID: id.New(), Name: name, Note: note}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO relay_accounts (id, name, note)
		 VALUES ($1, $2, NULLIF($3, ''))
		 RETURNING status, created_at, updated_at`,
		a.ID, a.Name, note,
	).Scan(&a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return Account{}, fmt.Errorf("accounts: create account: %w", err)
	}
	return a, nil
}

// ListAccounts returns accounts with active-key counts and last activity.
func (s *Store) ListAccounts(ctx context.Context, activeOnly bool) ([]AccountSummary, error) {
	q := `SELECT a.id, a.name, a.status, a.created_at,
	             COUNT(k.id) FILTER (WHERE k.revoked_at IS NULL) AS active_keys,
	             MAX(k.last_used_at) AS last_used
	      FROM relay_accounts a
	      LEFT JOIN relay_api_keys k ON k.account_id = a.id`
	if activeOnly {
		q += ` WHERE a.status = 'active'`
	}
	q += ` GROUP BY a.id ORDER BY a.created_at`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("accounts: list accounts: %w", err)
	}
	defer rows.Close()

	var out []AccountSummary
	for rows.Next() {
		var a AccountSummary
		if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.CreatedAt, &a.ActiveKeys, &a.LastUsed); err != nil {
			return nil, fmt.Errorf("accounts: scan account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DisableAccount sets an account's status to disabled.
func (s *Store) DisableAccount(ctx context.Context, accountID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE relay_accounts SET status = 'disabled', updated_at = now() WHERE id = $1`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("accounts: disable account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IssueKey mints a new API key for an account, persists only its prefix and
// HMAC hash, and returns the full token (to be shown to the operator once).
func (s *Store) IssueKey(ctx context.Context, accountID, env string, expires *time.Time) (token string, key APIKey, err error) {
	if len(s.pepper) == 0 {
		return "", APIKey{}, errors.New("accounts: api-key pepper is not configured")
	}
	if env != "live" && env != "test" {
		return "", APIKey{}, fmt.Errorf("accounts: invalid env %q (want live|test)", env)
	}
	exists, err := s.accountExists(ctx, accountID)
	if err != nil {
		return "", APIKey{}, err
	}
	if !exists {
		return "", APIKey{}, ErrNotFound
	}

	token, prefix, err := GenerateToken(env)
	if err != nil {
		return "", APIKey{}, fmt.Errorf("accounts: generate token: %w", err)
	}
	key = APIKey{ID: id.New(), AccountID: accountID, KeyPrefix: prefix, Env: env, ExpiresAt: expires}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO relay_api_keys (id, account_id, key_prefix, key_hash, env, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING created_at`,
		key.ID, accountID, prefix, HashToken(s.pepper, token), env, expires,
	).Scan(&key.CreatedAt)
	if err != nil {
		return "", APIKey{}, fmt.Errorf("accounts: insert key: %w", err)
	}
	return token, key, nil
}

// ListKeys returns an account's keys (never the secret).
func (s *Store) ListKeys(ctx context.Context, accountID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, account_id, key_prefix, env, created_at, last_used_at, expires_at, revoked_at
		 FROM relay_api_keys WHERE account_id = $1 ORDER BY created_at`,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("accounts: list keys: %w", err)
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.AccountID, &k.KeyPrefix, &k.Env, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt); err != nil {
			return nil, fmt.Errorf("accounts: scan key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeKey marks a key revoked by its prefix and returns the owning account.
// Already-revoked or unknown prefixes return ErrNotFound.
func (s *Store) RevokeKey(ctx context.Context, prefix string) (string, error) {
	var accountID string
	err := s.pool.QueryRow(ctx,
		`UPDATE relay_api_keys SET revoked_at = now()
		 WHERE key_prefix = $1 AND revoked_at IS NULL
		 RETURNING account_id`,
		prefix,
	).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("accounts: revoke key: %w", err)
	}
	return accountID, nil
}

// SetAPNsAllowlist replaces an account's APNs topic allowlist.
func (s *Store) SetAPNsAllowlist(ctx context.Context, accountID string, topics []string) error {
	return s.replaceAllowlist(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM relay_apns_allowlist WHERE account_id = $1`, accountID); err != nil {
			return err
		}
		for _, topic := range topics {
			if _, err := tx.Exec(ctx,
				`INSERT INTO relay_apns_allowlist (account_id, topic) VALUES ($1, $2)`,
				accountID, topic,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetFCMAllowlist replaces an account's FCM (project, packages) allowlist.
func (s *Store) SetFCMAllowlist(ctx context.Context, accountID, projectID string, packages []string) error {
	return s.replaceAllowlist(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM relay_fcm_allowlist WHERE account_id = $1`, accountID); err != nil {
			return err
		}
		for _, pkg := range packages {
			if _, err := tx.Exec(ctx,
				`INSERT INTO relay_fcm_allowlist (account_id, project_id, package_name) VALUES ($1, $2, $3)`,
				accountID, projectID, pkg,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

// Allowlists returns the APNs topics and FCM (project, package) pairs for an account.
func (s *Store) Allowlists(ctx context.Context, accountID string) (apns []string, fcm []FCMAllow, err error) {
	exists, err := s.accountExists(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, ErrNotFound
	}

	topicRows, err := s.pool.Query(ctx, `SELECT topic FROM relay_apns_allowlist WHERE account_id = $1 ORDER BY topic`, accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("accounts: list apns allowlist: %w", err)
	}
	defer topicRows.Close()
	for topicRows.Next() {
		var t string
		if err := topicRows.Scan(&t); err != nil {
			return nil, nil, err
		}
		apns = append(apns, t)
	}
	if err := topicRows.Err(); err != nil {
		return nil, nil, err
	}

	fcmRows, err := s.pool.Query(ctx, `SELECT project_id, package_name FROM relay_fcm_allowlist WHERE account_id = $1 ORDER BY project_id, package_name`, accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("accounts: list fcm allowlist: %w", err)
	}
	defer fcmRows.Close()
	for fcmRows.Next() {
		var f FCMAllow
		if err := fcmRows.Scan(&f.ProjectID, &f.PackageName); err != nil {
			return nil, nil, err
		}
		fcm = append(fcm, f)
	}
	return apns, fcm, fcmRows.Err()
}

// OpLogEntry is a redacted operational/audit log row. Empty string / zero
// fields are written as NULL. It carries no raw token or notification content.
type OpLogEntry struct {
	AccountID      string
	RequestID      string
	Event          string // required, e.g. "admin.key_issue"
	Actor          string
	Provider       string
	Outcome        string
	StatusCode     int
	ErrorCode      string
	UpstreamReason string
	TokenHash      string
	EgressIP       string
	LatencyMS      int
}

// WriteOpLog inserts an audit/operational record.
func (s *Store) WriteOpLog(ctx context.Context, e OpLogEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO relay_op_logs
		   (account_id, request_id, event, actor, provider, outcome, status_code, error_code, upstream_reason, token_hash, egress_ip, latency_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		nullStr(e.AccountID), nullStr(e.RequestID), e.Event, nullStr(e.Actor),
		nullStr(e.Provider), nullStr(e.Outcome), nullInt(e.StatusCode), nullStr(e.ErrorCode),
		nullStr(e.UpstreamReason), nullStr(e.TokenHash), nullStr(e.EgressIP), nullInt(e.LatencyMS),
	)
	if err != nil {
		return fmt.Errorf("accounts: write op log: %w", err)
	}
	return nil
}

// AuthRecord is the data needed to authenticate a presented API key.
type AuthRecord struct {
	AccountID     string
	KeyHash       []byte
	Env           string
	RevokedAt     *time.Time
	ExpiresAt     *time.Time
	AccountStatus string
}

// AuthLookup fetches the key + owning account by key prefix. Returns ErrNotFound
// when the prefix is unknown. Callers must still constant-time compare the hash
// and check revoked/expired/disabled — this method does not decide validity.
func (s *Store) AuthLookup(ctx context.Context, prefix string) (*AuthRecord, error) {
	var r AuthRecord
	err := s.pool.QueryRow(ctx,
		`SELECT k.account_id, k.key_hash, k.env, k.revoked_at, k.expires_at, a.status
		 FROM relay_api_keys k JOIN relay_accounts a ON a.id = k.account_id
		 WHERE k.key_prefix = $1`,
		prefix,
	).Scan(&r.AccountID, &r.KeyHash, &r.Env, &r.RevokedAt, &r.ExpiresAt, &r.AccountStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: auth lookup: %w", err)
	}
	return &r, nil
}

// TouchKeyLastUsed sets last_used_at for a key. The caller throttles how often
// this runs (≤ once/min via a Redis lock) so it is not a per-request write.
func (s *Store) TouchKeyLastUsed(ctx context.Context, prefix string) error {
	_, err := s.pool.Exec(ctx, `UPDATE relay_api_keys SET last_used_at = now() WHERE key_prefix = $1`, prefix)
	if err != nil {
		return fmt.Errorf("accounts: touch last_used: %w", err)
	}
	return nil
}

// APNsTopicAllowed reports whether the account may push to the given APNs topic.
func (s *Store) APNsTopicAllowed(ctx context.Context, accountID, topic string) (bool, error) {
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM relay_apns_allowlist WHERE account_id = $1 AND topic = $2`, accountID, topic).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("accounts: apns allow check: %w", err)
	}
	return true, nil
}

// FCMPairAllowed reports whether the project is allowed and whether the exact
// (project, package) pair is allowed, so the caller can return the precise
// project_not_allowed vs package_not_allowed error (spec §8.4).
func (s *Store) FCMPairAllowed(ctx context.Context, accountID, projectID, packageName string) (projectOK, packageOK bool, err error) {
	var one int
	perr := s.pool.QueryRow(ctx, `SELECT 1 FROM relay_fcm_allowlist WHERE account_id = $1 AND project_id = $2 LIMIT 1`, accountID, projectID).Scan(&one)
	switch {
	case errors.Is(perr, pgx.ErrNoRows):
		return false, false, nil
	case perr != nil:
		return false, false, fmt.Errorf("accounts: fcm project check: %w", perr)
	}
	kerr := s.pool.QueryRow(ctx, `SELECT 1 FROM relay_fcm_allowlist WHERE account_id = $1 AND project_id = $2 AND package_name = $3`, accountID, projectID, packageName).Scan(&one)
	switch {
	case errors.Is(kerr, pgx.ErrNoRows):
		return true, false, nil
	case kerr != nil:
		return true, false, fmt.Errorf("accounts: fcm package check: %w", kerr)
	}
	return true, true, nil
}

func (s *Store) accountExists(ctx context.Context, accountID string) (bool, error) {
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM relay_accounts WHERE id = $1`, accountID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("accounts: check account: %w", err)
	}
	return true, nil
}

func (s *Store) replaceAllowlist(ctx context.Context, accountID string, fn func(context.Context, pgx.Tx) error) error {
	exists, err := s.accountExists(ctx, accountID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("accounts: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if err := fn(ctx, tx); err != nil {
		return fmt.Errorf("accounts: set allowlist: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("accounts: commit allowlist: %w", err)
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(i int) any {
	if i == 0 {
		return nil
	}
	return i
}
