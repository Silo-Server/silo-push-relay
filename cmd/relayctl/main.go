// Command relayctl is the admin CLI for the Silo push relay. It manages relay
// accounts, API keys, and per-account allowlists by writing directly to the
// relay's PostgreSQL database — there is no public admin HTTP API (spec §5.6).
//
// Configuration comes from the environment:
//   - RELAY_DATABASE_URL   (required) privileged DSN
//   - RELAY_API_KEY_PEPPER (required only for `key issue`)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relayctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		usage(os.Stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "migrate":
		return cmdMigrate(args[1:])
	case "account":
		return cmdAccount(args[1:])
	case "key":
		return cmdKey(args[1:])
	case "allowlist":
		return cmdAllowlist(args[1:])
	case "-h", "--help", "help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// openStore opens the database and returns a data-access Store. When needPepper
// is true the API-key pepper is loaded too (required to mint keys).
func openStore(ctx context.Context, needPepper bool) (*accounts.Store, *store.DB, error) {
	dsn, err := config.DatabaseURL()
	if err != nil {
		return nil, nil, err
	}
	var pepper []byte
	if needPepper {
		if pepper, err = config.APIKeyPepper(); err != nil {
			return nil, nil, err
		}
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	return accounts.New(db.Pool, pepper), db, nil
}

func cmdMigrate(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: relayctl migrate <up|status>")
	}
	dsn, err := config.DatabaseURL()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch args[0] {
	case "up":
		return store.Migrate(ctx, dsn)
	case "status":
		return store.MigrationStatus(ctx, dsn)
	default:
		return fmt.Errorf("unknown migrate subcommand %q (want up|status)", args[0])
	}
}

func cmdAccount(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: relayctl account <create|list|disable>")
	}
	ctx := context.Background()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("account create", flag.ContinueOnError)
		name := fs.String("name", "", "operator-facing label (required)")
		note := fs.String("note", "", "optional note")
		actor := fs.String("actor", "", "operator identity for the audit log (default: OS user)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("account create: --name is required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		a, err := s.CreateAccount(ctx, *name, *note)
		if err != nil {
			return err
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.account_create", AccountID: a.ID, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("account created\n  id:     %s\n  name:   %s\n  status: %s\n", a.ID, a.Name, a.Status)
		return nil

	case "list":
		fs := flag.NewFlagSet("account list", flag.ContinueOnError)
		activeOnly := fs.Bool("active", false, "only active accounts")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		list, err := s.ListAccounts(ctx, *activeOnly)
		if err != nil {
			return err
		}
		printAccounts(list)
		return nil

	case "disable":
		fs := flag.NewFlagSet("account disable", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		actor := fs.String("actor", "", "operator identity for the audit log")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *acct == "" {
			return errors.New("account disable: --account is required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := s.DisableAccount(ctx, *acct); err != nil {
			return notFound(err, "account", *acct)
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.account_disable", AccountID: *acct, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("account %s disabled\n", *acct)
		return nil

	default:
		return fmt.Errorf("unknown account subcommand %q (want create|list|disable)", args[0])
	}
}

func cmdKey(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: relayctl key <issue|list|revoke>")
	}
	ctx := context.Background()
	switch args[0] {
	case "issue":
		fs := flag.NewFlagSet("key issue", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		env := fs.String("env", "live", "key environment: live|test")
		expires := fs.Duration("expires", 0, "optional expiry from now, e.g. 720h")
		actor := fs.String("actor", "", "operator identity for the audit log")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *acct == "" {
			return errors.New("key issue: --account is required")
		}
		s, db, err := openStore(ctx, true)
		if err != nil {
			return err
		}
		defer db.Close()
		var exp *time.Time
		if *expires > 0 {
			t := time.Now().Add(*expires)
			exp = &t
		}
		token, key, err := s.IssueKey(ctx, *acct, *env, exp)
		if err != nil {
			return notFound(err, "account", *acct)
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.key_issue", AccountID: *acct, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("API key issued (account %s, env %s)\n\n", key.AccountID, key.Env)
		fmt.Printf("    %s\n\n", token)
		fmt.Println("This is the ONLY time the full key is shown. Store it now; only its hash is kept.")
		fmt.Printf("prefix: %s\n", key.KeyPrefix)
		return nil

	case "list":
		fs := flag.NewFlagSet("key list", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *acct == "" {
			return errors.New("key list: --account is required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		keys, err := s.ListKeys(ctx, *acct)
		if err != nil {
			return err
		}
		printKeys(keys)
		return nil

	case "revoke":
		fs := flag.NewFlagSet("key revoke", flag.ContinueOnError)
		prefix := fs.String("key-prefix", "", "key prefix to revoke (required)")
		actor := fs.String("actor", "", "operator identity for the audit log")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *prefix == "" {
			return errors.New("key revoke: --key-prefix is required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		accountID, err := s.RevokeKey(ctx, *prefix)
		if err != nil {
			return notFound(err, "active key with prefix", *prefix)
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.key_revoke", AccountID: accountID, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("key %s revoked\n", *prefix)
		return nil

	default:
		return fmt.Errorf("unknown key subcommand %q (want issue|list|revoke)", args[0])
	}
}

func cmdAllowlist(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: relayctl allowlist <apns set|fcm set|show>")
	}
	ctx := context.Background()
	switch args[0] {
	case "apns":
		if len(args) < 2 || args[1] != "set" {
			return errors.New("usage: relayctl allowlist apns set --account <id> --topics a,b,c")
		}
		fs := flag.NewFlagSet("allowlist apns set", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		topics := fs.String("topics", "", "comma-separated APNs topics (required)")
		actor := fs.String("actor", "", "operator identity for the audit log")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *acct == "" || *topics == "" {
			return errors.New("allowlist apns set: --account and --topics are required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := s.SetAPNsAllowlist(ctx, *acct, splitCSV(*topics)); err != nil {
			return notFound(err, "account", *acct)
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.allowlist_apns_set", AccountID: *acct, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("APNs allowlist for %s set to: %s\n", *acct, strings.Join(splitCSV(*topics), ", "))
		return nil

	case "fcm":
		if len(args) < 2 || args[1] != "set" {
			return errors.New("usage: relayctl allowlist fcm set --account <id> --project <id> --packages a,b")
		}
		fs := flag.NewFlagSet("allowlist fcm set", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		project := fs.String("project", "", "Firebase project id (required)")
		packages := fs.String("packages", "", "comma-separated package names (required)")
		actor := fs.String("actor", "", "operator identity for the audit log")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *acct == "" || *project == "" || *packages == "" {
			return errors.New("allowlist fcm set: --account, --project and --packages are required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := s.SetFCMAllowlist(ctx, *acct, *project, splitCSV(*packages)); err != nil {
			return notFound(err, "account", *acct)
		}
		audit(ctx, s, accounts.OpLogEntry{Event: "admin.allowlist_fcm_set", AccountID: *acct, Actor: resolveActor(*actor), Outcome: "accepted"})
		fmt.Printf("FCM allowlist for %s set to project %s, packages: %s\n", *acct, *project, strings.Join(splitCSV(*packages), ", "))
		return nil

	case "show":
		fs := flag.NewFlagSet("allowlist show", flag.ContinueOnError)
		acct := fs.String("account", "", "account id (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *acct == "" {
			return errors.New("allowlist show: --account is required")
		}
		s, db, err := openStore(ctx, false)
		if err != nil {
			return err
		}
		defer db.Close()
		apns, fcm, err := s.Allowlists(ctx, *acct)
		if err != nil {
			return notFound(err, "account", *acct)
		}
		fmt.Printf("APNs topics: %s\n", orNone(apns))
		if len(fcm) == 0 {
			fmt.Println("FCM (project, package): (none)")
		} else {
			fmt.Println("FCM (project, package):")
			for _, f := range fcm {
				fmt.Printf("  %s  %s\n", f.ProjectID, f.PackageName)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown allowlist subcommand %q (want apns|fcm|show)", args[0])
	}
}

// ----- helpers -----

func audit(ctx context.Context, s *accounts.Store, e accounts.OpLogEntry) {
	if err := s.WriteOpLog(ctx, e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log write failed: %v\n", err)
	}
}

func resolveActor(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

// notFound maps accounts.ErrNotFound to a friendly message; other errors pass through.
func notFound(err error, kind, ref string) error {
	if errors.Is(err, accounts.ErrNotFound) {
		return fmt.Errorf("%s %q not found", kind, ref)
	}
	return err
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func printAccounts(list []accounts.AccountSummary) {
	if len(list) == 0 {
		fmt.Println("(no accounts)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tNAME\tSTATUS\tACTIVE KEYS\tLAST USED\tCREATED")
	for _, a := range list {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			a.ID, a.Name, a.Status, a.ActiveKeys, fmtTime(a.LastUsed), a.CreatedAt.UTC().Format(time.RFC3339))
	}
	_ = w.Flush()
}

func printKeys(keys []accounts.APIKey) {
	if len(keys) == 0 {
		fmt.Println("(no keys)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PREFIX\tENV\tCREATED\tLAST USED\tEXPIRES\tREVOKED")
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			k.KeyPrefix, k.Env, k.CreatedAt.UTC().Format(time.RFC3339),
			fmtTime(k.LastUsedAt), fmtTime(k.ExpiresAt), fmtTime(k.RevokedAt))
	}
	_ = w.Flush()
}

func usage(w *os.File) {
	_, _ = fmt.Fprint(w, `relayctl — Silo push relay admin CLI

Usage:
  relayctl <command> [flags]

Commands:
  migrate up|status
  account create --name <label> [--note <text>]
  account list [--active]
  account disable --account <id>
  key issue --account <id> [--env live|test] [--expires <dur>]
  key list --account <id>
  key revoke --key-prefix <prefix>
  allowlist apns set --account <id> --topics a,b,c
  allowlist fcm set --account <id> --project <id> --packages a,b
  allowlist show --account <id>

Environment:
  RELAY_DATABASE_URL    required: privileged PostgreSQL DSN
  RELAY_API_KEY_PEPPER  required for 'key issue'
`)
}
