// Package migrations embeds the relay's Goose SQL migrations so they ship inside
// the binary and can be applied by both cmd/relay (startup --migrate) and
// cmd/relayctl (migrate up/status) without shipping loose .sql files.
package migrations

import "embed"

// FS holds the timestamped Goose migration files under sql/.
//
//go:embed sql/*.sql
var FS embed.FS
