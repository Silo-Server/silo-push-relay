// Package observability holds logging and (in later phases) metrics wiring for
// the relay. The logger emits structured JSON and is the foundation for the
// redaction discipline the spec requires: device tokens, Authorization headers,
// API keys, and request payloads must never reach a log line.
package observability

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger builds a JSON slog.Logger at the given level
// ("debug"|"info"|"warn"|"error"). Unknown levels fall back to info.
func NewLogger(level string, w io.Writer) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parseLevel(level)})
	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
