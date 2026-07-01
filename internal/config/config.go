// Package config loads and validates the relay's runtime configuration.
//
// Non-secret tuning (listen address, timeouts, log level, environment label)
// comes from RELAY_* environment variables with safe defaults. Credentials
// (the APNs .p8 key, the FCM service-account JSON, the API-key HMAC pepper, and
// datastore DSNs) are resolved from a secret manager in a later phase via the
// SecretSource interface; Phase 0 wires none of them.
package config

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Default non-secret tuning values. Each may be overridden by the matching
// RELAY_* environment variable.
const (
	defaultListenAddr        = ":8080"
	defaultEnvironment       = "development"
	defaultLogLevel          = "info"
	defaultRegistrationAPNs  = "org.siloserver.silo"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 15 * time.Second
	defaultIdleTimeout       = 120 * time.Second
	defaultShutdownTimeout   = 20 * time.Second
	defaultAPNsExpirationTTL = 15 * time.Minute
	defaultMaxHeaderBytes    = 1 << 20  // 1 MiB
	defaultMaxBodyBytes      = 16 << 10 // 16 KiB; well above the ~1 KB legitimate send body
)

var (
	validLogLevels    = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	validEnvironments = map[string]bool{"development": true, "staging": true, "production": true}
)

// SecretSource resolves named secrets. Concrete implementations (secret
// manager, mounted file) land in a later phase; Phase 0 defines the seam only
// so credential loading has a stable interface to target.
type SecretSource interface {
	Get(ctx context.Context, name string) (string, error)
}

// Config is the validated runtime configuration consumed by cmd/relay.
type Config struct {
	ListenAddr  string // host:port the HTTP server binds
	Environment string // deployment label, safe to log: development|staging|production
	LogLevel    string // debug|info|warn|error

	APNsTeamID        string
	APNsKeyID         string
	APNsKeyPath       string
	APNsExpirationTTL time.Duration

	RegistrationAPNsTopics []string

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
	MaxBodyBytes      int64
}

// Load reads configuration from the environment, applies defaults, and
// validates the result. A malformed RELAY_* value (e.g. an unparseable
// duration or integer) is a hard error, not a silent fallback to the default —
// the process must refuse to start rather than run with a value the operator
// did not intend.
func Load(_ context.Context) (*Config, error) {
	l := &envLoader{}
	cfg := &Config{
		ListenAddr:  l.str("RELAY_LISTEN_ADDR", defaultListenAddr),
		Environment: strings.ToLower(l.str("RELAY_ENV", defaultEnvironment)),
		LogLevel:    strings.ToLower(l.str("RELAY_LOG_LEVEL", defaultLogLevel)),
		APNsTeamID:  strings.TrimSpace(l.str("RELAY_APNS_TEAM_ID", "")),
		APNsKeyID:   strings.TrimSpace(l.str("RELAY_APNS_KEY_ID", "")),
		APNsKeyPath: strings.TrimSpace(l.str("RELAY_APNS_KEY_PATH", "")),
		APNsExpirationTTL: l.dur(
			"RELAY_APNS_EXPIRATION_TTL",
			defaultAPNsExpirationTTL,
		),
		RegistrationAPNsTopics: l.csv(
			"RELAY_REGISTRATION_APNS_TOPICS",
			defaultRegistrationAPNs,
		),
		ReadHeaderTimeout: l.dur("RELAY_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout),
		ReadTimeout:       l.dur("RELAY_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:      l.dur("RELAY_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:       l.dur("RELAY_IDLE_TIMEOUT", defaultIdleTimeout),
		ShutdownTimeout:   l.dur("RELAY_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		MaxHeaderBytes:    int(l.num("RELAY_MAX_HEADER_BYTES", defaultMaxHeaderBytes)),
		MaxBodyBytes:      l.num("RELAY_MAX_BODY_BYTES", defaultMaxBodyBytes),
	}
	if len(l.errs) > 0 {
		return nil, fmt.Errorf("config: %s", strings.Join(l.errs, "; "))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate reports the first semantic configuration problem it finds (values
// that parsed but are out of range or not in an allowed set).
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: RELAY_LISTEN_ADDR must not be empty")
	}
	if !validEnvironments[c.Environment] {
		return fmt.Errorf("config: invalid RELAY_ENV %q (want development|staging|production)", c.Environment)
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("config: invalid RELAY_LOG_LEVEL %q (want debug|info|warn|error)", c.LogLevel)
	}
	apnsSet := 0
	for _, value := range []string{c.APNsTeamID, c.APNsKeyID, c.APNsKeyPath} {
		if value != "" {
			apnsSet++
		}
	}
	if apnsSet != 0 && apnsSet != 3 {
		return fmt.Errorf("config: RELAY_APNS_TEAM_ID, RELAY_APNS_KEY_ID, and RELAY_APNS_KEY_PATH must be set together")
	}
	if len(c.RegistrationAPNsTopics) == 0 {
		return fmt.Errorf("config: RELAY_REGISTRATION_APNS_TOPICS must include at least one APNs topic")
	}
	for _, topic := range c.RegistrationAPNsTopics {
		if strings.TrimSpace(topic) == "" {
			return fmt.Errorf("config: RELAY_REGISTRATION_APNS_TOPICS contains an empty topic")
		}
	}
	timeouts := []struct {
		name string
		val  time.Duration
	}{
		{"RELAY_READ_HEADER_TIMEOUT", c.ReadHeaderTimeout},
		{"RELAY_READ_TIMEOUT", c.ReadTimeout},
		{"RELAY_WRITE_TIMEOUT", c.WriteTimeout},
		{"RELAY_IDLE_TIMEOUT", c.IdleTimeout},
		{"RELAY_SHUTDOWN_TIMEOUT", c.ShutdownTimeout},
		{"RELAY_APNS_EXPIRATION_TTL", c.APNsExpirationTTL},
	}
	for _, t := range timeouts {
		if t.val <= 0 {
			return fmt.Errorf("config: %s must be > 0, got %s", t.name, t.val)
		}
	}
	if c.MaxHeaderBytes <= 0 {
		return fmt.Errorf("config: RELAY_MAX_HEADER_BYTES must be > 0")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: RELAY_MAX_BODY_BYTES must be > 0")
	}
	return nil
}

func (c *Config) APNsConfigured() bool {
	return c != nil && c.APNsTeamID != "" && c.APNsKeyID != "" && c.APNsKeyPath != ""
}

// envLoader reads RELAY_* environment variables, collecting parse errors so
// Load can fail with all of them at once instead of silently defaulting.
type envLoader struct {
	errs []string
}

func (l *envLoader) str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func (l *envLoader) dur(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}

func (l *envLoader) num(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s: invalid integer %q", key, v))
		return def
	}
	return n
}

func (l *envLoader) csv(key, def string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		v = def
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
