package config

import (
	"context"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Force the default path regardless of the ambient environment: setting the
	// vars to "" makes the env* helpers fall back to their defaults, and
	// t.Setenv restores the prior values when the test finishes.
	for _, k := range []string{
		"RELAY_LISTEN_ADDR", "RELAY_ENV", "RELAY_LOG_LEVEL",
		"RELAY_APNS_TEAM_ID", "RELAY_APNS_KEY_ID", "RELAY_APNS_KEY_PATH",
		"RELAY_APNS_EXPIRATION_TTL",
		"RELAY_REGISTRATION_APNS_TOPICS",
		"RELAY_READ_HEADER_TIMEOUT", "RELAY_READ_TIMEOUT", "RELAY_WRITE_TIMEOUT",
		"RELAY_IDLE_TIMEOUT", "RELAY_SHUTDOWN_TIMEOUT",
		"RELAY_MAX_HEADER_BYTES", "RELAY_MAX_BODY_BYTES",
	} {
		t.Setenv(k, "")
	}

	cfg, err := Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, defaultLogLevel)
	}
	if cfg.ReadHeaderTimeout != defaultReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %s, want %s", cfg.ReadHeaderTimeout, defaultReadHeaderTimeout)
	}
	if cfg.APNsExpirationTTL != defaultAPNsExpirationTTL {
		t.Errorf("APNsExpirationTTL = %s, want %s", cfg.APNsExpirationTTL, defaultAPNsExpirationTTL)
	}
	if cfg.MaxBodyBytes != defaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, defaultMaxBodyBytes)
	}
	if got := cfg.RegistrationAPNsTopics; len(got) != 1 || got[0] != defaultRegistrationAPNs {
		t.Errorf("RegistrationAPNsTopics = %v, want [%s]", got, defaultRegistrationAPNs)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("RELAY_LISTEN_ADDR", "127.0.0.1:9999")
	t.Setenv("RELAY_ENV", "production")
	t.Setenv("RELAY_READ_TIMEOUT", "30s")
	t.Setenv("RELAY_APNS_TEAM_ID", "TEAM123456")
	t.Setenv("RELAY_APNS_KEY_ID", "KEY1234567")
	t.Setenv("RELAY_APNS_KEY_PATH", "/run/secrets/AuthKey_KEY1234567.p8")
	t.Setenv("RELAY_APNS_EXPIRATION_TTL", "30m")
	t.Setenv("RELAY_REGISTRATION_APNS_TOPICS", "org.siloserver.silo")

	cfg, err := Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9999", cfg.ListenAddr)
	}
	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want production", cfg.Environment)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %s, want 30s", cfg.ReadTimeout)
	}
	if !cfg.APNsConfigured() || cfg.APNsTeamID != "TEAM123456" || cfg.APNsKeyID != "KEY1234567" || cfg.APNsKeyPath == "" {
		t.Errorf("APNs config not loaded: %+v", cfg)
	}
	if cfg.APNsExpirationTTL != 30*time.Minute {
		t.Errorf("APNsExpirationTTL = %s, want 30m", cfg.APNsExpirationTTL)
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		return &Config{
			ListenAddr:        ":8080",
			Environment:       "development",
			LogLevel:          "info",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       120 * time.Second,
			ShutdownTimeout:   20 * time.Second,
			APNsExpirationTTL: 15 * time.Minute,
			MaxHeaderBytes:    1 << 20,
			MaxBodyBytes:      16 << 10,
			RegistrationAPNsTopics: []string{
				defaultRegistrationAPNs,
			},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	apns := base()
	apns.APNsTeamID = "TEAM123456"
	apns.APNsKeyID = "KEY1234567"
	apns.APNsKeyPath = "/run/secrets/key.p8"
	if err := apns.Validate(); err != nil {
		t.Fatalf("valid APNs config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"empty listen addr": func(c *Config) { c.ListenAddr = "" },
		"bad log level":     func(c *Config) { c.LogLevel = "verbose" },
		"bad environment":   func(c *Config) { c.Environment = "prod" },
		"zero read timeout": func(c *Config) { c.ReadTimeout = 0 },
		"zero apns ttl":     func(c *Config) { c.APNsExpirationTTL = 0 },
		"zero body cap":     func(c *Config) { c.MaxBodyBytes = 0 },
		"partial apns":      func(c *Config) { c.APNsTeamID = "TEAM123456" },
		"empty topics":      func(c *Config) { c.RegistrationAPNsTopics = nil },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", name)
		}
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	t.Setenv("RELAY_READ_TIMEOUT", "thirty-seconds")
	if _, err := Load(context.Background()); err == nil {
		t.Fatal("Load() = nil error, want hard error for an unparseable duration")
	}
}

func TestLoadRejectsBadInt(t *testing.T) {
	t.Setenv("RELAY_MAX_BODY_BYTES", "16k")
	if _, err := Load(context.Background()); err == nil {
		t.Fatal("Load() = nil error, want hard error for an unparseable integer")
	}
}
