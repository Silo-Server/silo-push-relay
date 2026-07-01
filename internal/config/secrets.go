package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Datastore / secret environment variables. Per spec §14.3 the DSN and pepper
// come from a secret manager in production; an env fallback is supported (and is
// the Phase 1 path). The APNs .p8 key and FCM credentials are never read from
// env — those land via the SecretSource in a later phase.
const (
	envDatabaseURL    = "RELAY_DATABASE_URL"
	envRedisURL       = "RELAY_REDIS_URL"
	envAPIKeyPepper   = "RELAY_API_KEY_PEPPER"
	envTrustedProxies = "RELAY_TRUSTED_PROXIES"
	minPepperLen      = 16
)

// DatabaseURL returns the PostgreSQL DSN. It is required: the relay and relayctl
// both need a database.
func DatabaseURL() (string, error) {
	v := os.Getenv(envDatabaseURL)
	if v == "" {
		return "", fmt.Errorf("config: %s is required", envDatabaseURL)
	}
	return v, nil
}

// RedisURL returns the Redis connection URL (redis:// or rediss://). Required:
// rate limiting and idempotency need Redis.
func RedisURL() (string, error) {
	v := os.Getenv(envRedisURL)
	if v == "" {
		return "", fmt.Errorf("config: %s is required", envRedisURL)
	}
	return v, nil
}

// APIKeyPepper returns the server-side pepper used to HMAC API keys. It must be
// present and reasonably long; key hashing is meaningless without it.
func APIKeyPepper() ([]byte, error) {
	v := os.Getenv(envAPIKeyPepper)
	if len(v) < minPepperLen {
		return nil, fmt.Errorf("config: %s must be set and at least %d characters", envAPIKeyPepper, minPepperLen)
	}
	return []byte(v), nil
}

// TrustedProxies parses RELAY_TRUSTED_PROXIES (comma-separated CIDRs) into
// prefixes. When the immediate peer is in this set, the relay reads the client
// IP from the LB-set forwarding header; otherwise it uses RemoteAddr. Empty is
// valid (no trusted proxy — RemoteAddr is always used).
func TrustedProxies() ([]netip.Prefix, error) {
	v := strings.TrimSpace(os.Getenv(envTrustedProxies))
	if v == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("config: %s: invalid CIDR %q: %w", envTrustedProxies, part, err)
		}
		out = append(out, p)
	}
	return out, nil
}
