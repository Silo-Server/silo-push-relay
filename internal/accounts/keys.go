package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

// API-key format: rk_<env>_<secret>, where <secret> is 32 bytes of CSPRNG
// output, base64url-encoded (no padding). The lookup handle stored in cleartext
// is the prefix rk_<env>_<first prefixSecretChars of the secret>; the full token
// is hashed with HMAC-SHA256(pepper, token) and only the hash is persisted
// (spec §8.2). A fast keyed hash is correct here because the token is
// high-entropy — slow KDFs (argon2id) are for low-entropy passwords.
const (
	keyScheme         = "rk"
	secretBytes       = 32 // 256 bits of entropy
	prefixSecretChars = 8  // chars of the encoded secret kept in the public prefix
)

// ErrInvalidToken is returned when a presented token is not well-formed.
var ErrInvalidToken = errors.New("accounts: malformed api key token")

// GenerateToken mints a new API key for the given env ("live"|"test"). It
// returns the full token (shown to the operator exactly once) and the non-secret
// prefix used as the indexed lookup handle.
func GenerateToken(env string) (token, prefix string, err error) {
	b := make([]byte, secretBytes)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	token = keyScheme + "_" + env + "_" + secret
	prefix = keyScheme + "_" + env + "_" + secret[:prefixSecretChars]
	return token, prefix, nil
}

// PrefixOf derives the public lookup prefix from a presented token without
// validating its secret. It is the value matched against relay_api_keys.key_prefix.
func PrefixOf(token string) (string, error) {
	scheme, env, secret, ok := splitToken(token)
	if !ok || len(secret) < prefixSecretChars {
		return "", ErrInvalidToken
	}
	return scheme + "_" + env + "_" + secret[:prefixSecretChars], nil
}

// HashToken computes HMAC-SHA256(pepper, token) — the value stored in
// relay_api_keys.key_hash and compared on each request.
func HashToken(pepper []byte, token string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(token))
	return mac.Sum(nil)
}

// VerifyToken reports whether token hashes (under pepper) to storedHash, using a
// constant-time comparison. Callers verifying an unknown prefix should still call
// this against a decoy hash so timing does not reveal prefix existence (spec §8.2).
func VerifyToken(pepper []byte, token string, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(HashToken(pepper, token), storedHash) == 1
}

// splitToken parses rk_<env>_<secret>. The secret may itself contain '_'
// (base64url alphabet includes it), so only the first two underscores are split.
func splitToken(token string) (scheme, env, secret string, ok bool) {
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 || parts[0] != keyScheme || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
