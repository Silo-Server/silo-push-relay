package accounts

import (
	"strings"
	"testing"
)

func TestGenerateTokenFormat(t *testing.T) {
	token, prefix, err := GenerateToken("live")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(token, "rk_live_") {
		t.Errorf("token %q missing rk_live_ scheme", token)
	}
	if !strings.HasPrefix(token, prefix) {
		t.Errorf("token %q does not start with its prefix %q", token, prefix)
	}
	if got, err := PrefixOf(token); err != nil || got != prefix {
		t.Errorf("PrefixOf(token) = %q,%v; want %q,nil", got, err, prefix)
	}
	// Two tokens must differ.
	other, _, _ := GenerateToken("live")
	if other == token {
		t.Error("GenerateToken returned identical tokens")
	}
}

func TestPrefixOfRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "nope", "rk_live", "rk__secret", "rk_live_", "xx_live_abcdefgh"} {
		if _, err := PrefixOf(bad); err == nil {
			t.Errorf("PrefixOf(%q) = nil error, want ErrInvalidToken", bad)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	pepper := []byte("test-pepper-which-is-long-enough")
	token, _, _ := GenerateToken("test")

	h := HashToken(pepper, token)
	if len(h) != 32 {
		t.Fatalf("hash length = %d, want 32", len(h))
	}
	// Deterministic under the same pepper.
	if string(HashToken(pepper, token)) != string(h) {
		t.Error("HashToken not deterministic")
	}
	// Verifies the right token.
	if !VerifyToken(pepper, token, h) {
		t.Error("VerifyToken rejected the correct token")
	}
	// Rejects a different token.
	other, _, _ := GenerateToken("test")
	if VerifyToken(pepper, other, h) {
		t.Error("VerifyToken accepted a wrong token")
	}
	// Rejects under a different pepper.
	if VerifyToken([]byte("a-different-pepper-of-good-length"), token, h) {
		t.Error("VerifyToken accepted under the wrong pepper")
	}
}
