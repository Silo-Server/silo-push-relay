package id

import (
	"strings"
	"testing"
	"time"
)

func TestNewFormat(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	v := New()
	if len(v) != 26 {
		t.Fatalf("len(New()) = %d, want 26", len(v))
	}
	for _, c := range v {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("New() = %q contains non-Crockford char %q", v, c)
		}
	}
}

func TestNewUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v := New()
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate id generated: %q", v)
		}
		seen[v] = struct{}{}
	}
}

// TestNewMonotonic guards the property that makes ULIDs worth using: IDs minted
// later sort lexicographically after earlier ones (the timestamp occupies the
// high-order characters). A regression in the timestamp byte packing would slip
// past the format and uniqueness tests but fail here.
func TestNewMonotonic(t *testing.T) {
	a := New()
	time.Sleep(2 * time.Millisecond)
	b := New()
	if a >= b {
		t.Errorf("ids not time-ordered: a=%q should sort before b=%q", a, b)
	}
}
