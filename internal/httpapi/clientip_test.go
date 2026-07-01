package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func ipReq(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	cases := []struct {
		name    string
		remote  string
		xff     string
		trusted []netip.Prefix
		want    string
	}{
		{"untrusted peer ignores forged XFF", "203.0.113.5:443", "1.2.3.4", trusted, "203.0.113.5"},
		{"trusted peer takes rightmost untrusted hop", "10.1.2.3:443", "203.0.113.9, 10.9.9.9", trusted, "203.0.113.9"},
		{"trusted peer with no XFF falls back to peer", "10.1.2.3:443", "", trusted, "10.1.2.3"},
		{"no trusted set uses RemoteAddr", "203.0.113.5:443", "1.2.3.4", nil, "203.0.113.5"},
		{"unparseable remote addr returns empty", "not a remote addr", "", trusted, ""},
	}
	for _, c := range cases {
		if got := resolveClientIP(ipReq(c.remote, c.xff), c.trusted); got != c.want {
			t.Errorf("%s: resolveClientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		wantOK bool
	}{
		{"Bearer rk_live_abc", "rk_live_abc", true},
		{"bearer rk_live_abc", "rk_live_abc", true}, // case-insensitive scheme
		{"Bearer   rk_live_abc  ", "rk_live_abc", true},
		{"", "", false},
		{"Basic xyz", "", false},
		{"Bearer ", "", false},
		{"rk_live_abc", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got, ok := bearerToken(r)
		if ok != c.wantOK || got != c.want {
			t.Errorf("bearerToken(%q) = (%q,%v), want (%q,%v)", c.header, got, ok, c.want, c.wantOK)
		}
	}
}
