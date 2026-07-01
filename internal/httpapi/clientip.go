package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// resolveClientIP returns the caller's IP. The relay sits behind a TLS load
// balancer, so RemoteAddr is the LB. Only when the immediate peer is in the
// trusted-proxy set does the relay read the right-most untrusted hop from the
// LB-set X-Forwarded-For. A caller-supplied X-Forwarded-For from an untrusted
// peer is ignored — otherwise an attacker could forge IPs to evade the per-IP
// auth-failure limiter and poison op-log egress_ip (spec §8.2).
func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := remoteIP(r.RemoteAddr)
	if !peer.IsValid() {
		return ""
	}
	if !ipInAny(peer, trusted) {
		return peer.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if !ipInAny(addr, trusted) {
			return addr.String()
		}
	}
	return peer.String()
}

func remoteIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func ipInAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
