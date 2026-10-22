package yabber

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPResolver struct {
	trusted []netip.Prefix
}

func newClientIPResolver(values []string) (*clientIPResolver, error) {
	resolver := &clientIPResolver{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", value)
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}
		resolver.trusted = append(resolver.trusted, prefix.Masked())
	}
	return resolver, nil
}

// resolve returns the client address and whether the direct peer is a
// trusted proxy. For a trusted peer it walks X-Forwarded-For from the right,
// skipping further trusted proxies, and stops at the first untrusted or
// malformed hop, so clients cannot spoof addresses by prepending entries.
func (r *clientIPResolver) resolve(request *http.Request) (netip.Addr, bool) {
	peer := remoteAddress(request.RemoteAddr)
	if !peer.IsValid() || !r.isTrusted(peer) {
		return peer, false
	}
	var hops []string
	for _, value := range request.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		address, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = address.Unmap()
		if !r.isTrusted(client) {
			break
		}
	}
	return client, true
}

func (r *clientIPResolver) isTrusted(address netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func remoteAddress(value string) netip.Addr {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}
