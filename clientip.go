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
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", value)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		resolver.trusted = append(resolver.trusted, prefix.Masked())
	}
	return resolver, nil
}

func (r *clientIPResolver) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		state := requestStateFromContext(request.Context())
		if state != nil {
			state.ClientIP = r.resolve(request)
		}
		next.ServeHTTP(w, request)
	})
}

func (r *clientIPResolver) resolve(request *http.Request) string {
	remote := remoteAddress(request.RemoteAddr)
	if !remote.IsValid() {
		return ""
	}
	if !r.isTrusted(remote) {
		return remote.String()
	}

	values := request.Header.Values("X-Forwarded-For")
	var addresses []netip.Addr
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			address, err := netip.ParseAddr(strings.TrimSpace(part))
			if err == nil {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	for i := len(addresses) - 1; i >= 0; i-- {
		if !r.isTrusted(addresses[i]) {
			return addresses[i].String()
		}
	}
	if len(addresses) > 0 {
		return addresses[0].String()
	}
	return remote.String()
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
	host := value
	if parsedHost, _, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}
