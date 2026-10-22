package yabber

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// hostTable maps host patterns to values. Patterns are exact names,
// single-label wildcards ("*.example.com"), or the catch-all "*".
type hostTable[T any] struct {
	exact    map[string]T
	wildcard map[string]T // keyed by the parent domain
	fallback *T
}

func newHostTable[T any]() *hostTable[T] {
	return &hostTable[T]{exact: make(map[string]T), wildcard: make(map[string]T)}
}

// set stores value for pattern and reports whether pattern was already set.
func (t *hostTable[T]) set(pattern string, value T) (replaced bool) {
	switch {
	case pattern == "*":
		replaced = t.fallback != nil
		t.fallback = &value
	case strings.HasPrefix(pattern, "*."):
		_, replaced = t.wildcard[pattern[2:]]
		t.wildcard[pattern[2:]] = value
	default:
		_, replaced = t.exact[pattern]
		t.exact[pattern] = value
	}
	return replaced
}

// get returns the value stored for exactly pattern.
func (t *hostTable[T]) get(pattern string) (T, bool) {
	switch {
	case pattern == "*":
		if t.fallback != nil {
			return *t.fallback, true
		}
		var zero T
		return zero, false
	case strings.HasPrefix(pattern, "*."):
		value, ok := t.wildcard[pattern[2:]]
		return value, ok
	default:
		value, ok := t.exact[pattern]
		return value, ok
	}
}

// match finds the value for a normalized hostname: an exact entry first, then
// a wildcard for its parent domain, then the catch-all.
func (t *hostTable[T]) match(host string) (T, bool) {
	if value, ok := t.exact[host]; ok {
		return value, true
	}
	if label, parent, ok := strings.Cut(host, "."); ok && label != "" {
		if value, ok := t.wildcard[parent]; ok {
			return value, true
		}
	}
	if t.fallback != nil {
		return *t.fallback, true
	}
	var zero T
	return zero, false
}

func (t *hostTable[T]) empty() bool {
	return len(t.exact) == 0 && len(t.wildcard) == 0 && t.fallback == nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// requestHost extracts the normalized hostname from a Host header or SNI
// value, dropping any port and IPv6 brackets.
func requestHost(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	return normalizeHost(strings.Trim(hostport, "[]"))
}

func validateHostPattern(pattern string) error {
	if pattern == "" {
		return errors.New("empty host")
	}
	if _, err := netip.ParseAddr(pattern); err == nil || pattern == "*" {
		return nil
	}
	name := strings.TrimPrefix(pattern, "*.")
	if name == "" || strings.Contains(name, "*") || strings.ContainsAny(name, "/:@ \t\r\n") {
		return fmt.Errorf("invalid host %q", pattern)
	}
	return nil
}
