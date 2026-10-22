package yabber

import (
	"context"
	"net/http"
	"net/netip"
)

// Middleware wraps an HTTP handler.
type Middleware func(http.Handler) http.Handler

// Chain wraps handler so that middleware runs in declaration order.
func Chain(handler http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}

// requestState is per-request routing metadata. It is only touched by the
// goroutine serving the request.
type requestState struct {
	id          string
	listener    string
	site        string
	route       string
	clientIP    netip.Addr
	trustedPeer bool
	rejectedBy  string
	applied     map[string]struct{}
}

// markApplied records that a policy ran and reports whether it was new.
func (s *requestState) markApplied(policy string) bool {
	if _, ok := s.applied[policy]; ok {
		return false
	}
	if s.applied == nil {
		s.applied = make(map[string]struct{})
	}
	s.applied[policy] = struct{}{}
	return true
}

// RequestInfo is Yabber's routing metadata for a request.
type RequestInfo struct {
	RequestID string `json:"request_id"`
	Listener  string `json:"listener"`
	Site      string `json:"site,omitempty"`
	Route     string `json:"route,omitempty"`
	// ClientIP is the peer address, or the forwarded client address when the
	// peer is a trusted proxy.
	ClientIP string `json:"client_ip,omitempty"`
}

// Info returns routing metadata for a request served by Yabber, or the zero
// value for any other request.
func Info(r *http.Request) RequestInfo {
	state := requestStateFrom(r.Context())
	if state == nil {
		return RequestInfo{}
	}
	info := RequestInfo{RequestID: state.id, Listener: state.listener, Site: state.site, Route: state.route}
	if state.clientIP.IsValid() {
		info.ClientIP = state.clientIP.String()
	}
	return info
}

type requestStateKey struct{}

func requestStateFrom(ctx context.Context) *requestState {
	state, _ := ctx.Value(requestStateKey{}).(*requestState)
	return state
}

func withRequestState(r *http.Request, state *requestState) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestStateKey{}, state))
}

func withSite(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := requestStateFrom(r.Context()); state != nil {
			state.site = name
		}
		next.ServeHTTP(w, r)
	})
}

func withRoute(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := requestStateFrom(r.Context()); state != nil {
			state.route = name
		}
		next.ServeHTTP(w, r)
	})
}

func reject(w http.ResponseWriter, r *http.Request, by string, status int, message string) {
	if state := requestStateFrom(r.Context()); state != nil {
		state.rejectedBy = by
	}
	http.Error(w, message, status)
}
