package yabber

import (
	"context"
	"net/http"
)

// Middleware wraps an HTTP handler.
type Middleware func(http.Handler) http.Handler

// Chain wraps handler with middleware in declaration order.
func Chain(handler http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}

func chain(handler http.Handler, middleware ...Middleware) http.Handler {
	return Chain(handler, middleware...)
}

type requestContextKey struct{}

type requestState struct {
	RequestID  string
	Listener   string
	Host       string
	Route      string
	ClientIP   string
	RejectedBy string
	Applied    map[string]struct{}
}

// RequestInfo contains Yabber routing metadata for the current request.
type RequestInfo struct {
	RequestID  string `json:"request_id"`
	Listener   string `json:"listener"`
	Host       string `json:"host,omitempty"`
	Route      string `json:"route,omitempty"`
	ClientIP   string `json:"client_ip"`
	RejectedBy string `json:"rejected_by,omitempty"`
}

// Info returns routing metadata for a request handled by Yabber.
func Info(r *http.Request) RequestInfo {
	state := requestStateFromContext(r.Context())
	if state == nil {
		return RequestInfo{}
	}
	return RequestInfo{
		RequestID: state.RequestID, Listener: state.Listener,
		Host: state.Host, Route: state.Route, ClientIP: state.ClientIP,
		RejectedBy: state.RejectedBy,
	}
}

// ClientIP returns Yabber's trusted client address for the request.
func ClientIP(r *http.Request) string {
	return Info(r).ClientIP
}

func requestStateFromContext(ctx context.Context) *requestState {
	state, _ := ctx.Value(requestContextKey{}).(*requestState)
	return state
}

func withRequestState(r *http.Request, state *requestState) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestContextKey{}, state))
}

func withHost(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := requestStateFromContext(r.Context()); state != nil {
			state.Host = name
		}
		next.ServeHTTP(w, r)
	})
}

func withRoute(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := requestStateFromContext(r.Context()); state != nil {
			state.Route = name
		}
		next.ServeHTTP(w, r)
	})
}

func reject(w http.ResponseWriter, r *http.Request, policy string, status int, message string) {
	if state := requestStateFromContext(r.Context()); state != nil {
		state.RejectedBy = policy
	}
	http.Error(w, message, status)
}
