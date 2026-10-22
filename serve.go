package yabber

import (
	"net/http"
	"runtime/debug"
	"time"
)

// listenerHandler is the entry point for every request on a listener. It
// resolves the active snapshot per request, so configuration changes apply
// to the next request, even on existing connections.
type listenerHandler struct {
	server *Server
	name   string
}

func (h *listenerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s := h.server
	listener := s.current.Load().listeners[h.name]
	if listener == nil {
		// The listener was removed and this connection is draining.
		w.Header().Set("Connection", "close")
		http.Error(w, "listener removed", http.StatusServiceUnavailable)
		return
	}

	state := &requestState{listener: h.name}
	state.clientIP, state.trustedPeer = listener.clientIP.resolve(r)
	state.id = requestID(r, state.trustedPeer)
	r.Header.Set("X-Request-ID", state.id)
	w.Header().Set("X-Request-ID", state.id)
	r = withRequestState(r, state)
	tracker := &responseTracker{ResponseWriter: w}

	s.metrics.active.Add(1)
	defer func() {
		recovered := recover()
		incomplete := recovered == http.ErrAbortHandler || (recovered != nil && tracker.status != 0)
		if recovered != nil && recovered != http.ErrAbortHandler {
			s.opts.logger.Error("panic serving request", "request_id", state.id,
				"panic", recovered, "stack", string(debug.Stack()))
			if tracker.status == 0 {
				http.Error(tracker, "internal server error", http.StatusInternalServerError)
			}
		}
		s.metrics.active.Add(-1)
		s.record(r, state, tracker, start, recovered != nil)
		// Abort the connection when the response is incomplete, so the
		// client does not mistake a truncated body for a complete one.
		if incomplete {
			panic(http.ErrAbortHandler)
		}
	}()

	if s.serveACMEChallenge(tracker, r, state) {
		return
	}
	listener.handler.ServeHTTP(tracker, r)
}

func (s *Server) record(r *http.Request, state *requestState, tracker *responseTracker, start time.Time, panicked bool) {
	status := tracker.status
	if status == 0 {
		status = http.StatusOK
	}
	record := RequestRecord{
		Time:       start.UTC(),
		Duration:   time.Since(start),
		RequestID:  state.id,
		Listener:   state.listener,
		Site:       state.site,
		Route:      state.route,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Status:     status,
		Bytes:      tracker.bytes,
		RejectedBy: state.rejectedBy,
		Panicked:   panicked,
	}
	if state.clientIP.IsValid() {
		record.ClientIP = state.clientIP.String()
	}
	s.metrics.observe(record)
	for _, observer := range s.opts.observers {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					s.opts.logger.Error("observer panicked", "panic", recovered)
				}
			}()
			observer.ObserveRequest(record)
		}()
	}
}
