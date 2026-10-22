package yabber

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// maxEvents is how many recent events Server.Events keeps.
const maxEvents = 256

// Event is a notable occurrence: a certificate issued or failing, an ACME
// account replaced, a configuration applied, a listener stopping. Events are
// the server's log records at Info and above, kept in memory so that an API
// or dashboard can show them without reading log files.
type Event struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// eventLog is a ring buffer of the most recent events.
type eventLog struct {
	mu     sync.Mutex
	events []Event
	next   int
}

func (l *eventLog) add(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) < maxEvents {
		l.events = append(l.events, event)
		return
	}
	l.events[l.next] = event
	l.next = (l.next + 1) % maxEvents
}

// list returns events oldest first.
func (l *eventLog) list() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Concat(l.events[l.next:], l.events[:l.next])
}

// eventHandler records Info and above into an eventLog and passes records
// on to the configured handler.
type eventHandler struct {
	next  slog.Handler
	log   *eventLog
	attrs []slog.Attr
}

func (h *eventHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo || h.next.Enabled(ctx, level)
}

func (h *eventHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelInfo {
		event := Event{Time: record.Time, Level: record.Level.String(), Message: record.Message}
		add := func(attr slog.Attr) bool {
			if event.Attrs == nil {
				event.Attrs = make(map[string]string)
			}
			event.Attrs[attr.Key] = attr.Value.Resolve().String()
			return true
		}
		for _, attr := range h.attrs {
			add(attr)
		}
		record.Attrs(add)
		h.log.add(event)
	}
	if h.next.Enabled(ctx, record.Level) {
		return h.next.Handle(ctx, record)
	}
	return nil
}

func (h *eventHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventHandler{next: h.next.WithAttrs(attrs), log: h.log, attrs: slices.Concat(h.attrs, attrs)}
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	return &eventHandler{next: h.next.WithGroup(name), log: h.log, attrs: h.attrs}
}
