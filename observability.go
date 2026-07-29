package yabber

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestRecord is emitted after a request completes.
type RequestRecord struct {
	Time       time.Time     `json:"time"`
	Duration   time.Duration `json:"duration"`
	RequestID  string        `json:"request_id"`
	Listener   string        `json:"listener"`
	Host       string        `json:"host,omitempty"`
	Route      string        `json:"route,omitempty"`
	ClientIP   string        `json:"client_ip"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	Status     int           `json:"status"`
	Bytes      int64         `json:"bytes"`
	RejectedBy string        `json:"rejected_by,omitempty"`
	Panicked   bool          `json:"panicked,omitempty"`
}

// Observer receives completed request records.
type Observer interface {
	ObserveRequest(RequestRecord)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(RequestRecord)

func (f ObserverFunc) ObserveRequest(record RequestRecord) { f(record) }

// AccessLog writes one JSON request record per line.
type AccessLog struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func NewAccessLog(writer io.Writer) *AccessLog {
	return &AccessLog{encoder: json.NewEncoder(writer)}
}

func (l *AccessLog) ObserveRequest(record RequestRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.encoder.Encode(record)
}

// RouteMetrics is an aggregate for one listener/host/route tuple.
type RouteMetrics struct {
	Listener      string
	Host          string
	Route         string
	Requests      uint64
	Errors        uint64
	Rejected      uint64
	ResponseBytes uint64
	TotalDuration time.Duration
	StatusClasses [6]uint64
}

// MetricsSnapshot is a point-in-time copy of server request metrics.
type MetricsSnapshot struct {
	ActiveRequests uint64
	Requests       uint64
	Errors         uint64
	Rejected       uint64
	ResponseBytes  uint64
	TotalDuration  time.Duration
	StatusClasses  [6]uint64
	Routes         []RouteMetrics
}

type metricKey struct {
	listener string
	host     string
	route    string
}

type Metrics struct {
	active        atomic.Uint64
	requests      atomic.Uint64
	errors        atomic.Uint64
	rejected      atomic.Uint64
	responseBytes atomic.Uint64
	durationNS    atomic.Uint64
	statusClasses [6]atomic.Uint64
	mu            sync.Mutex
	routes        map[metricKey]*RouteMetrics
}

func newMetrics() *Metrics {
	return &Metrics{routes: make(map[metricKey]*RouteMetrics)}
}

func (m *Metrics) begin() { m.active.Add(1) }
func (m *Metrics) end()   { m.active.Add(^uint64(0)) }

func (m *Metrics) ObserveRequest(record RequestRecord) {
	m.requests.Add(1)
	m.responseBytes.Add(uint64(max(record.Bytes, 0)))
	m.durationNS.Add(uint64(max(record.Duration.Nanoseconds(), 0)))
	if record.Status >= http.StatusInternalServerError || record.Panicked {
		m.errors.Add(1)
	}
	if record.RejectedBy != "" {
		m.rejected.Add(1)
	}
	statusClass := record.Status / 100
	if statusClass >= 1 && statusClass <= 5 {
		m.statusClasses[statusClass].Add(1)
	}

	key := metricKey{listener: record.Listener, host: record.Host, route: record.Route}
	m.mu.Lock()
	item := m.routes[key]
	if item == nil {
		item = &RouteMetrics{Listener: key.listener, Host: key.host, Route: key.route}
		m.routes[key] = item
	}
	item.Requests++
	item.ResponseBytes += uint64(max(record.Bytes, 0))
	item.TotalDuration += record.Duration
	if record.Status >= http.StatusInternalServerError || record.Panicked {
		item.Errors++
	}
	if record.RejectedBy != "" {
		item.Rejected++
	}
	if statusClass >= 1 && statusClass <= 5 {
		item.StatusClasses[statusClass]++
	}
	m.mu.Unlock()
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	result := MetricsSnapshot{
		ActiveRequests: m.active.Load(),
		Requests:       m.requests.Load(),
		Errors:         m.errors.Load(),
		Rejected:       m.rejected.Load(),
		ResponseBytes:  m.responseBytes.Load(),
		TotalDuration:  time.Duration(m.durationNS.Load()),
	}
	for statusClass := 1; statusClass <= 5; statusClass++ {
		result.StatusClasses[statusClass] = m.statusClasses[statusClass].Load()
	}
	m.mu.Lock()
	result.Routes = make([]RouteMetrics, 0, len(m.routes))
	for _, item := range m.routes {
		result.Routes = append(result.Routes, *item)
	}
	m.mu.Unlock()
	sort.Slice(result.Routes, func(i, j int) bool {
		left, right := result.Routes[i], result.Routes[j]
		if left.Listener != right.Listener {
			return left.Listener < right.Listener
		}
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		return left.Route < right.Route
	})
	return result
}

// MetricsHandler returns a Prometheus-compatible metrics handler. Applications
// should mount it on a private administration server.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snapshot := s.Metrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# TYPE yabber_http_active_requests gauge\nyabber_http_active_requests %d\n", snapshot.ActiveRequests)
		for _, route := range snapshot.Routes {
			labels := fmt.Sprintf(
				`listener="%s",host="%s",route="%s"`,
				metricLabel(route.Listener), metricLabel(route.Host), metricLabel(route.Route),
			)
			_, _ = fmt.Fprintf(w, "yabber_http_requests_total{%s} %d\n", labels, route.Requests)
			_, _ = fmt.Fprintf(w, "yabber_http_errors_total{%s} %d\n", labels, route.Errors)
			_, _ = fmt.Fprintf(w, "yabber_http_rejected_total{%s} %d\n", labels, route.Rejected)
			_, _ = fmt.Fprintf(w, "yabber_http_response_bytes_total{%s} %d\n", labels, route.ResponseBytes)
			_, _ = fmt.Fprintf(
				w, "yabber_http_request_duration_seconds_total{%s} %g\n",
				labels, route.TotalDuration.Seconds(),
			)
			for statusClass := 1; statusClass <= 5; statusClass++ {
				_, _ = fmt.Fprintf(
					w,
					"yabber_http_responses_total{%s,status_class=\"%dxx\"} %d\n",
					labels, statusClass, route.StatusClasses[statusClass],
				)
			}
		}
	})
}

func metricLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

type responseTracker struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseTracker) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseTracker) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseTracker) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *responseTracker) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseTracker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *responseTracker) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func requestID(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" && len(value) <= 128 {
		return value
	}
	var data [16]byte
	if _, err := rand.Read(data[:]); err == nil {
		return hex.EncodeToString(data[:])
	}
	return time.Now().UTC().Format("20060102150405.000000000")
}
