package yabber

import (
	"bufio"
	"cmp"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestRecord describes a completed request.
type RequestRecord struct {
	Time       time.Time     `json:"time"`
	Duration   time.Duration `json:"duration_ns"`
	RequestID  string        `json:"request_id"`
	Listener   string        `json:"listener"`
	Site       string        `json:"site,omitempty"`
	Route      string        `json:"route,omitempty"`
	ClientIP   string        `json:"client_ip,omitempty"`
	Method     string        `json:"method"`
	Host       string        `json:"host"`
	Path       string        `json:"path"`
	Status     int           `json:"status"`
	Bytes      int64         `json:"bytes"`
	RejectedBy string        `json:"rejected_by,omitempty"`
	Panicked   bool          `json:"panicked,omitempty"`
}

// Observer receives a record for every completed request. It runs on the
// request goroutine and should return quickly.
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

// RouteMetrics aggregates requests for one listener, site and route.
type RouteMetrics struct {
	Listener      string        `json:"listener"`
	Site          string        `json:"site"`
	Route         string        `json:"route"`
	Requests      uint64        `json:"requests"`
	Errors        uint64        `json:"errors"`
	Rejected      uint64        `json:"rejected"`
	ResponseBytes uint64        `json:"response_bytes"`
	TotalDuration time.Duration `json:"total_duration_ns"`
	// StatusClasses counts responses by status class; index 2 is 2xx.
	StatusClasses [6]uint64 `json:"status_classes"`
}

// MetricsSnapshot is a point-in-time copy of request metrics.
type MetricsSnapshot struct {
	ActiveRequests int64          `json:"active_requests"`
	Routes         []RouteMetrics `json:"routes"`
}

// Total sums the per-route metrics.
func (s MetricsSnapshot) Total() RouteMetrics {
	var total RouteMetrics
	for _, route := range s.Routes {
		total.Requests += route.Requests
		total.Errors += route.Errors
		total.Rejected += route.Rejected
		total.ResponseBytes += route.ResponseBytes
		total.TotalDuration += route.TotalDuration
		for i := range total.StatusClasses {
			total.StatusClasses[i] += route.StatusClasses[i]
		}
	}
	return total
}

type metricKey struct {
	listener, site, route string
}

type metrics struct {
	active atomic.Int64
	mu     sync.Mutex
	routes map[metricKey]*RouteMetrics
}

func newMetrics() *metrics {
	return &metrics{routes: make(map[metricKey]*RouteMetrics)}
}

func (m *metrics) observe(record RequestRecord) {
	key := metricKey{listener: record.Listener, site: record.Site, route: record.Route}
	m.mu.Lock()
	defer m.mu.Unlock()
	route := m.routes[key]
	if route == nil {
		route = &RouteMetrics{Listener: key.listener, Site: key.site, Route: key.route}
		m.routes[key] = route
	}
	route.Requests++
	route.ResponseBytes += uint64(max(record.Bytes, 0))
	route.TotalDuration += record.Duration
	if record.Status >= http.StatusInternalServerError || record.Panicked {
		route.Errors++
	}
	if record.RejectedBy != "" {
		route.Rejected++
	}
	if class := record.Status / 100; class >= 1 && class <= 5 {
		route.StatusClasses[class]++
	}
}

func (m *metrics) snapshot() MetricsSnapshot {
	m.mu.Lock()
	routes := make([]RouteMetrics, 0, len(m.routes))
	for _, route := range m.routes {
		routes = append(routes, *route)
	}
	m.mu.Unlock()
	slices.SortFunc(routes, func(a, b RouteMetrics) int {
		return cmp.Or(cmp.Compare(a.Listener, b.Listener), cmp.Compare(a.Site, b.Site), cmp.Compare(a.Route, b.Route))
	})
	return MetricsSnapshot{ActiveRequests: m.active.Load(), Routes: routes}
}

// WritePrometheus writes the snapshot in the Prometheus text format.
func (s MetricsSnapshot) WritePrometheus(w io.Writer) error {
	b := bufio.NewWriter(w)
	fmt.Fprintf(b, "# TYPE yabber_http_active_requests gauge\nyabber_http_active_requests %d\n", s.ActiveRequests)
	counters := []struct {
		name  string
		value func(RouteMetrics) string
	}{
		{"yabber_http_requests_total", func(r RouteMetrics) string { return fmt.Sprint(r.Requests) }},
		{"yabber_http_errors_total", func(r RouteMetrics) string { return fmt.Sprint(r.Errors) }},
		{"yabber_http_rejected_total", func(r RouteMetrics) string { return fmt.Sprint(r.Rejected) }},
		{"yabber_http_response_bytes_total", func(r RouteMetrics) string { return fmt.Sprint(r.ResponseBytes) }},
		{"yabber_http_request_duration_seconds_total", func(r RouteMetrics) string { return fmt.Sprint(r.TotalDuration.Seconds()) }},
	}
	for _, counter := range counters {
		fmt.Fprintf(b, "# TYPE %s counter\n", counter.name)
		for _, route := range s.Routes {
			fmt.Fprintf(b, "%s{%s} %s\n", counter.name, metricLabels(route), counter.value(route))
		}
	}
	fmt.Fprintf(b, "# TYPE yabber_http_responses_total counter\n")
	for _, route := range s.Routes {
		for class := 1; class <= 5; class++ {
			fmt.Fprintf(b, "yabber_http_responses_total{%s,status_class=\"%dxx\"} %d\n",
				metricLabels(route), class, route.StatusClasses[class])
		}
	}
	return b.Flush()
}

func metricLabels(route RouteMetrics) string {
	return fmt.Sprintf(`listener="%s",site="%s",route="%s"`,
		metricLabel(route.Listener), metricLabel(route.Site), metricLabel(route.Route))
}

var metricLabelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func metricLabel(value string) string { return metricLabelEscaper.Replace(value) }

// responseTracker records the status and size of a response.
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
	// Informational responses such as 103 Early Hints precede the real one.
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseTracker) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

// Flush and Hijack are implemented directly, not only through Unwrap, for
// handlers that type-assert http.Flusher or http.Hijacker.

func (w *responseTracker) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseTracker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// requestID reuses X-Request-ID from trusted proxies and otherwise generates
// one, so clients cannot inject arbitrary values into logs.
func requestID(r *http.Request, trusted bool) string {
	if trusted {
		if id := r.Header.Get("X-Request-ID"); validRequestID(id) {
			return id
		}
	}
	return rand.Text()
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}
