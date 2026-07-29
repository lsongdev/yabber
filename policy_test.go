package yabber

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitByClientIP(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Policies = []Policy{{
		Name: "api",
		RateLimit: &RateLimitPolicy{
			RequestsPerSecond: 0.001,
			Burst:             1,
			Key:               "client_ip",
		},
	}}
	config.Hosts[0].Routes[0].Policies = []string{"api"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")

	assertPolicyStatus(t, handler, "192.0.2.1:1000", "", http.StatusOK)
	assertPolicyStatus(t, handler, "192.0.2.1:1001", "", http.StatusTooManyRequests)
	assertPolicyStatus(t, handler, "192.0.2.2:1000", "", http.StatusOK)

	snapshot := server.Metrics()
	if snapshot.Requests != 3 || snapshot.Rejected != 1 {
		t.Fatalf("metrics = requests:%d rejected:%d", snapshot.Requests, snapshot.Rejected)
	}
}

func TestUnchangedRateLimitSurvivesApply(t *testing.T) {
	config := basicHTTPConfig("before")
	config.Policies = []Policy{{
		Name: "api",
		RateLimit: &RateLimitPolicy{
			RequestsPerSecond: 0.001,
			Burst:             1,
		},
	}}
	config.Hosts[0].Routes[0].Policies = []string{"api"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	assertPolicyStatus(t, handler, "192.0.2.1:1000", "", http.StatusOK)

	updated := config
	updated.Hosts[0].Routes[0].Handle.StaticResponse.Body = "after"
	if err := server.Apply(updated); err != nil {
		t.Fatal(err)
	}
	assertPolicyStatus(t, handler, "192.0.2.1:1001", "", http.StatusTooManyRequests)
}

func TestInheritedPolicyIsAppliedOnlyOnce(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Policies = []Policy{{
		Name:        "shared",
		Concurrency: &ConcurrencyPolicy{Max: 1},
	}}
	config.Listeners[0].Policies = []string{"shared"}
	config.Hosts[0].Policies = []string{"shared"}
	config.Hosts[0].Routes[0].Policies = []string{"shared"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	assertPolicyStatus(t, handler, "192.0.2.1:1000", "", http.StatusOK)
}

func TestTrustedProxyClientIP(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Listeners[0].TrustedProxies = []string{"10.0.0.0/8"}
	config.Policies = []Policy{{
		Name: "api",
		RateLimit: &RateLimitPolicy{
			RequestsPerSecond: 0.001,
			Burst:             1,
			Key:               "client_ip",
		},
	}}
	config.Hosts[0].Routes[0].Policies = []string{"api"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")

	assertPolicyStatus(t, handler, "10.0.0.2:1000", "203.0.113.10", http.StatusOK)
	assertPolicyStatus(t, handler, "10.0.0.2:1001", "203.0.113.10", http.StatusTooManyRequests)
	assertPolicyStatus(t, handler, "10.0.0.2:1002", "203.0.113.11", http.StatusOK)
}

func TestUntrustedProxyCannotSpoofClientIP(t *testing.T) {
	resolver, err := newClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.50")
	if got := resolver.resolve(request); got != "192.0.2.10" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestRateLimitBoundsIdentityMap(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Policies = []Policy{{
		Name: "bounded",
		RateLimit: &RateLimitPolicy{
			RequestsPerSecond: 1,
			Burst:             1,
			MaxKeys:           1,
		},
	}}
	config.Hosts[0].Routes[0].Policies = []string{"bounded"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	assertPolicyStatus(t, handler, "192.0.2.1:1", "", http.StatusOK)
	assertPolicyStatus(t, handler, "192.0.2.2:1", "", http.StatusTooManyRequests)
}

func TestConcurrencyLimit(t *testing.T) {
	middleware, err := newConcurrencyMiddleware("expensive", ConcurrencyPolicy{Max: 1})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	firstDone := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		firstDone <- response.Code
	}()
	<-started

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
	close(release)
	if status := <-firstDone; status != http.StatusNoContent {
		t.Fatalf("first status = %d", status)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	var called atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	config := reverseProxyConfig(upstream.URL)
	config.Policies = []Policy{{
		Name:    "body",
		Request: &RequestPolicy{MaxBodyBytes: 5},
	}}
	config.Hosts[0].Routes[0].Policies = []string{"body"}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	request := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("123456"))
	request.Host = "example.com"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", response.Code)
	}
	if called.Load() {
		t.Fatal("oversized request reached upstream")
	}
}

func TestReverseProxyRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()

	config := reverseProxyConfig(upstream.URL)
	config.Hosts[0].Routes[0].Handle.ReverseProxy.RequestTimeout = 20 * time.Millisecond
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.Host = "example.com"
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestAccessLogObserverAndMetrics(t *testing.T) {
	var log bytes.Buffer
	records := make(chan RequestRecord, 1)
	server, err := New(
		basicHTTPConfig("ok"),
		WithAccessLog(&log),
		WithObserver(ObserverFunc(func(record RequestRecord) { records <- record })),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.Host = "example.com"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	record := <-records
	if record.Listener != "http" || record.Host != "site" || record.Route != "home" {
		t.Fatalf("record routing = %#v", record)
	}
	if record.RequestID == "" || response.Header().Get("X-Request-ID") != record.RequestID {
		t.Fatalf("request ID = %q, header = %q", record.RequestID, response.Header().Get("X-Request-ID"))
	}
	var logged RequestRecord
	if err := json.NewDecoder(&log).Decode(&logged); err != nil {
		t.Fatal(err)
	}
	if logged.RequestID != record.RequestID {
		t.Fatalf("logged request ID = %q", logged.RequestID)
	}
	metrics := server.Metrics()
	if metrics.Requests != 1 || len(metrics.Routes) != 1 || metrics.Routes[0].Route != "home" {
		t.Fatalf("metrics = %#v", metrics)
	}
	metricsResponse := httptest.NewRecorder()
	server.MetricsHandler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsResponse.Body.String(), `route="home"`) {
		t.Fatalf("metrics response = %q", metricsResponse.Body.String())
	}
}

func TestMiddlewarePanicIsObservedAndRecovered(t *testing.T) {
	records := make(chan RequestRecord, 1)
	server, err := New(
		basicHTTPConfig("ok"),
		WithMiddleware(func(http.Handler) http.Handler {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				panic("broken middleware")
			})
		}),
		WithObserver(ObserverFunc(func(record RequestRecord) { records <- record })),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.Host = "example.com"
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	record := <-records
	if !record.Panicked || server.Metrics().Errors != 1 {
		t.Fatalf("record = %#v, metrics = %#v", record, server.Metrics())
	}
}

func TestUnknownPolicyIsRejected(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Hosts[0].Routes[0].Policies = []string{"missing"}
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "unknown policy") {
		t.Fatalf("error = %v", err)
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	config, err := Load("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Policies) != 2 || config.Server.MaxHeaderBytes != 65536 {
		t.Fatalf("example config = %#v", config)
	}
}

func TestStaticResponseRejectsInvalidFinalStatus(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Hosts[0].Routes[0].Handle.StaticResponse.Status = 700
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "invalid response status") {
		t.Fatalf("error = %v", err)
	}
}

func TestListenerStatus(t *testing.T) {
	config := basicHTTPConfig("ok")
	config.Listeners[0].Address = "127.0.0.1:0"
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	status := server.ListenerStatuses()["http"]
	if !status.Running || status.Address == "" || !server.Healthy() {
		t.Fatalf("listener status = %#v, healthy = %v", status, server.Healthy())
	}
}

func assertPolicyStatus(t *testing.T, handler http.Handler, remoteAddr, forwardedFor string, expected int) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.Host = "example.com"
	request.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != expected {
		t.Fatalf("remote %s forwarded %s: status = %d, want %d", remoteAddr, forwardedFor, response.Code, expected)
	}
}

func reverseProxyConfig(upstream string) Config {
	config := basicHTTPConfig("")
	config.Hosts[0].Routes[0].Handle = Handler{ReverseProxy: &ReverseProxy{URL: upstream}}
	return config
}
