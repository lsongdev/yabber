package yabber

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func httpGet(t *testing.T, addr, host string) (int, string) {
	t.Helper()
	request, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	request.Host = host
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, readBody(t, response)
}

func TestApplySwapsAtomicallyAndKeepsPreviousOnError(t *testing.T) {
	server := startServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("before")}))
	addr := address(t, server, "http")

	if err := server.Apply(siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("after")})); err != nil {
		t.Fatal(err)
	}
	if _, body := httpGet(t, addr, "a.com"); body != "after" {
		t.Fatalf("body = %q", body)
	}
	if address(t, server, "http") != addr {
		t.Fatal("unchanged listener was rebound")
	}

	if err := server.Apply(siteConfig(Site{Hosts: []string{"a.com"}})); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if _, body := httpGet(t, addr, "a.com"); body != "after" {
		t.Fatalf("body after failed Apply = %q", body)
	}
}

func TestApplyRebindsChangedListeners(t *testing.T) {
	config := siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("ok")})
	server := startServer(t, config)
	oldAddr := address(t, server, "http")

	free, _ := net.Listen("tcp", "127.0.0.1:0")
	newAddr := free.Addr().String()
	free.Close()
	config.Listeners[0].Address = newAddr
	config.Listeners = append(config.Listeners, Listener{Name: "extra", Address: "127.0.0.1:0"})
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	if got := address(t, server, "http"); got != newAddr {
		t.Fatalf("http listener on %s, want %s", got, newAddr)
	}
	if status, body := httpGet(t, address(t, server, "extra"), "a.com"); status != 200 || body != "ok" {
		t.Fatalf("extra listener = %d %q", status, body)
	}
	if conn, err := net.DialTimeout("tcp", oldAddr, time.Second); err == nil {
		conn.Close()
		t.Fatal("old address still accepts connections")
	}
	if !server.Healthy() {
		t.Fatalf("status = %#v", server.Status())
	}
}

func TestApplyRollsBackWhenBindFails(t *testing.T) {
	occupied, _ := net.Listen("tcp", "127.0.0.1:0")
	defer occupied.Close()
	config := siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("ok")})
	server := startServer(t, config)

	config.Listeners = append(config.Listeners, Listener{Name: "busy", Address: occupied.Addr().String()})
	config.Sites[0].Handler = respond("new")
	err := server.Apply(config)
	var listenerError *ListenerError
	if !errors.As(err, &listenerError) || listenerError.Listener != "busy" {
		t.Fatalf("error = %v", err)
	}
	if _, body := httpGet(t, address(t, server, "http"), "a.com"); body != "ok" {
		t.Fatalf("body = %q, want previous configuration", body)
	}
}

func TestUpdateSerializesReadModifyWrite(t *testing.T) {
	server := newServer(t, siteConfig(Site{Hosts: []string{"seed.com"}, Handler: respond("seed")}))
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			err := server.Update(func(config *Config) error {
				config.Sites = append(config.Sites, Site{Hosts: []string{fmt.Sprintf("s%d.com", i)}, Handler: respond("x")})
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := len(server.Config().Sites); n != 21 {
		t.Fatalf("sites = %d, want 21", n)
	}
	if err := server.Update(func(*Config) error { return errors.New("abort") }); err == nil {
		t.Fatal("modify error was ignored")
	}
}

func TestConfigReturnsACopy(t *testing.T) {
	server := newServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("a")}))
	config := server.Config()
	config.Sites[0].Hosts[0] = "changed.com"
	if server.Config().Sites[0].Hosts[0] != "a.com" {
		t.Fatal("Config exposes internal state")
	}
}

func TestShutdownForcesCloseAfterTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer upstream.Close()
	defer close(release)
	server := startServer(t, siteConfig(proxySite(Proxy{Upstream: upstream.URL})))
	addr := address(t, server, "http")
	go func() {
		request, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
		request.Host = "example.com"
		if response, err := http.DefaultClient.Do(request); err == nil {
			response.Body.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown reported success with a request still in flight")
	}
	if server.Status().Running {
		t.Fatal("server still running after Shutdown")
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still accepting")
	}
	if err := server.Start(); err != nil {
		t.Fatalf("restart after shutdown: %v", err)
	}
}

func TestPanicsAreRecoveredAndAbortsPropagate(t *testing.T) {
	var records []RequestRecord
	panicking := WithMiddleware(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/abort" {
				w.WriteHeader(200)
				w.Write([]byte("partial"))
			}
			panic("boom")
		})
	})
	server := newServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("ok")}),
		panicking, WithObserver(ObserverFunc(func(record RequestRecord) { records = append(records, record) })))

	assertResponse(t, get(t, server, "http://a.com/"), http.StatusInternalServerError, "")
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
			}
		}()
		get(t, server, "http://a.com/abort")
	}()
	if len(records) != 2 || !records[0].Panicked || !records[1].Panicked {
		t.Fatalf("records = %#v", records)
	}
}

func TestObservabilityRecords(t *testing.T) {
	var log strings.Builder
	server := newServer(t, siteConfig(Site{Name: "main", Hosts: []string{"a.com"}, Routes: []Route{
		{Name: "home", Path: "/", Handler: respond("ok")},
	}}), WithAccessLog(&log))

	request := httptest.NewRequest("GET", "http://a.com/", nil)
	request.Header.Set("X-Request-ID", "client-chosen")
	response := serve(t, server, "http", request)
	id := response.Header().Get("X-Request-ID")
	if id == "" || id == "client-chosen" {
		t.Fatalf("request ID = %q; untrusted clients must not choose it", id)
	}
	if !strings.Contains(log.String(), `"site":"main","route":"home"`) || !strings.Contains(log.String(), id) {
		t.Fatalf("access log = %s", log.String())
	}

	metrics := server.Metrics()
	if total := metrics.Total(); total.Requests != 1 || total.StatusClasses[2] != 1 {
		t.Fatalf("metrics = %#v", metrics)
	}
	var text strings.Builder
	if err := metrics.WritePrometheus(&text); err != nil {
		t.Fatal(err)
	}
	if strings.Count(text.String(), "# TYPE yabber_http_requests_total counter") != 1 ||
		!strings.Contains(text.String(), `yabber_http_requests_total{listener="http",site="main",route="home"} 1`) {
		t.Fatalf("prometheus = %s", text.String())
	}
}

func TestTrustedProxyRequestID(t *testing.T) {
	config := siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("ok")})
	config.Listeners[0].TrustedProxies = []string{"10.0.0.1"}
	server := newServer(t, config)
	request := httptest.NewRequest("GET", "http://a.com/", nil)
	request.RemoteAddr = "10.0.0.1:1000"
	request.Header.Set("X-Request-ID", "edge-123")
	if id := serve(t, server, "http", request).Header().Get("X-Request-ID"); id != "edge-123" {
		t.Fatalf("request ID = %q", id)
	}
}

func TestEventsKeepRecentInfoAndAbove(t *testing.T) {
	server := newServer(t, siteConfig(Site{Hosts: []string{"a.com"}, Handler: respond("a")}))
	logger := server.opts.logger.With("component", "test")
	logger.Debug("debug is not an event")
	for i := range maxEvents + 10 {
		logger.Info("event", "n", i)
	}
	logger.Warn("last", "detail", "x")
	events := server.Events()
	if len(events) != maxEvents {
		t.Fatalf("events = %d, want %d", len(events), maxEvents)
	}
	first, last := events[0], events[len(events)-1]
	if first.Attrs["n"] != "11" || last.Message != "last" || last.Level != "WARN" || last.Attrs["component"] != "test" {
		t.Fatalf("first = %#v, last = %#v", first, last)
	}
	if err := server.Apply(siteConfig(Site{Hosts: []string{"b.com"}, Handler: respond("b")})); err != nil {
		t.Fatal(err)
	}
	if got := server.Events(); got[len(got)-1].Message != "configuration applied" {
		t.Fatalf("last event = %#v", got[len(got)-1])
	}
}
