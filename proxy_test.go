package yabber

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// echoUpstream replies with the request line and selected headers.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s host=%s xff=%s xfh=%s xfp=%s real=%s",
			r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Real-IP"))
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

func proxySite(proxy Proxy) Site {
	return Site{Hosts: []string{"example.com"}, Routes: []Route{{Path: "/", Handler: Handler{Proxy: &proxy}}}}
}

func TestProxyPathRewriting(t *testing.T) {
	upstream := echoUpstream(t)
	server := newServer(t, siteConfig(proxySite(Proxy{Upstream: upstream.URL + "/base", StripPrefix: "/api"})))
	for path, want := range map[string]string{
		"/api/users?x=1": "/base/users?x=1",
		"/api":           "/base/",
		"/apifoo":        "/base/apifoo", // prefix must match whole segments
		"/api/a%2Fb":     "/base/a%2Fb",  // escaped slashes survive
	} {
		body := get(t, server, "http://example.com"+path).Body.String()
		if got, _, _ := strings.Cut(body, " "); got != want {
			t.Errorf("%s forwarded as %q, want %q", path, got, want)
		}
	}
}

func TestProxyPreservesHostByDefault(t *testing.T) {
	upstream := echoUpstream(t)
	server := newServer(t, siteConfig(proxySite(Proxy{Upstream: upstream.URL})))
	if body := get(t, server, "http://example.com/").Body.String(); !strings.Contains(body, "host=example.com ") {
		t.Fatalf("body = %q", body)
	}

	server = newServer(t, siteConfig(proxySite(Proxy{Upstream: upstream.URL, HostHeader: "internal.local"})))
	if body := get(t, server, "http://example.com/").Body.String(); !strings.Contains(body, "host=internal.local ") {
		t.Fatalf("body = %q", body)
	}
}

func TestProxyForwardingHeaders(t *testing.T) {
	upstream := echoUpstream(t)
	config := siteConfig(proxySite(Proxy{Upstream: upstream.URL}))
	config.Listeners[0].TrustedProxies = []string{"10.0.0.0/8"}
	server := newServer(t, config)

	spoofed := httptest.NewRequest("GET", "http://example.com/", nil)
	spoofed.RemoteAddr = "192.0.2.1:1234"
	spoofed.Header.Set("X-Forwarded-For", "6.6.6.6")
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	spoofed.Header.Set("X-Real-IP", "6.6.6.6")
	body := serve(t, server, "http", spoofed).Body.String()
	if !strings.Contains(body, "xff=192.0.2.1 xfh=example.com xfp=http real=192.0.2.1") {
		t.Fatalf("untrusted client: %q", body)
	}

	proxied := httptest.NewRequest("GET", "http://example.com/", nil)
	proxied.RemoteAddr = "10.0.0.2:1234"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.7")
	proxied.Header.Set("X-Forwarded-Proto", "https")
	body = serve(t, server, "http", proxied).Body.String()
	if !strings.Contains(body, "xff=203.0.113.7, 10.0.0.2 xfh=example.com xfp=https real=203.0.113.7") {
		t.Fatalf("trusted proxy: %q", body)
	}
}

func TestProxyUnixSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "app.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "unix "+r.URL.Path)
	}))
	upstream.Listener = listener
	upstream.Start()
	defer upstream.Close()

	server := newServer(t, siteConfig(proxySite(Proxy{Upstream: "unix:" + socket})))
	assertResponse(t, get(t, server, "http://example.com/hello"), 200, "unix /hello")
}

func TestProxyErrors(t *testing.T) {
	server := newServer(t, siteConfig(proxySite(Proxy{Upstream: "http://127.0.0.1:1"})))
	assertResponse(t, get(t, server, "http://example.com/"), http.StatusBadGateway, "")

	if err := Validate(siteConfig(proxySite(Proxy{Upstream: "ftp://x"}))); err == nil {
		t.Fatal("invalid upstream accepted")
	}
}

func TestProxyTransportsAreShared(t *testing.T) {
	config := siteConfig(proxySite(Proxy{Upstream: "http://127.0.0.1:1"}))
	config.Listeners = append(config.Listeners, Listener{Name: "alt", Address: "127.0.0.1:0"})
	config.Sites = append(config.Sites, Site{Hosts: []string{"b.com"}, Handler: Handler{Proxy: &Proxy{Upstream: "http://127.0.0.1:2"}}})
	server := newServer(t, config)
	if n := len(server.current.Load().transports); n != 1 {
		t.Fatalf("transports = %d, want 1 shared pool", n)
	}
	before := server.current.Load().transports
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	for key, transport := range server.current.Load().transports {
		if before[key] != transport {
			t.Fatal("Apply replaced an unchanged transport")
		}
	}
}

func TestPolicyTimeoutDoesNotBufferStreams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "data: second\n\n")
	}))
	defer upstream.Close()
	config := siteConfig(proxySite(Proxy{Upstream: upstream.URL}))
	config.Policies = []Policy{{Name: "bounded", Request: &RequestPolicy{Timeout: Duration(5 * time.Second)}}}
	config.Sites[0].Policies = []string{"bounded"}
	server := startServer(t, config)

	start := time.Now()
	request, _ := http.NewRequest("GET", "http://"+address(t, server, "http")+"/", nil)
	request.Host = "example.com"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	line, _ := bufio.NewReader(response.Body).ReadString('\n')
	if elapsed := time.Since(start); line != "data: first\n" || elapsed > 200*time.Millisecond {
		t.Fatalf("first event %q after %v; the response was buffered", line, elapsed)
	}
}

func TestPolicyTimeoutReturnsGatewayTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()
	config := siteConfig(proxySite(Proxy{Upstream: upstream.URL}))
	config.Policies = []Policy{{Name: "fast", Request: &RequestPolicy{Timeout: Duration(20 * time.Millisecond)}}}
	config.Sites[0].Routes[0].Policies = []string{"fast"}
	server := newServer(t, config)
	assertResponse(t, get(t, server, "http://example.com/"), http.StatusGatewayTimeout, "")
}
