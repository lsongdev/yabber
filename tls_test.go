package yabber

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tlsConfig(sites ...Site) Config {
	return Config{
		Listeners: []Listener{
			{Name: "http", Address: "127.0.0.1:0"},
			{Name: "https", Address: "127.0.0.1:0", TLS: true},
		},
		Sites: sites,
	}
}

func dialTLS(t *testing.T, server *Server, serverName string) tls.ConnectionState {
	t.Helper()
	conn, err := tls.Dial("tcp", address(t, server, "https"), &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState()
}

func TestHTTPSNegotiatesHTTP2AndSelectsCertificateBySNI(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	config := tlsConfig(
		Site{Hosts: []string{"a.example.com"}, Handler: respond("a")},
		Site{Hosts: []string{"*.example.net"}, Handler: respond("net")},
	)
	config.TLS.Certificates = []Certificate{
		writeCertificate(t, expiry, "a.example.com"),
		writeCertificate(t, expiry, "*.example.net"),
	}
	server := startServer(t, config)

	state := dialTLS(t, server, "a.example.com")
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN = %q, want h2", state.NegotiatedProtocol)
	}
	if name := state.PeerCertificates[0].DNSNames[0]; name != "a.example.com" {
		t.Fatalf("certificate = %q", name)
	}
	if name := dialTLS(t, server, "x.example.net").PeerCertificates[0].DNSNames[0]; name != "*.example.net" {
		t.Fatalf("wildcard certificate = %q", name)
	}
}

func TestNewestCertificateWins(t *testing.T) {
	config := tlsConfig(Site{Hosts: []string{"a.com"}, Handler: respond("a")})
	newer := writeCertificate(t, time.Now().Add(90*24*time.Hour), "a.com")
	config.TLS.Certificates = []Certificate{newer, writeCertificate(t, time.Now().Add(time.Hour), "a.com")}
	server := startServer(t, config)
	if got := dialTLS(t, server, "a.com").PeerCertificates[0].NotAfter; got.Before(time.Now().Add(89 * 24 * time.Hour)) {
		t.Fatalf("served certificate expiring %v, want the newest", got)
	}
}

func TestExpiredCertificateWarnsInsteadOfFailing(t *testing.T) {
	var logs bytes.Buffer
	config := tlsConfig(Site{Hosts: []string{"a.com"}, Handler: respond("a")})
	config.TLS.Certificates = []Certificate{writeCertificate(t, time.Now().Add(-time.Hour), "a.com")}
	if err := Validate(config, WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))); err != nil {
		t.Fatalf("expired certificate blocked the configuration: %v", err)
	}
	if !strings.Contains(logs.String(), "outside its validity period") {
		t.Fatalf("logs = %q", logs.String())
	}
}

func TestTLSSiteRequiresCertificate(t *testing.T) {
	config := tlsConfig(Site{Hosts: []string{"a.com", "b.com"}, Handler: respond("a")})
	config.TLS.Certificates = []Certificate{writeCertificate(t, time.Now().Add(time.Hour), "a.com")}
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), `no certificate covers "b.com"`) {
		t.Fatalf("error = %v", err)
	}

	config.Sites[0].Listeners = []string{"http"}
	if err := Validate(config); err != nil {
		t.Fatalf("HTTP-only site: %v", err)
	}
}

func TestDefaultListeners(t *testing.T) {
	config := Config{Sites: []Site{{Hosts: []string{"a.com"}, Handler: respond("a")}}}
	server := newServer(t, config)
	if names := listenerNames(server); names != "http" {
		t.Fatalf("listeners without certificates = %s", names)
	}
	config.TLS.Certificates = []Certificate{writeCertificate(t, time.Now().Add(time.Hour), "a.com")}
	server = newServer(t, config)
	if names := listenerNames(server); names != "http,https" {
		t.Fatalf("listeners with certificates = %s", names)
	}
}

func listenerNames(server *Server) string {
	var names []string
	for _, listener := range server.Status().Listeners {
		names = append(names, listener.Name)
	}
	return strings.Join(names, ",")
}

func TestHTTPRedirectsToHTTPS(t *testing.T) {
	config := tlsConfig(
		Site{Hosts: []string{"a.com"}, Handler: respond("secure")},
		Site{Hosts: []string{"b.com"}, AllowHTTP: true, Handler: respond("plain")},
	)
	config.Listeners[1].Address = "127.0.0.1:8443"
	config.TLS.Certificates = []Certificate{writeCertificate(t, time.Now().Add(time.Hour), "a.com", "b.com")}
	store := testHTTP01Store{"a.com/token": "key-authorization"}
	server := newServer(t, config, WithHTTP01Store(store))

	response := get(t, server, "http://a.com/path?q=1")
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "https://a.com:8443/path?q=1" {
		t.Fatalf("redirect = %d %q", response.Code, response.Header().Get("Location"))
	}
	assertResponse(t, get(t, server, "http://b.com/"), 200, "plain")
	assertResponse(t, get(t, server, "http://a.com/.well-known/acme-challenge/token"), 200, "key-authorization")
}

type testHTTP01Store map[string]string

func (s testHTTP01Store) GetHTTP01Token(host, token string) (string, bool) {
	value, ok := s[host+"/"+token]
	return value, ok
}

func TestCertificateSource(t *testing.T) {
	file := writeCertificate(t, time.Now().Add(time.Hour), "db.example.com")
	source := CertificateSourceFunc(func() ([]tls.Certificate, error) {
		certificate, err := tls.LoadX509KeyPair(file.Cert, file.Key)
		return []tls.Certificate{certificate}, err
	})
	config := Config{Sites: []Site{{Hosts: []string{"db.example.com"}, Handler: respond("db")}}}
	server := newServer(t, config, WithCertificateSource(source))
	request := httptest.NewRequest("GET", "https://db.example.com/", nil)
	assertResponse(t, serve(t, server, "https", request), 200, "db")
}
