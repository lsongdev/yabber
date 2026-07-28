package yabber

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testHTTP01Store map[string]string

func (s testHTTP01Store) GetHTTP01Token(host, token string) (string, bool) {
	value, ok := s[host+"\x00"+token]
	return value, ok
}

func TestHTTP01PrecedesHostRoutes(t *testing.T) {
	store := testHTTP01Store{"example.com\x00token": "key-authorization"}
	server, err := New(Config{
		Version:   ConfigVersion,
		Listeners: []Listener{{Name: "http", Address: ":8080", Protocol: ProtocolHTTP}},
		Hosts: []VirtualHost{{
			Name: "redirect", Hostnames: []string{"example.com"}, Listeners: []string{"http"},
			HTTP: &HostHTTP{RedirectToHTTPS: true},
		}},
	}, WithHTTP01Store(store))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler("http")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "key-authorization" {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestHostAndRouteMatching(t *testing.T) {
	server, err := New(Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "http", Address: ":8080", Protocol: ProtocolHTTP},
		},
		Hosts: []VirtualHost{
			{
				Name:      "api",
				Hostnames: []string{"api.example.com"},
				Listeners: []string{"http"},
				Routes: []Route{
					staticRoute("health", "GET", "/health", http.StatusCreated, "healthy"),
				},
			},
			{
				Name:      "wildcard",
				Hostnames: []string{"*.example.net"},
				Listeners: []string{"http"},
				Routes: []Route{
					staticRoute("home", "", "/", http.StatusOK, "wildcard"),
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler("http")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		host   string
		method string
		path   string
		status int
		body   string
	}{
		{name: "exact host", host: "api.example.com", method: "GET", path: "/health", status: http.StatusCreated, body: "healthy"},
		{name: "host port ignored", host: "api.example.com:8080", method: "GET", path: "/health", status: http.StatusCreated, body: "healthy"},
		{name: "method mismatch", host: "api.example.com", method: "POST", path: "/health", status: http.StatusMethodNotAllowed},
		{name: "single label wildcard", host: "one.example.net", method: "GET", path: "/", status: http.StatusOK, body: "wildcard"},
		{name: "wildcard does not cross labels", host: "one.two.example.net", method: "GET", path: "/", status: http.StatusNotFound},
		{name: "unknown host", host: "unknown.example.org", method: "GET", path: "/", status: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://"+test.host+test.path, nil)
			request.Host = test.host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if test.body != "" && response.Body.String() != test.body {
				t.Fatalf("body = %q, want %q", response.Body.String(), test.body)
			}
		})
	}
}

func TestReverseProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s|%s", r.URL.Path, r.Header.Get("X-Forwarded-Host"))
	}))
	defer upstream.Close()

	server, err := New(Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "http", Address: ":8080", Protocol: ProtocolHTTP},
		},
		Hosts: []VirtualHost{
			{
				Name:      "proxy",
				Hostnames: []string{"proxy.example.com"},
				Listeners: []string{"http"},
				Routes: []Route{
					{
						Name:  "api",
						Match: Match{Path: "/api/"},
						Handle: Handler{ReverseProxy: &ReverseProxy{
							URL:         upstream.URL + "/base",
							StripPrefix: "/api",
						}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/api/users", nil)
	request.Host = "proxy.example.com"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Body.String() != "/base/users|proxy.example.com" {
		t.Fatalf("body = %q", response.Body.String())
	}
}

func TestWorkerHandler(t *testing.T) {
	server, err := New(Config{
		Version:   ConfigVersion,
		Listeners: []Listener{{Name: "http", Address: ":8080", Protocol: ProtocolHTTP}},
		Hosts: []VirtualHost{{
			Name: "worker", Hostnames: []string{"worker.example.com"}, Listeners: []string{"http"},
			Routes: []Route{{
				Name: "worker", Match: Match{Path: "/"}, Handle: Handler{Worker: &WorkerHandler{
					Script: `export default {
						fetch(request, env) {
							return new Response(request.method + " from worker", { status: 201 });
						}
					}`,
				}},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler("http")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://worker.example.com/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != "POST from worker" {
		t.Fatalf("response = (%d, %q)", response.Code, response.Body.String())
	}
}

func TestWorkerHandlerRequiresScript(t *testing.T) {
	config := basicHTTPConfig("unused")
	config.Hosts[0].Routes[0].Handle = Handler{Worker: &WorkerHandler{}}
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "worker script is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyIsAtomicAndRequiresRestartForListenerChanges(t *testing.T) {
	config := basicHTTPConfig("before")
	config.Listeners[0].Address = "127.0.0.1:0"
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	if address := server.Addresses()["http"]; address == "" {
		t.Fatal("running listener did not report its bound address")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	handler, _ := server.Handler("http")
	assertResponseBody(t, handler, "example.com", "before")

	updated := basicHTTPConfig("after")
	updated.Listeners[0].Address = "127.0.0.1:0"
	if err := server.Apply(updated); err != nil {
		t.Fatal(err)
	}
	assertResponseBody(t, handler, "example.com", "after")

	invalid := basicHTTPConfig("invalid")
	invalid.Listeners[0].Address = "127.0.0.1:0"
	invalid.Hosts[0].Routes[0].Handle = Handler{}
	if err := server.Apply(invalid); err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	assertResponseBody(t, handler, "example.com", "after")

	changedListener := basicHTTPConfig("after")
	changedListener.Listeners[0].Address = "127.0.0.1:8089"
	if err := server.Apply(changedListener); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Apply error = %v, want ErrRestartRequired", err)
	}

	changedTimeout := updated
	changedTimeout.Server.ReadHeaderTimeout = 30 * time.Second
	if err := server.Apply(changedTimeout); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Apply timeout error = %v, want ErrRestartRequired", err)
	}
}

func TestCertificatesAreLoadedOnlyWhenReferencedByHTTPS(t *testing.T) {
	unused := Certificate{
		Name:            "unused",
		CertificateFile: "/does/not/exist/cert.pem",
		PrivateKeyFile:  "/does/not/exist/key.pem",
	}
	httpOnly := basicHTTPConfig("ok")
	httpOnly.Certificates = []Certificate{unused}
	if _, err := New(httpOnly); err != nil {
		t.Fatalf("unused certificate was loaded: %v", err)
	}

	https := Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "https", Address: ":443", Protocol: ProtocolHTTPS, TLS: &TLSConfig{}},
		},
		Certificates: []Certificate{unused},
		Hosts: []VirtualHost{
			{
				Name:      "secure",
				Hostnames: []string{"secure.example.com"},
				Listeners: []string{"https"},
				TLS:       &HostTLS{Certificate: "unused"},
				Routes:    []Route{staticRoute("home", "", "/", 200, "secure")},
			},
		},
	}
	if _, err := New(https); err == nil || !strings.Contains(err.Error(), "load certificate") {
		t.Fatalf("New error = %v, want certificate load error", err)
	}
}

func TestHTTPSCertificateSelection(t *testing.T) {
	certFile, keyFile := writeSelfSignedCertificate(t, []string{"api.example.com", "*.example.net"})
	server, err := New(Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "https", Address: ":443", Protocol: ProtocolHTTPS, TLS: &TLSConfig{}},
		},
		Certificates: []Certificate{
			{
				Name:            "site",
				CertificateFile: certFile,
				PrivateKeyFile:  keyFile,
			},
		},
		Hosts: []VirtualHost{
			{
				Name:      "site",
				Hostnames: []string{"api.example.com", "*.example.net"},
				Listeners: []string{"https"},
				TLS:       &HostTLS{Certificate: "site"},
				Routes:    []Route{staticRoute("home", "", "/", 200, "secure")},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := server.current.Load().certificates["https"]
	for _, hostname := range []string{"api.example.com", "one.example.net"} {
		if _, err := index.get(hostname); err != nil {
			t.Fatalf("get certificate for %q: %v", hostname, err)
		}
	}
	if _, err := index.get("one.two.example.net"); err == nil {
		t.Fatal("multi-label hostname unexpectedly matched wildcard certificate")
	}
}

func TestCustomCertificateLoader(t *testing.T) {
	certFile, keyFile := writeSelfSignedCertificate(t, []string{"db.example.com"})
	loadCount := 0
	loader := CertificateLoaderFunc(func(definition Certificate) (*tls.Certificate, error) {
		loadCount++
		if definition.Name != "database-certificate" {
			t.Fatalf("certificate name = %q", definition.Name)
		}
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &certificate, err
	})

	_, err := New(Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "https", Address: ":443", Protocol: ProtocolHTTPS, TLS: &TLSConfig{}},
		},
		Certificates: []Certificate{{Name: "database-certificate"}},
		Hosts: []VirtualHost{
			{
				Name:      "database",
				Hostnames: []string{"db.example.com"},
				Listeners: []string{"https"},
				TLS:       &HostTLS{Certificate: "database-certificate"},
				Routes:    []Route{staticRoute("home", "", "/", 200, "database")},
			},
		},
	}, WithCertificateLoader(loader))
	if err != nil {
		t.Fatal(err)
	}
	if loadCount != 1 {
		t.Fatalf("load count = %d, want 1", loadCount)
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "yabber.yaml")
	data := []byte(`
version: 1
server:
  shutdown_timeout: 10s
listeners:
  - name: http
    address: ":8080"
    protocol: http
certificates:
  - name: unused
    source:
      files:
        certificate: certs/site.pem
        private_key: certs/site.key
hosts:
  - name: site
    hostnames: [example.com]
    listeners: [http]
    routes:
      - name: files
        match:
          path: /
        handle:
          file_server:
            root: public
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Server.ShutdownTimeout != 10*time.Second {
		t.Fatalf("shutdown timeout = %s", config.Server.ShutdownTimeout)
	}
	def := config.Certificates[0]
	if def.CertificateFile != filepath.Join(dir, "certs/site.pem") {
		t.Fatalf("certificate path = %q", def.CertificateFile)
	}
	root := config.Hosts[0].Routes[0].Handle.FileServer.Root
	if root != filepath.Join(dir, "public") {
		t.Fatalf("file root = %q", root)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yabber.yaml")
	data := []byte(`
version: 1
unknown_option: true
listeners: []
hosts: []
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

func basicHTTPConfig(body string) Config {
	return Config{
		Version: ConfigVersion,
		Listeners: []Listener{
			{Name: "http", Address: ":8080", Protocol: ProtocolHTTP},
		},
		Hosts: []VirtualHost{
			{
				Name:      "site",
				Hostnames: []string{"example.com"},
				Listeners: []string{"http"},
				Routes:    []Route{staticRoute("home", "", "/", 200, body)},
			},
		},
	}
}

func staticRoute(name, method, path string, status int, body string) Route {
	return Route{
		Name:  name,
		Match: Match{Method: method, Path: path},
		Handle: Handler{StaticResponse: &StaticResponse{
			Status: status,
			Body:   body,
		}},
	}
}

func assertResponseBody(t *testing.T, handler http.Handler, host, expected string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	request.Host = host
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != expected {
		t.Fatalf("response = (%d, %q), want (200, %q)", response.Code, response.Body.String(), expected)
	}
}

func writeSelfSignedCertificate(t *testing.T, dnsNames []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "certificate.pem")
	keyFile := filepath.Join(dir, "privatekey.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
