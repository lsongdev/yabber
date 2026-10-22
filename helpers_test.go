package yabber

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// siteConfig serves one site on a single plain HTTP listener.
func siteConfig(site Site) Config {
	return Config{
		Listeners: []Listener{{Name: "http", Address: "127.0.0.1:0"}},
		Sites:     []Site{site},
	}
}

func respond(body string) Handler {
	return Handler{Respond: &Respond{Body: body}}
}

func newServer(t *testing.T, config Config, options ...Option) *Server {
	t.Helper()
	server, err := New(config, options...)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func startServer(t *testing.T, config Config, options ...Option) *Server {
	t.Helper()
	server := newServer(t, config, options...)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// serve sends a request through a listener handler without a network.
func serve(t *testing.T, server *Server, listener string, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	handler, err := server.Handler(listener)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func get(t *testing.T, server *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, server, "http", httptest.NewRequest(http.MethodGet, url, nil))
}

func assertResponse(t *testing.T, response *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if response.Code != status || (body != "" && response.Body.String() != body) {
		t.Fatalf("response = (%d, %q), want (%d, %q)", response.Code, response.Body.String(), status, body)
	}
}

func address(t *testing.T, server *Server, listener string) string {
	t.Helper()
	for _, status := range server.Status().Listeners {
		if status.Name == listener && status.Running {
			return status.Address
		}
	}
	t.Fatalf("listener %q is not running", listener)
	return ""
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeCertificate(t *testing.T, notAfter time.Time, names ...string) Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certificate := Certificate{Cert: filepath.Join(dir, "cert.pem"), Key: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(certificate.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificate.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificate
}
