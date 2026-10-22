package yabber

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCA is a minimal ACME server. It validates HTTP-01 challenges by
// fetching the token from validateAddr with the identifier as Host, and
// issues certificates signed by its own root.
type fakeCA struct {
	server       *httptest.Server
	root         *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	validateAddr atomic.Value // string
	reject       atomic.Bool  // fail every validation
	issued       atomic.Int32

	mu         sync.Mutex
	nonce      int
	thumbprint string
	orders     []*fakeOrder
}

type fakeOrder struct {
	host, token string
	status      string // pending, ready, valid, invalid
	problem     string
	chain       []byte
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{}
	ca.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &ca.rootKey.PublicKey, ca.rootKey)
	ca.root, _ = x509.ParseCertificate(der)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"newNonce":"%[1]s/nonce","newAccount":"%[1]s/account","newOrder":"%[1]s/order"}`, ca.server.URL)
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, r *http.Request) { ca.setNonce(w) })
	mux.HandleFunc("POST /account", func(w http.ResponseWriter, r *http.Request) {
		header, _ := ca.decode(t, w, r)
		var jwk map[string]string
		json.Unmarshal(header.JWK, &jwk)
		canonical, _ := json.Marshal(jwk) // keys sorted, as RFC 7638 requires
		sum := sha256.Sum256(canonical)
		ca.mu.Lock()
		ca.thumbprint = base64.RawURLEncoding.EncodeToString(sum[:])
		ca.mu.Unlock()
		w.Header().Set("Location", ca.server.URL+"/account/1")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))
	})
	mux.HandleFunc("POST /order", func(w http.ResponseWriter, r *http.Request) {
		_, payload := ca.decode(t, w, r)
		var request struct{ Identifiers []struct{ Value string } }
		json.Unmarshal(payload, &request)
		ca.mu.Lock()
		order := &fakeOrder{host: request.Identifiers[0].Value, token: rand.Text(), status: "pending"}
		ca.orders = append(ca.orders, order)
		id := len(ca.orders) - 1
		ca.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", ca.server.URL, id))
		w.WriteHeader(http.StatusCreated)
		ca.writeOrder(w, id)
	})
	mux.HandleFunc("POST /order/{id}", func(w http.ResponseWriter, r *http.Request) {
		ca.decode(t, w, r)
		ca.writeOrder(w, ca.id(r))
	})
	mux.HandleFunc("POST /authz/{id}", func(w http.ResponseWriter, r *http.Request) {
		ca.decode(t, w, r)
		ca.writeAuthorization(w, ca.id(r))
	})
	mux.HandleFunc("POST /chall/{id}", func(w http.ResponseWriter, r *http.Request) {
		ca.decode(t, w, r)
		id := ca.id(r)
		ca.validate(ca.orders[id])
		ca.writeAuthorization(w, id)
	})
	mux.HandleFunc("POST /finalize/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, payload := ca.decode(t, w, r)
		var request struct{ CSR string }
		json.Unmarshal(payload, &request)
		der, _ := base64.RawURLEncoding.DecodeString(request.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		id := ca.id(r)
		ca.mu.Lock()
		order := ca.orders[id]
		if err != nil || order.status != "ready" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != order.host {
			ca.mu.Unlock()
			http.Error(w, `{"type":"urn:ietf:params:acme:error:badCSR"}`, http.StatusBadRequest)
			return
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(id + 2)), DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, ca.root, csr.PublicKey, ca.rootKey)
		order.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
		order.status = "valid"
		ca.mu.Unlock()
		ca.issued.Add(1)
		ca.writeOrder(w, id)
	})
	mux.HandleFunc("POST /cert/{id}", func(w http.ResponseWriter, r *http.Request) {
		ca.decode(t, w, r)
		ca.mu.Lock()
		defer ca.mu.Unlock()
		w.Write(ca.orders[ca.id(r)].chain)
	})
	ca.server = httptest.NewTLSServer(mux)
	t.Cleanup(ca.server.Close)
	return ca
}

func (ca *fakeCA) setNonce(w http.ResponseWriter) {
	ca.mu.Lock()
	ca.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprint("nonce-", ca.nonce))
	ca.mu.Unlock()
}

func (ca *fakeCA) decode(t *testing.T, w http.ResponseWriter, r *http.Request) (struct{ JWK json.RawMessage }, []byte) {
	ca.setNonce(w)
	var jws struct{ Protected, Payload string }
	json.NewDecoder(r.Body).Decode(&jws)
	protected, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var header struct{ JWK json.RawMessage }
	json.Unmarshal(protected, &header)
	return header, payload
}

func (ca *fakeCA) id(r *http.Request) int {
	var id int
	fmt.Sscan(r.PathValue("id"), &id)
	return id
}

func (ca *fakeCA) validate(order *fakeOrder) {
	ca.mu.Lock()
	want := order.token + "." + ca.thumbprint
	ca.mu.Unlock()
	problem := ""
	request, _ := http.NewRequest("GET", "http://"+ca.validateAddr.Load().(string)+"/.well-known/acme-challenge/"+order.token, nil)
	request.Host = order.host
	response, err := http.DefaultClient.Do(request)
	switch {
	case ca.reject.Load():
		problem = "rejected by test"
	case err != nil:
		problem = err.Error()
	default:
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			problem = fmt.Sprintf("got %q (status %d), want key authorization", body, response.StatusCode)
		}
	}
	ca.mu.Lock()
	order.status, order.problem = "ready", problem
	if problem != "" {
		order.status = "invalid"
	}
	ca.mu.Unlock()
}

func (ca *fakeCA) writeOrder(w http.ResponseWriter, id int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	order := ca.orders[id]
	certificate := ""
	if order.status == "valid" {
		certificate = fmt.Sprintf("%s/cert/%d", ca.server.URL, id)
	}
	fmt.Fprintf(w, `{"status":%q,"identifiers":[{"type":"dns","value":%q}],"authorizations":["%s/authz/%d"],"finalize":"%s/finalize/%d","certificate":%q}`,
		order.status, order.host, ca.server.URL, id, ca.server.URL, id, certificate)
}

func (ca *fakeCA) writeAuthorization(w http.ResponseWriter, id int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	order := ca.orders[id]
	status, errorJSON := "pending", `{}`
	switch order.status {
	case "ready", "valid":
		status = "valid"
	case "invalid":
		status = "invalid"
		errorJSON = fmt.Sprintf(`{"type":"urn:ietf:params:acme:error:unauthorized","detail":%q}`, order.problem)
	}
	fmt.Fprintf(w, `{"status":%q,"identifier":{"type":"dns","value":%q},"challenges":[{"type":"http-01","url":"%s/chall/%d","token":%q,"status":%q,"error":%s}]}`,
		status, order.host, ca.server.URL, id, order.token, status, errorJSON)
}

// rootFile writes the CA's HTTPS server certificate for tls.acme.ca_root.
func (ca *fakeCA) rootFile(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.server.Certificate().Raw}), 0o644)
	return path
}

func acmeConfig(ca *fakeCA, t *testing.T, storage string, hosts ...string) Config {
	return Config{
		Listeners: []Listener{
			{Name: "http", Address: "127.0.0.1:0"},
			{Name: "https", Address: "127.0.0.1:0", TLS: true},
		},
		TLS: TLSConfig{ACME: &ACMEConfig{
			Email: "admin@example.com", Directory: ca.server.URL + "/directory",
			CARoot: ca.rootFile(t), Storage: storage,
		}},
		Sites: []Site{{Hosts: hosts, Handler: respond("secure")}},
	}
}

// waitForCertificate polls until host has a managed certificate or failure.
func waitForCertificate(t *testing.T, server *Server, host string) CertificateStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, status := range server.Certificates() {
			if status.Managed && status.Names[0] == host && (!status.NotAfter.IsZero() || status.Error != "") {
				return status
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no ACME result for %s: %#v", host, server.Certificates())
	return CertificateStatus{}
}

func TestACMEObtainsServesAndReusesCertificates(t *testing.T) {
	ca := newFakeCA(t)
	storage := t.TempDir()
	config := acmeConfig(ca, t, storage, "a.test", "b.test")

	// Start without ACME to learn the HTTP address, then enable it via Apply.
	plain := config
	plain.TLS = TLSConfig{}
	plain.Sites = []Site{{Hosts: []string{"a.test", "b.test"}, Listeners: []string{"http"}, Handler: respond("plain")}}
	server := startServer(t, plain)
	ca.validateAddr.Store(address(t, server, "http"))
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"a.test", "b.test"} {
		if status := waitForCertificate(t, server, host); status.Error != "" {
			t.Fatalf("%s: %s", host, status.Error)
		}
		conn, err := tls.Dial("tcp", address(t, server, "https"), &tls.Config{ServerName: host, RootCAs: certPool(ca.root)})
		if err != nil {
			t.Fatalf("%s: handshake: %v", host, err)
		}
		conn.Close()
	}
	if info, err := os.Stat(filepath.Join(storage, "certificates")); err != nil || !info.IsDir() {
		t.Fatalf("storage = %v", err)
	}
	keys, _ := filepath.Glob(filepath.Join(storage, "certificates", "*", "a.test.key"))
	if len(keys) != 1 {
		t.Fatalf("stored keys = %v", keys)
	}
	if info, _ := os.Stat(keys[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", info.Mode())
	}
	if issued := ca.issued.Load(); issued != 2 {
		t.Fatalf("issued = %d", issued)
	}

	// A new server with the same storage serves stored certificates at once.
	server.Close()
	restarted := startServer(t, config)
	if status := waitForCertificate(t, restarted, "a.test"); status.NotAfter.IsZero() {
		t.Fatalf("status = %#v", status)
	}
	time.Sleep(100 * time.Millisecond)
	if issued := ca.issued.Load(); issued != 2 {
		t.Fatalf("restart re-issued certificates: issued = %d", issued)
	}
}

func TestACMEFailureIsReportedAndRetriedLater(t *testing.T) {
	ca := newFakeCA(t)
	ca.reject.Store(true)
	config := acmeConfig(ca, t, t.TempDir(), "fail.test")
	ca.validateAddr.Store("127.0.0.1:1")
	server := startServer(t, config)
	status := waitForCertificate(t, server, "fail.test")
	if !strings.Contains(status.Error, "rejected by test") || time.Until(status.RetryAt) < 4*time.Minute {
		t.Fatalf("status = %#v", status)
	}
}

func TestACMEConfigValidation(t *testing.T) {
	ca := newFakeCA(t)
	config := acmeConfig(ca, t, t.TempDir(), "*.wild.test")
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "cannot issue wildcard") {
		t.Fatalf("wildcard: %v", err)
	}

	config = acmeConfig(ca, t, t.TempDir(), "a.test")
	config.Listeners = config.Listeners[1:]
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "plain HTTP listener") {
		t.Fatalf("no HTTP listener: %v", err)
	}

	config = acmeConfig(ca, t, "", "a.test")
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "storage is required") {
		t.Fatalf("no storage: %v", err)
	}

	config = acmeConfig(ca, t, t.TempDir(), "a.test")
	config.Listeners = nil
	server := newServer(t, config)
	if names := listenerNames(server); names != "http,https" {
		t.Fatalf("default listeners with ACME = %s", names)
	}
}

func TestACMEManagerSurvivesUnrelatedApply(t *testing.T) {
	ca := newFakeCA(t)
	config := acmeConfig(ca, t, t.TempDir(), "a.test")
	server := newServer(t, config)
	before := server.current.Load().acme
	config.Sites[0].Handler = respond("changed")
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	if server.current.Load().acme != before {
		t.Fatal("Apply replaced an unchanged ACME manager")
	}
}

func TestRenewAt(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	if got, want := renewAt(leaf), start.Add(60*24*time.Hour); !got.Equal(want) {
		t.Fatalf("renewAt = %v, want %v", got, want)
	}
}

func certPool(certificates ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

func TestLoadDefaultsACMEStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yabber.yaml")
	os.WriteFile(path, []byte("tls:\n  acme: {email: a@b.c}\nsites: []\n"), 0o644)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.TLS.ACME.Storage; got != filepath.Join(dir, "acme") {
		t.Fatalf("storage = %q", got)
	}
}
