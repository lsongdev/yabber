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
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	mu            sync.Mutex
	nonce         int
	thumbprint    string
	orders        []*fakeOrder
	accounts      map[string]bool // valid account URLs
	registrations int
}

type fakeOrder struct {
	host, token string
	status      string // pending, ready, valid, invalid
	problem     string
	chain       []byte
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{accounts: make(map[string]bool)}
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
		ca.registrations++
		account := fmt.Sprintf("%s/account/%d", ca.server.URL, ca.registrations)
		ca.accounts[account] = true
		ca.mu.Unlock()
		w.Header().Set("Location", account)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))
	})
	mux.HandleFunc("POST /order", func(w http.ResponseWriter, r *http.Request) {
		header, payload := ca.decode(t, w, r)
		ca.mu.Lock()
		known := ca.accounts[header.KID]
		ca.mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"account not found"}`))
			return
		}
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

// dropAccounts forgets every account, as a CA does when one is deleted.
func (ca *fakeCA) dropAccounts() {
	ca.mu.Lock()
	clear(ca.accounts)
	ca.mu.Unlock()
}

type fakeJWSHeader struct {
	JWK json.RawMessage
	KID string
}

func (ca *fakeCA) decode(t *testing.T, w http.ResponseWriter, r *http.Request) (fakeJWSHeader, []byte) {
	ca.setNonce(w)
	var jws struct{ Protected, Payload string }
	json.NewDecoder(r.Body).Decode(&jws)
	protected, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var header fakeJWSHeader
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

func acmeConfig(ca *fakeCA, t *testing.T, hosts ...string) Config {
	return Config{
		Listeners: []Listener{
			{Name: "http", Address: "127.0.0.1:0"},
			{Name: "https", Address: "127.0.0.1:0", TLS: true},
		},
		TLS: TLSConfig{ACME: &ACMEConfig{
			Email: "admin@example.com", Directory: ca.server.URL + "/directory",
			CARoot: ca.rootFile(t),
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
	dataDir := t.TempDir()
	config := acmeConfig(ca, t, "a.test", "b.test")

	// Start without ACME to learn the HTTP address, then enable it via Apply.
	plain := config
	plain.TLS = TLSConfig{}
	plain.Sites = []Site{{Hosts: []string{"a.test", "b.test"}, Listeners: []string{"http"}, Handler: respond("plain")}}
	server := startServer(t, plain, WithDataDir(dataDir))
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
	if info, err := os.Stat(filepath.Join(dataDir, "acme", "certificates")); err != nil || !info.IsDir() {
		t.Fatalf("storage = %v", err)
	}
	keys, _ := filepath.Glob(filepath.Join(dataDir, "acme", "certificates", "*", "a.test.key"))
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
	restarted := startServer(t, config, WithDataDir(dataDir))
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
	config := acmeConfig(ca, t, "fail.test")
	ca.validateAddr.Store("127.0.0.1:1")
	server := startServer(t, config, WithDataDir(t.TempDir()))
	status := waitForCertificate(t, server, "fail.test")
	if !strings.Contains(status.Error, "rejected by test") || time.Until(status.RetryAt) < 4*time.Minute {
		t.Fatalf("status = %#v", status)
	}
}

func TestACMEConfigValidation(t *testing.T) {
	ca := newFakeCA(t)
	dataDir := WithDataDir(t.TempDir())
	config := acmeConfig(ca, t, "*.wild.test")
	if err := Validate(config, dataDir); err == nil || !strings.Contains(err.Error(), "cannot issue wildcard") {
		t.Fatalf("wildcard: %v", err)
	}

	config = acmeConfig(ca, t, "a.test")
	config.Listeners = config.Listeners[1:]
	if err := Validate(config, dataDir); err == nil || !strings.Contains(err.Error(), "plain HTTP listener") {
		t.Fatalf("no HTTP listener: %v", err)
	}

	config = acmeConfig(ca, t, "a.test")
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "needs a data directory") {
		t.Fatalf("no data directory: %v", err)
	}

	config.TLS.ACME.AccountURL = "https://ca.test/acct/1"
	if err := Validate(config, dataDir); err == nil || !strings.Contains(err.Error(), "requires account_key") {
		t.Fatalf("account_url without key: %v", err)
	}
	config.TLS.ACME.AccountURL = ""
	config.TLS.ACME.AccountKey = filepath.Join(t.TempDir(), "missing.key")
	if err := Validate(config, dataDir); err == nil || !strings.Contains(err.Error(), "account_key") {
		t.Fatalf("missing account key: %v", err)
	}

	config = acmeConfig(ca, t, "a.test")
	config.Listeners = nil
	server := newServer(t, config, dataDir)
	if names := listenerNames(server); names != "http,https" {
		t.Fatalf("default listeners with ACME = %s", names)
	}
}

func TestACMEManagerSurvivesUnrelatedApply(t *testing.T) {
	ca := newFakeCA(t)
	config := acmeConfig(ca, t, "a.test")
	server := newServer(t, config, WithDataDir(t.TempDir()))
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

func TestLoadResolvesACMEPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("tls:\n  acme: {account_key: keys/account.pem, ca_root: ca.pem}\nsites: []\n"), 0o644)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.TLS.ACME.AccountKey; got != filepath.Join(dir, "keys/account.pem") {
		t.Fatalf("account_key = %q", got)
	}
	if got := config.TLS.ACME.CARoot; got != filepath.Join(dir, "ca.pem") {
		t.Fatalf("ca_root = %q", got)
	}
}

func TestACMETakesOverFromStaleListedCertificate(t *testing.T) {
	ca := newFakeCA(t)
	config := acmeConfig(ca, t, "a.test", "b.test")
	config.TLS.Certificates = []Certificate{
		writeCertificate(t, time.Now().Add(-time.Hour), "a.test"),  // expired
		writeCertificate(t, time.Now().Add(6*time.Hour), "b.test"), // inside the grace period
	}
	plain := Config{Listeners: config.Listeners[:1], Sites: []Site{{Hosts: []string{"x.test"}, Handler: respond("x")}}}
	server := startServer(t, plain, WithDataDir(t.TempDir()))
	ca.validateAddr.Store(address(t, server, "http"))
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	if got := server.current.Load().managedHosts; strings.Join(got, ",") != "a.test,b.test" {
		t.Fatalf("managed = %v", got)
	}
	for _, host := range []string{"a.test", "b.test"} {
		waitForCertificate(t, server, host)
		conn, err := tls.Dial("tcp", address(t, server, "https"), &tls.Config{ServerName: host, RootCAs: certPool(ca.root)})
		if err != nil {
			t.Fatalf("%s: ACME certificate not preferred over the stale one: %v", host, err)
		}
		conn.Close()
	}
}

func TestRefreshPicksUpRenewedAndExpiringCertificates(t *testing.T) {
	ca := newFakeCA(t)
	config := acmeConfig(ca, t, "a.test")
	listed := writeCertificate(t, time.Now().Add(30*24*time.Hour), "a.test")
	config.TLS.Certificates = []Certificate{listed}
	server := startServer(t, config, WithDataDir(t.TempDir()))
	if managed := server.current.Load().managedHosts; len(managed) != 0 {
		t.Fatalf("managed = %v while a current certificate covers the host", managed)
	}
	served := func() time.Time {
		conn, err := tls.Dial("tcp", address(t, server, "https"), &tls.Config{ServerName: "a.test", InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].NotAfter
	}
	before := served()

	// certbot-style renewal: the same paths now hold a newer certificate.
	renewed := writeCertificate(t, time.Now().Add(90*24*time.Hour), "a.test")
	copyFile(t, renewed.Cert, listed.Cert)
	copyFile(t, renewed.Key, listed.Key)
	server.mu.Lock()
	err := server.refreshCertificatesLocked()
	server.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if after := served(); !after.After(before) {
		t.Fatalf("refresh kept serving the old certificate (%v)", after)
	}

	// The listed certificate is about to expire: ACME takes the host over.
	expiring := writeCertificate(t, time.Now().Add(time.Hour), "a.test")
	copyFile(t, expiring.Cert, listed.Cert)
	copyFile(t, expiring.Key, listed.Key)
	server.mu.Lock()
	server.refreshCertificatesLocked()
	server.mu.Unlock()
	if managed := server.current.Load().managedHosts; strings.Join(managed, ",") != "a.test" {
		t.Fatalf("managed after expiry = %v", managed)
	}
}

func TestReloadResetsACMEBackoff(t *testing.T) {
	ca := newFakeCA(t)
	manager, err := newACMEManager(ACMEConfig{Directory: ca.server.URL + "/directory"}, t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		manager.recordFailure("a.test", errors.New("dns not ready"))
	}
	failedAt := manager.failures["a.test"].failedAt
	if wait := time.Until(manager.retryAt("a.test")); wait < 30*time.Minute {
		t.Fatalf("backoff after four failures = %v", wait)
	}

	manager.setHosts([]string{"a.test"}, false)
	if wait := time.Until(manager.retryAt("a.test")); wait < 30*time.Minute {
		t.Fatalf("a refresh reset the backoff: %v", wait)
	}
	manager.setHosts([]string{"a.test"}, true)
	if got := manager.retryAt("a.test"); !got.Equal(failedAt.Add(acmeReloadRetry)) {
		t.Fatalf("retry after reload = %v, want one minute after the last failure", got.Sub(failedAt))
	}
	if retryAt := manager.recordFailure("a.test", errors.New("again")); time.Until(retryAt) > acmeMinRetry {
		t.Fatalf("backoff did not restart from the minimum: %v", time.Until(retryAt))
	}
}

func TestCertificateMetrics(t *testing.T) {
	config := tlsConfig(Site{Hosts: []string{"a.com"}, Handler: respond("a")})
	config.TLS.Certificates = []Certificate{writeCertificate(t, time.Now().Add(48*time.Hour), "a.com")}
	server := newServer(t, config)
	var text strings.Builder
	if err := server.Metrics().WritePrometheus(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), `yabber_certificate_expiry_timestamp_seconds{names="a.com",managed="false"} `) {
		t.Fatalf("prometheus = %s", text.String())
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// issueAfterAccountLoss issues a.test, drops every account at the CA, then
// adds b.test so that the next order meets the lost account.
func issueAfterAccountLoss(t *testing.T, ca *fakeCA, config Config, dataDir string) *Server {
	t.Helper()
	plain := Config{Listeners: config.Listeners[:1], Sites: []Site{{Hosts: []string{"x.test"}, Handler: respond("x")}}}
	server := startServer(t, plain, WithDataDir(dataDir))
	ca.validateAddr.Store(address(t, server, "http"))
	config.Sites[0].Hosts = []string{"a.test"}
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	if status := waitForCertificate(t, server, "a.test"); status.Error != "" {
		t.Fatal(status.Error)
	}
	ca.dropAccounts()
	config.Sites[0].Hosts = []string{"a.test", "b.test"}
	if err := server.Apply(config); err != nil {
		t.Fatal(err)
	}
	return server
}

func hasEvent(server *Server, level, message string) bool {
	for _, event := range server.Events() {
		if event.Level == level && strings.Contains(event.Message, message) {
			return true
		}
	}
	return false
}

func TestGeneratedAccountIsReplacedVisibly(t *testing.T) {
	ca := newFakeCA(t)
	dataDir := t.TempDir()
	server := issueAfterAccountLoss(t, ca, acmeConfig(ca, t, "a.test"), dataDir)

	if status := waitForCertificate(t, server, "b.test"); status.Error != "" {
		t.Fatalf("issuance after account loss: %s", status.Error)
	}
	if !hasEvent(server, "WARN", "registered a new one") {
		t.Fatalf("no warning event for the replaced account: %#v", server.Events())
	}
	archived, _ := filepath.Glob(filepath.Join(dataDir, "acme", "accounts", "*.invalid-*"))
	if len(archived) != 1 || ca.registrations != 2 {
		t.Fatalf("archived = %v, registrations = %d", archived, ca.registrations)
	}
}

func TestConfiguredAccountIsNeverReplaced(t *testing.T) {
	ca := newFakeCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyFile := filepath.Join(t.TempDir(), "account.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	config := acmeConfig(ca, t, "a.test")
	config.TLS.ACME.AccountKey = keyFile
	server := issueAfterAccountLoss(t, ca, config, t.TempDir())

	status := waitForCertificate(t, server, "b.test")
	if !strings.Contains(status.Error, "configured account") {
		t.Fatalf("status = %#v", status)
	}
	if !hasEvent(server, "ERROR", "account from the configuration is no longer valid") {
		t.Fatalf("no error event: %#v", server.Events())
	}
	if ca.registrations != 1 {
		t.Fatalf("registrations = %d; the configured account was replaced", ca.registrations)
	}
}
