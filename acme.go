package yabber

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lsongdev/acme-go/acme"
)

const (
	letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	acmeChallengePrefix  = "/.well-known/acme-challenge/"
	acmeOrderTimeout     = 5 * time.Minute
	acmeCheckInterval    = 12 * time.Hour
	acmeMinRetry         = 5 * time.Minute
	acmeMaxRetry         = 12 * time.Hour
)

// HTTP01Store answers ACME HTTP-01 challenges for an ACME client running
// outside Yabber.
type HTTP01Store interface {
	GetHTTP01Token(host, token string) (keyAuthorization string, ok bool)
}

// WithHTTP01Store answers /.well-known/acme-challenge/ requests on plain HTTP
// listeners ahead of sites and HTTPS redirects. It is only needed when
// certificates come from an external ACME client; tls.acme answers its own
// challenges.
func WithHTTP01Store(store HTTP01Store) Option {
	return func(o *options) { o.http01 = store }
}

// serveACMEChallenge answers an HTTP-01 challenge request, if r is one.
func (s *Server) serveACMEChallenge(w http.ResponseWriter, r *http.Request, state *requestState) bool {
	if r.TLS != nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	token, ok := strings.CutPrefix(r.URL.Path, acmeChallengePrefix)
	if !ok || token == "" || strings.Contains(token, "/") {
		return false
	}
	keyAuthorization, ok := "", false
	if manager := s.current.Load().acme; manager != nil {
		keyAuthorization, ok = manager.challenge(token)
	}
	if !ok && s.opts.http01 != nil {
		keyAuthorization, ok = s.opts.http01.GetHTTP01Token(requestHost(r.Host), token)
	}
	if !ok {
		return false
	}
	state.route = "acme-http-01"
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(keyAuthorization))
	}
	return true
}

// acmeEligible reports whether ACME HTTP-01 can issue a certificate for a
// host pattern.
func acmeEligible(host string) bool {
	if host == "*" || strings.HasPrefix(host, "*.") {
		return false
	}
	_, err := netip.ParseAddr(host)
	return err != nil
}

// acmeManager obtains and renews one certificate per hostname with HTTP-01
// challenges. Certificates and the account are stored on disk per ACME
// directory, so staging and production never mix. A single goroutine (run)
// talks to the CA; handshakes and challenge requests only read state.
type acmeManager struct {
	config      ACMEConfig
	logger      *slog.Logger
	client      *acme.Client
	accountPath string
	certDir     string

	mu       sync.RWMutex
	hosts    []string
	certs    map[string]*tls.Certificate
	failures map[string]*acmeFailure
	tokens   map[string]string
	wake     chan struct{}
}

type acmeFailure struct {
	err     error
	count   int
	retryAt time.Time
}

func newACMEManager(config ACMEConfig, logger *slog.Logger) (*acmeManager, error) {
	if config.Storage == "" {
		return nil, errors.New("tls.acme.storage is required")
	}
	if config.Directory == "" {
		config.Directory = letsEncryptDirectory
	}
	directory, err := url.Parse(config.Directory)
	if err != nil || directory.Host == "" {
		return nil, fmt.Errorf("invalid tls.acme.directory %q", config.Directory)
	}
	httpClient := &http.Client{Timeout: time.Minute}
	if config.CARoot != "" {
		pem, err := os.ReadFile(config.CARoot)
		if err != nil {
			return nil, fmt.Errorf("tls.acme.ca_root: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.acme.ca_root %s contains no certificates", config.CARoot)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
		httpClient.Transport = transport
	}
	client, err := acme.NewClient(&acme.Config{DirectoryURL: config.Directory})
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	name := strings.ReplaceAll(directory.Host, ":", "_")
	return &acmeManager{
		config:      config,
		logger:      logger,
		client:      client,
		accountPath: filepath.Join(config.Storage, "accounts", name+".json"),
		certDir:     filepath.Join(config.Storage, "certificates", name),
		certs:       make(map[string]*tls.Certificate),
		failures:    make(map[string]*acmeFailure),
		tokens:      make(map[string]string),
		wake:        make(chan struct{}, 1),
	}, nil
}

// setHosts replaces the managed hostnames, loading stored certificates for
// new ones, and wakes the issuing loop.
func (m *acmeManager) setHosts(hosts []string) {
	m.mu.Lock()
	m.hosts = hosts
	for _, host := range hosts {
		if m.certs[host] != nil {
			continue
		}
		certificate, err := tls.LoadX509KeyPair(m.certPath(host))
		if err == nil {
			err = parseLeaf(&certificate)
		}
		switch {
		case err == nil:
			m.certs[host] = &certificate
		case !errors.Is(err, fs.ErrNotExist):
			m.logger.Warn("ignoring stored ACME certificate", "host", host, "error", err)
		}
	}
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *acmeManager) certificate(host string) (*tls.Certificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	certificate, ok := m.certs[host]
	return certificate, ok
}

func (m *acmeManager) challenge(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keyAuthorization, ok := m.tokens[token]
	return keyAuthorization, ok
}

func (m *acmeManager) certPath(host string) (string, string) {
	base := filepath.Join(m.certDir, host)
	return base + ".crt", base + ".key"
}

// run issues and renews certificates until ctx is done.
func (m *acmeManager) run(ctx context.Context) {
	for {
		timer := time.NewTimer(time.Until(m.maintain(ctx)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// maintain obtains every certificate that is missing or due for renewal and
// returns when it should run again.
func (m *acmeManager) maintain(ctx context.Context) time.Time {
	now := time.Now()
	next := now.Add(acmeCheckInterval)
	m.mu.RLock()
	hosts := slices.Clone(m.hosts)
	m.mu.RUnlock()
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		if certificate, ok := m.certificate(host); ok && now.Before(renewAt(certificate.Leaf)) {
			next = earliest(next, renewAt(certificate.Leaf))
			continue
		}
		m.mu.RLock()
		failure := m.failures[host]
		m.mu.RUnlock()
		if failure != nil && now.Before(failure.retryAt) {
			next = earliest(next, failure.retryAt)
			continue
		}

		certificate, err := m.obtain(ctx, host)
		m.mu.Lock()
		if err != nil {
			if failure == nil {
				failure = &acmeFailure{}
			}
			failure.err, failure.count = err, failure.count+1
			failure.retryAt = time.Now().Add(min(acmeMinRetry<<min(failure.count-1, 10), acmeMaxRetry))
			m.failures[host] = failure
			next = earliest(next, failure.retryAt)
		} else {
			m.certs[host] = certificate
			delete(m.failures, host)
			next = earliest(next, renewAt(certificate.Leaf))
		}
		m.mu.Unlock()
		if err != nil {
			if ctx.Err() == nil {
				m.logger.Warn("ACME certificate request failed", "host", host, "error", err, "retry_at", failure.retryAt)
			}
		} else {
			m.logger.Info("ACME certificate obtained", "host", host, "not_after", certificate.Leaf.NotAfter)
		}
	}
	return next
}

// renewAt is two thirds into a certificate's lifetime: 30 days before expiry
// for Let's Encrypt's 90-day certificates.
func renewAt(leaf *x509.Certificate) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(lifetime * 2 / 3)
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (m *acmeManager) obtain(ctx context.Context, host string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, acmeOrderTimeout)
	defer cancel()
	if err := m.ensureAccount(ctx); err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	orderURL, order, err := m.client.CreateOrder(ctx, &acme.OrderRequest{
		Identifiers: []acme.Identifier{{Type: "dns", Value: host}},
	})
	if err != nil {
		return nil, fmt.Errorf("create order: %w", err)
	}
	for _, authorizationURL := range order.Authorizations {
		if err := m.authorize(ctx, authorizationURL); err != nil {
			return nil, err
		}
	}
	if order, err = m.client.WaitOrder(ctx, orderURL); err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if order.Status != acme.OrderStatusValid {
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, key)
		if err != nil {
			return nil, err
		}
		if _, err := m.client.FinalizeOrder(ctx, order.Finalize, csr); err != nil {
			return nil, fmt.Errorf("finalize order: %w", err)
		}
		if order, err = m.client.WaitOrder(ctx, orderURL); err != nil {
			return nil, err
		}
		if order.Status != acme.OrderStatusValid {
			return nil, fmt.Errorf("order is %s after finalization", order.Status)
		}
	}
	chain, err := m.client.GetCertificatePEM(ctx, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("download certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair([]byte(chain), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("issued certificate: %w", err)
	}
	if err := parseLeaf(&certificate); err != nil {
		return nil, err
	}
	certPath, keyPath := m.certPath(host)
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, []byte(chain), 0o644); err != nil {
		return nil, err
	}
	return &certificate, nil
}

func (m *acmeManager) authorize(ctx context.Context, authorizationURL string) error {
	authorization, err := m.client.GetAuthorization(ctx, authorizationURL)
	if err != nil {
		return fmt.Errorf("get authorization: %w", err)
	}
	if authorization.Status == acme.AuthorizationStatusValid {
		return nil
	}
	index := slices.IndexFunc(authorization.Challenges, func(c acme.Challenge) bool { return c.Type == "http-01" })
	if index < 0 {
		return fmt.Errorf("CA offered no http-01 challenge for %s", authorization.Identifier.Value)
	}
	challenge := authorization.Challenges[index]
	keyAuthorization, err := m.client.GetKeyAuthorization(challenge.Token)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.tokens[challenge.Token] = keyAuthorization
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.tokens, challenge.Token)
		m.mu.Unlock()
	}()
	if err := m.client.CompleteChallenge(ctx, challenge.URL); err != nil {
		return fmt.Errorf("start challenge: %w", err)
	}
	if _, err := m.client.WaitAuthorization(ctx, authorizationURL); err != nil {
		return fmt.Errorf("validate %s: %w", authorization.Identifier.Value, err)
	}
	return nil
}

type acmeAccount struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

// ensureAccount loads the stored account or registers a new one, agreeing
// to the CA's terms of service.
func (m *acmeManager) ensureAccount(ctx context.Context) error {
	if m.client.AccountURL != "" {
		return nil
	}
	data, err := os.ReadFile(m.accountPath)
	if err == nil {
		var account acmeAccount
		if err := json.Unmarshal(data, &account); err != nil {
			return fmt.Errorf("%s: %w", m.accountPath, err)
		}
		if err := m.client.ImportKey(account.Key); err != nil {
			return err
		}
		m.client.AccountURL = account.URL
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := m.client.GenerateKey(); err != nil {
		return err
	}
	contact := []string{}
	if m.config.Email != "" {
		contact = append(contact, "mailto:"+m.config.Email)
	}
	accountURL, _, err := m.client.Register(ctx, &acme.AccountRequest{TermsOfServiceAgreed: true, Contact: contact})
	if err != nil {
		return err
	}
	key, err := m.client.ExportKey()
	if err != nil {
		return err
	}
	data, err = json.MarshalIndent(acmeAccount{URL: accountURL, Key: key}, "", "  ")
	if err != nil {
		return err
	}
	m.logger.Info("ACME account registered", "directory", m.config.Directory, "account", accountURL)
	return writeFileAtomic(m.accountPath, data, 0o600)
}

// writeFileAtomic replaces path so that readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err == nil {
		err = file.Chmod(perm)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// CertificateStatus describes a certificate the server can present.
type CertificateStatus struct {
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after,omitzero"`
	// Managed certificates are obtained and renewed through ACME.
	Managed bool `json:"managed"`
	// Error is the last failed ACME attempt for a managed name.
	Error   string    `json:"error,omitempty"`
	RetryAt time.Time `json:"retry_at,omitzero"`
}

func (m *acmeManager) statuses() []CertificateStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var statuses []CertificateStatus
	for _, host := range m.hosts {
		status := CertificateStatus{Names: []string{host}, Managed: true}
		if certificate := m.certs[host]; certificate != nil {
			status.NotAfter = certificate.Leaf.NotAfter
		}
		if failure := m.failures[host]; failure != nil {
			status.Error, status.RetryAt = failure.err.Error(), failure.retryAt
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func staticCertificateStatuses(table *certificateTable) []CertificateStatus {
	seen := make(map[*tls.Certificate]bool)
	var statuses []CertificateStatus
	for _, certificates := range []map[string]*tls.Certificate{table.exact, table.wildcard} {
		for _, certificate := range certificates {
			if !seen[certificate] {
				seen[certificate] = true
				statuses = append(statuses, CertificateStatus{Names: certificate.Leaf.DNSNames, NotAfter: certificate.Leaf.NotAfter})
			}
		}
	}
	return statuses
}
