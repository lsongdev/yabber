package yabber

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// CertificateSource supplies certificates in addition to those listed in the
// configuration, for example from a database. It is called whenever a
// configuration is compiled.
type CertificateSource interface {
	Certificates() ([]tls.Certificate, error)
}

// CertificateSourceFunc adapts a function to CertificateSource.
type CertificateSourceFunc func() ([]tls.Certificate, error)

func (f CertificateSourceFunc) Certificates() ([]tls.Certificate, error) { return f() }

// certificateTable selects certificates by SNI hostname.
type certificateTable = hostTable[*tls.Certificate]

// certificateGrace is how long a listed certificate must remain valid to
// count as covering its names. Within it, ACME takes over a host a day
// before the listed certificate expires.
const certificateGrace = 24 * time.Hour

// certificateStore holds the listed certificates, split by validity. Only
// current certificates cover hosts; stale ones (expired, expiring within
// certificateGrace, or not yet valid) are served only as a last resort, so
// one stale file never blocks a reload but never blocks ACME either.
type certificateStore struct {
	current *certificateTable
	stale   *certificateTable
}

func (s *certificateStore) empty() bool {
	return s.current.empty() && s.stale.empty()
}

// loadCertificates reads the listed certificates and those from source. When
// several certificates cover a name, the one that expires last wins, so a
// renewed certificate can be added before the old one is removed.
func loadCertificates(files []Certificate, source CertificateSource, logger *slog.Logger) (*certificateStore, error) {
	var certificates []tls.Certificate
	for _, file := range files {
		if file.Cert == "" || file.Key == "" {
			return nil, errors.New("certificate requires both cert and key")
		}
		certificate, err := tls.LoadX509KeyPair(file.Cert, file.Key)
		if err != nil {
			return nil, fmt.Errorf("load certificate %s: %w", file.Cert, err)
		}
		certificates = append(certificates, certificate)
	}
	if source != nil {
		extra, err := source.Certificates()
		if err != nil {
			return nil, fmt.Errorf("certificate source: %w", err)
		}
		certificates = append(certificates, extra...)
	}

	store := &certificateStore{current: newHostTable[*tls.Certificate](), stale: newHostTable[*tls.Certificate]()}
	now := time.Now()
	for i := range certificates {
		certificate := &certificates[i]
		if err := parseLeaf(certificate); err != nil {
			return nil, err
		}
		leaf := certificate.Leaf
		if len(leaf.DNSNames) == 0 {
			return nil, fmt.Errorf("certificate %q has no DNS names", leaf.Subject.CommonName)
		}
		table := store.current
		if now.Before(leaf.NotBefore) || now.Add(certificateGrace).After(leaf.NotAfter) {
			table = store.stale
			logger.Warn("certificate is expired, expiring or not yet valid; it no longer covers its names",
				"names", strings.Join(leaf.DNSNames, ","),
				"not_before", leaf.NotBefore, "not_after", leaf.NotAfter)
		}
		for _, name := range leaf.DNSNames {
			name = normalizeHost(name)
			if existing, ok := table.get(name); ok && !existing.Leaf.NotAfter.Before(leaf.NotAfter) {
				continue
			}
			table.set(name, certificate)
		}
	}
	return store, nil
}

func parseLeaf(certificate *tls.Certificate) error {
	if certificate.Leaf != nil {
		return nil
	}
	if len(certificate.Certificate) == 0 {
		return errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	certificate.Leaf = leaf
	return nil
}

// covers reports whether a certificate in the table serves a host pattern.
// The catch-all "*" is served for whichever names have certificates.
func covers(table *certificateTable, pattern string) bool {
	if pattern == "*" {
		return true
	}
	// A wildcard pattern's first label "*" makes match consult only the
	// wildcard certificate for its parent domain.
	_, ok := table.match(pattern)
	return ok
}

func tlsVersion(value string) (uint16, error) {
	switch strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "TLS") {
	case "", "1.2", "12":
		return tls.VersionTLS12, nil
	case "1.3", "13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS minimum version %q", value)
	}
}
