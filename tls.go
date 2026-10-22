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

// loadCertificates indexes every certificate by its DNS names. When several
// certificates cover a name, the one that expires last wins, so a renewed
// certificate can be added before the old one is removed. Expired
// certificates are logged rather than rejected: one stale certificate must
// not stop the whole gateway from starting or reloading.
func loadCertificates(files []Certificate, source CertificateSource, logger *slog.Logger) (*certificateTable, error) {
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

	table := newHostTable[*tls.Certificate]()
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
		if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			logger.Warn("certificate is outside its validity period",
				"names", strings.Join(leaf.DNSNames, ","),
				"not_before", leaf.NotBefore, "not_after", leaf.NotAfter)
		}
		for _, name := range leaf.DNSNames {
			name = normalizeHost(name)
			if current, ok := table.get(name); ok && !current.Leaf.NotAfter.Before(leaf.NotAfter) {
				continue
			}
			table.set(name, certificate)
		}
	}
	return table, nil
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
