package yabber

import (
	"crypto/tls"
	"fmt"
	"os"
)

// CertificateLoader resolves certificate material. OhMyServer can implement
// this interface with an in-memory database adapter; standalone Yabber uses
// FileCertificateLoader.
type CertificateLoader interface {
	LoadCertificate(Certificate) (*tls.Certificate, error)
}

type CertificateLoaderFunc func(Certificate) (*tls.Certificate, error)

func (f CertificateLoaderFunc) LoadCertificate(certificate Certificate) (*tls.Certificate, error) {
	return f(certificate)
}

type FileCertificateLoader struct{}

func (FileCertificateLoader) LoadCertificate(definition Certificate) (*tls.Certificate, error) {
	if definition.CertificateFile == "" || definition.PrivateKeyFile == "" {
		return nil, fmt.Errorf("certificate %q requires certificate and private_key files", definition.Name)
	}
	certPEM, err := os.ReadFile(definition.CertificateFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(definition.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}
