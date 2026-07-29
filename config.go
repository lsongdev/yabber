// Package yabber implements a small, embeddable HTTP and HTTPS server.
package yabber

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ConfigVersion = 1

type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
)

type Config struct {
	Version      int           `json:"version" yaml:"version"`
	Server       ServerConfig  `json:"server,omitempty" yaml:"server,omitempty"`
	Policies     []Policy      `json:"policies,omitempty" yaml:"policies,omitempty"`
	Listeners    []Listener    `json:"listeners" yaml:"listeners"`
	Certificates []Certificate `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	Hosts        []VirtualHost `json:"hosts" yaml:"hosts"`
}

type ServerConfig struct {
	ShutdownTimeout   time.Duration `json:"shutdown_timeout,omitempty" yaml:"shutdown_timeout,omitempty"`
	ReadTimeout       time.Duration `json:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	ReadHeaderTimeout time.Duration `json:"read_header_timeout,omitempty" yaml:"read_header_timeout,omitempty"`
	WriteTimeout      time.Duration `json:"write_timeout,omitempty" yaml:"write_timeout,omitempty"`
	IdleTimeout       time.Duration `json:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
	MaxHeaderBytes    int           `json:"max_header_bytes,omitempty" yaml:"max_header_bytes,omitempty"`
}

type Listener struct {
	Name           string     `json:"name" yaml:"name"`
	Address        string     `json:"address" yaml:"address"`
	Protocol       Protocol   `json:"protocol" yaml:"protocol"`
	Enabled        *bool      `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	TLS            *TLSConfig `json:"tls,omitempty" yaml:"tls,omitempty"`
	TrustedProxies []string   `json:"trusted_proxies,omitempty" yaml:"trusted_proxies,omitempty"`
	Policies       []string   `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type TLSConfig struct {
	MinVersion         string `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	DefaultCertificate string `json:"default_certificate,omitempty" yaml:"default_certificate,omitempty"`
}

type Certificate struct {
	Name            string `json:"name" yaml:"name"`
	Certificate     string `json:"certificate" yaml:"certificate"`
	PrivateKey      string `json:"private_key" yaml:"private_key"`
	CertificateFile string `json:"certificate_file" yaml:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file" yaml:"private_key_file"`
}

type VirtualHost struct {
	Name      string    `json:"name" yaml:"name"`
	Hostnames []string  `json:"hostnames" yaml:"hostnames"`
	Listeners []string  `json:"listeners" yaml:"listeners"`
	Enabled   *bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	TLS       *HostTLS  `json:"tls,omitempty" yaml:"tls,omitempty"`
	HTTP      *HostHTTP `json:"http,omitempty" yaml:"http,omitempty"`
	Policies  []string  `json:"policies,omitempty" yaml:"policies,omitempty"`
	Routes    []Route   `json:"routes,omitempty" yaml:"routes,omitempty"`
}

type HostTLS struct {
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
}

type HostHTTP struct {
	RedirectToHTTPS bool `json:"redirect_to_https,omitempty" yaml:"redirect_to_https,omitempty"`
}

type Route struct {
	Name     string   `json:"name" yaml:"name"`
	Match    Match    `json:"match,omitempty" yaml:"match,omitempty"`
	Handle   Handler  `json:"handle" yaml:"handle"`
	Enabled  *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Policies []string `json:"policies,omitempty" yaml:"policies,omitempty"`
}

// Policy is a reusable middleware bundle. Policies may be attached to a
// listener, virtual host, or route.
type Policy struct {
	Name        string             `json:"name" yaml:"name"`
	Request     *RequestPolicy     `json:"request,omitempty" yaml:"request,omitempty"`
	RateLimit   *RateLimitPolicy   `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	Concurrency *ConcurrencyPolicy `json:"concurrency,omitempty" yaml:"concurrency,omitempty"`
}

type RequestPolicy struct {
	MaxBodyBytes int64         `json:"max_body_bytes,omitempty" yaml:"max_body_bytes,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

type RateLimitPolicy struct {
	RequestsPerSecond float64       `json:"requests_per_second" yaml:"requests_per_second"`
	Burst             int           `json:"burst" yaml:"burst"`
	Key               string        `json:"key,omitempty" yaml:"key,omitempty"`
	MaxKeys           int           `json:"max_keys,omitempty" yaml:"max_keys,omitempty"`
	IdleTimeout       time.Duration `json:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
}

type ConcurrencyPolicy struct {
	Max int `json:"max" yaml:"max"`
}

type Match struct {
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty"`
}

type Handler struct {
	ReverseProxy   *ReverseProxy   `json:"reverse_proxy,omitempty" yaml:"reverse_proxy,omitempty"`
	FileServer     *FileServer     `json:"file_server,omitempty" yaml:"file_server,omitempty"`
	StaticResponse *StaticResponse `json:"static_response,omitempty" yaml:"static_response,omitempty"`
	Redirect       *Redirect       `json:"redirect,omitempty" yaml:"redirect,omitempty"`
	Worker         *WorkerHandler  `json:"worker,omitempty" yaml:"worker,omitempty"`
}

type WorkerHandler struct {
	Script string `json:"script" yaml:"script"`
}

type ReverseProxy struct {
	URL                    string        `json:"url" yaml:"url"`
	StripPrefix            string        `json:"strip_prefix,omitempty" yaml:"strip_prefix,omitempty"`
	RequestTimeout         time.Duration `json:"request_timeout,omitempty" yaml:"request_timeout,omitempty"`
	DialTimeout            time.Duration `json:"dial_timeout,omitempty" yaml:"dial_timeout,omitempty"`
	TLSHandshakeTimeout    time.Duration `json:"tls_handshake_timeout,omitempty" yaml:"tls_handshake_timeout,omitempty"`
	ResponseHeaderTimeout  time.Duration `json:"response_header_timeout,omitempty" yaml:"response_header_timeout,omitempty"`
	IdleConnTimeout        time.Duration `json:"idle_conn_timeout,omitempty" yaml:"idle_conn_timeout,omitempty"`
	ExpectContinueTimeout  time.Duration `json:"expect_continue_timeout,omitempty" yaml:"expect_continue_timeout,omitempty"`
	MaxIdleConns           int           `json:"max_idle_conns,omitempty" yaml:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost    int           `json:"max_idle_conns_per_host,omitempty" yaml:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost        int           `json:"max_conns_per_host,omitempty" yaml:"max_conns_per_host,omitempty"`
	MaxResponseHeaderBytes int64         `json:"max_response_header_bytes,omitempty" yaml:"max_response_header_bytes,omitempty"`
}

type FileServer struct {
	Root        string `json:"root" yaml:"root"`
	StripPrefix string `json:"strip_prefix,omitempty" yaml:"strip_prefix,omitempty"`
}

type StaticResponse struct {
	Status  int               `json:"status,omitempty" yaml:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body    string            `json:"body,omitempty" yaml:"body,omitempty"`
}

type Redirect struct {
	Location string `json:"location" yaml:"location"`
	Status   int    `json:"status,omitempty" yaml:"status,omitempty"`
}

// Load reads a YAML configuration file. Relative certificate and file-server
// paths are resolved relative to the configuration file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	base := filepath.Dir(path)
	for i := range cfg.Certificates {
		def := &cfg.Certificates[i]
		if def.CertificateFile == "" || def.PrivateKeyFile == "" {
			continue
		}
		def.CertificateFile = resolvePath(base, def.CertificateFile)
		def.PrivateKeyFile = resolvePath(base, def.PrivateKeyFile)
	}
	for i := range cfg.Hosts {
		for j := range cfg.Hosts[i].Routes {
			files := cfg.Hosts[i].Routes[j].Handle.FileServer
			if files != nil {
				files.Root = resolvePath(base, files.Root)
			}
		}
	}
	return cfg, nil
}

// Validate parses referenced certificates and builds all configured routes
// without binding any network listeners.
func Validate(config Config) error {
	_, err := compile(config, FileCertificateLoader{})
	return err
}

func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}

func enabled(value *bool) bool {
	return value == nil || *value
}

func normalizedHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
