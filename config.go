// Package yabber is a small HTTP and HTTPS gateway built on net/http. It
// terminates TLS, matches requests by hostname and path, and forwards them to
// upstream services, static files, redirects or fixed responses.
package yabber

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigVersion is the configuration schema version understood by this package.
const ConfigVersion = 1

// Config describes a complete gateway.
type Config struct {
	Version   int          `yaml:"version,omitempty" json:"version,omitempty"`
	Server    ServerConfig `yaml:"server,omitempty" json:"server,omitempty"`
	TLS       TLSConfig    `yaml:"tls,omitempty" json:"tls,omitempty"`
	Listeners []Listener   `yaml:"listeners,omitempty" json:"listeners,omitempty"`
	Policies  []Policy     `yaml:"policies,omitempty" json:"policies,omitempty"`
	Sites     []Site       `yaml:"sites" json:"sites"`
}

// ServerConfig holds connection limits shared by every listener. Zero values
// select the defaults listed on each field.
type ServerConfig struct {
	// ReadHeaderTimeout defaults to 10s.
	ReadHeaderTimeout Duration `yaml:"read_header_timeout,omitempty" json:"read_header_timeout,omitempty"`
	// ReadTimeout and WriteTimeout are unlimited by default so that uploads,
	// WebSockets and streaming responses work. Bound individual requests
	// with a policy timeout instead.
	ReadTimeout  Duration `yaml:"read_timeout,omitempty" json:"read_timeout,omitempty"`
	WriteTimeout Duration `yaml:"write_timeout,omitempty" json:"write_timeout,omitempty"`
	// IdleTimeout defaults to 2m.
	IdleTimeout Duration `yaml:"idle_timeout,omitempty" json:"idle_timeout,omitempty"`
	// ShutdownTimeout bounds graceful draining and defaults to 10s.
	ShutdownTimeout Duration `yaml:"shutdown_timeout,omitempty" json:"shutdown_timeout,omitempty"`
	// MaxHeaderBytes defaults to 64 KiB.
	MaxHeaderBytes int `yaml:"max_header_bytes,omitempty" json:"max_header_bytes,omitempty"`
}

// TLSConfig lists the certificates served on TLS listeners. Certificates are
// selected by SNI against their DNS names, so sites never reference them.
type TLSConfig struct {
	// MinVersion is "1.2" (default) or "1.3".
	MinVersion   string        `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	Certificates []Certificate `yaml:"certificates,omitempty" json:"certificates,omitempty"`
	// ACME obtains certificates for hosts no listed certificate covers.
	ACME *ACMEConfig `yaml:"acme,omitempty" json:"acme,omitempty"`
}

// ACMEConfig obtains and renews certificates automatically from an ACME CA
// using HTTP-01 challenges, so the CA must reach a plain HTTP listener on
// port 80. Enabling it agrees to the CA's terms of service. Wildcard hosts
// still need a listed certificate.
type ACMEConfig struct {
	// Email is the account contact address. Optional.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
	// Directory defaults to Let's Encrypt production. Use
	// https://acme-staging-v02.api.letsencrypt.org/directory while testing.
	Directory string `yaml:"directory,omitempty" json:"directory,omitempty"`
	// CARoot is a PEM file of roots to trust for the directory, for private
	// CAs such as step-ca.
	CARoot string `yaml:"ca_root,omitempty" json:"ca_root,omitempty"`
	// Storage holds the account and issued certificates. Load defaults it to
	// "acme" beside the configuration file.
	Storage string `yaml:"storage,omitempty" json:"storage,omitempty"`
}

// Certificate is a PEM certificate chain and private key on disk.
type Certificate struct {
	Cert string `yaml:"cert" json:"cert"`
	Key  string `yaml:"key" json:"key"`
}

// Listener binds one TCP address. When a configuration has no listeners,
// Yabber listens on ":80" as "http", plus ":443" as "https" when any
// certificate is available.
type Listener struct {
	Name    string `yaml:"name" json:"name"`
	Address string `yaml:"address" json:"address"`
	TLS     bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
	// TrustedProxies lists addresses or CIDR prefixes whose X-Forwarded-*
	// and X-Request-ID headers are believed.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	Policies       []string `yaml:"policies,omitempty" json:"policies,omitempty"`
}

// Site serves a set of hostnames. A site either lists routes or, as a
// shorthand for a single route on "/", sets one handler directly:
//
//	sites:
//	  - hosts: [example.com]
//	    proxy: http://127.0.0.1:3000
type Site struct {
	// Name labels logs and metrics. It defaults to the first host.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Hosts are exact names, single-label wildcards such as "*.example.com",
	// or "*" for any otherwise unmatched host.
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Listeners restricts the site to the named listeners. By default a site
	// is served on every listener.
	Listeners []string `yaml:"listeners,omitempty" json:"listeners,omitempty"`
	// AllowHTTP serves the site on plain HTTP listeners. By default a site
	// that is also served over TLS redirects plain HTTP requests to HTTPS.
	AllowHTTP bool     `yaml:"allow_http,omitempty" json:"allow_http,omitempty"`
	Policies  []string `yaml:"policies,omitempty" json:"policies,omitempty"`
	Routes    []Route  `yaml:"routes,omitempty" json:"routes,omitempty"`
	Handler   `yaml:",inline"`
}

// Route matches requests by method and path and sends them to one handler.
type Route struct {
	// Name labels logs and metrics. It defaults to "METHOD PATH".
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Method restricts the route to one HTTP method. GET also matches HEAD.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// Path is a net/http.ServeMux pattern path: "/api/" matches the subtree,
	// "/health" matches exactly, and "/{$}" matches only the root. It
	// defaults to "/".
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	Policies []string `yaml:"policies,omitempty" json:"policies,omitempty"`
	Handler  `yaml:",inline"`
}

// Handler holds exactly one request handler.
type Handler struct {
	Proxy    *Proxy    `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	Files    *Files    `yaml:"files,omitempty" json:"files,omitempty"`
	Respond  *Respond  `yaml:"respond,omitempty" json:"respond,omitempty"`
	Redirect *Redirect `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	// Extensions configures handlers registered with WithHandler, keyed by
	// their registered name. In YAML they sit beside the built-in handlers.
	Extensions map[string]any `yaml:"-" json:"-"`
}

func (h Handler) defined() bool {
	return h.Proxy != nil || h.Files != nil || h.Respond != nil || h.Redirect != nil || len(h.Extensions) > 0
}

// Proxy forwards requests to an upstream server. In YAML it may be written as
// the upstream URL alone.
type Proxy struct {
	// Upstream is an http:// or https:// URL, optionally with a base path, or
	// unix:/path/to.sock for a Unix domain socket.
	Upstream string `yaml:"upstream" json:"upstream"`
	// StripPrefix removes a leading path segment prefix before forwarding.
	StripPrefix string `yaml:"strip_prefix,omitempty" json:"strip_prefix,omitempty"`
	// HostHeader overrides the Host sent upstream. By default the client's
	// Host is preserved.
	HostHeader string `yaml:"host_header,omitempty" json:"host_header,omitempty"`
	// DialTimeout defaults to 5s.
	DialTimeout Duration `yaml:"dial_timeout,omitempty" json:"dial_timeout,omitempty"`
	// ResponseHeaderTimeout is unlimited by default.
	ResponseHeaderTimeout Duration `yaml:"response_header_timeout,omitempty" json:"response_header_timeout,omitempty"`
	// MaxConns limits connections per upstream host. Zero means unlimited.
	MaxConns int `yaml:"max_conns,omitempty" json:"max_conns,omitempty"`
	// InsecureSkipVerify accepts any upstream TLS certificate.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
}

// Files serves a directory. Dotfiles other than .well-known are hidden, and
// directories without index.html return 404 unless Browse is set. In YAML it
// may be written as the root directory alone.
type Files struct {
	Root        string `yaml:"root" json:"root"`
	StripPrefix string `yaml:"strip_prefix,omitempty" json:"strip_prefix,omitempty"`
	Browse      bool   `yaml:"browse,omitempty" json:"browse,omitempty"`
}

// Respond writes a fixed response. In YAML it may be written as the body
// alone.
type Respond struct {
	// Status defaults to 200.
	Status  int               `yaml:"status,omitempty" json:"status,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
}

// Redirect sends clients elsewhere. In YAML it may be written as the target
// alone.
type Redirect struct {
	To string `yaml:"to" json:"to"`
	// Status defaults to 308 Permanent Redirect.
	Status int `yaml:"status,omitempty" json:"status,omitempty"`
	// PreservePath appends the request path and query to To.
	PreservePath bool `yaml:"preserve_path,omitempty" json:"preserve_path,omitempty"`
}

// Policy is a reusable bundle of request limits. Policies may be attached to
// listeners, sites and routes; a policy reached from several scopes applies
// once per request, and one named policy shares its state everywhere.
type Policy struct {
	Name        string             `yaml:"name" json:"name"`
	Request     *RequestPolicy     `yaml:"request,omitempty" json:"request,omitempty"`
	RateLimit   *RateLimitPolicy   `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	Concurrency *ConcurrencyPolicy `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
}

type RequestPolicy struct {
	MaxBodyBytes int64 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	// Timeout cancels the request context, which aborts proxied requests
	// with 504. It also bounds WebSocket and streaming lifetimes.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type RateLimitPolicy struct {
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`
	Burst             int     `yaml:"burst" json:"burst"`
	// Key is "client_ip" (default, IPv6 grouped by /64) or "global".
	Key string `yaml:"key,omitempty" json:"key,omitempty"`
	// MaxKeys bounds tracked clients; the least recently seen is evicted.
	// It defaults to 10000.
	MaxKeys int `yaml:"max_keys,omitempty" json:"max_keys,omitempty"`
	// IdleTimeout forgets clients after inactivity and defaults to 10m.
	IdleTimeout Duration `yaml:"idle_timeout,omitempty" json:"idle_timeout,omitempty"`
}

type ConcurrencyPolicy struct {
	Max int `yaml:"max" json:"max"`
}

// Load reads a YAML configuration file. Unknown fields are rejected, and
// relative certificate and file paths are resolved against the file's
// directory.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg.resolvePaths(filepath.Dir(path))
	return cfg, nil
}

// Parse decodes a YAML configuration. Relative paths are left unchanged.
func Parse(data []byte) (Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("configuration is empty")
		}
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) resolvePaths(base string) {
	if acme := c.TLS.ACME; acme != nil {
		if acme.Storage == "" {
			acme.Storage = "acme"
		}
		acme.Storage = resolvePath(base, acme.Storage)
		acme.CARoot = resolvePath(base, acme.CARoot)
	}
	for i := range c.TLS.Certificates {
		certificate := &c.TLS.Certificates[i]
		certificate.Cert = resolvePath(base, certificate.Cert)
		certificate.Key = resolvePath(base, certificate.Key)
	}
	for i := range c.Sites {
		site := &c.Sites[i]
		if site.Files != nil {
			site.Files.Root = resolvePath(base, site.Files.Root)
		}
		for j := range site.Routes {
			if files := site.Routes[j].Files; files != nil {
				files.Root = resolvePath(base, files.Root)
			}
		}
	}
}

func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
