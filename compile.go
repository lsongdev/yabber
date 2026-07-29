package yabber

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	workerruntime "github.com/lsongdev/workers-go/worker"
)

type snapshot struct {
	config       Config
	handlers     map[string]http.Handler
	certificates map[string]*certificateIndex
	listeners    map[string]Listener
	transports   []*http.Transport
	policies     map[string]compiledPolicy
}

type certificateIndex struct {
	exact     map[string]*tls.Certificate
	wildcards []wildcardCertificate
	fallback  *tls.Certificate
}

type wildcardCertificate struct {
	suffix      string
	certificate *tls.Certificate
}

func compile(cfg Config, loader CertificateLoader) (*snapshot, error) {
	return compileWithPrevious(cfg, loader, nil)
}

func compileWithPrevious(cfg Config, loader CertificateLoader, previous *snapshot) (*snapshot, error) {
	if cfg.Version == 0 {
		cfg.Version = ConfigVersion
	}
	if cfg.Version != ConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if err := validateServerConfig(cfg.Server); err != nil {
		return nil, err
	}

	listeners, err := validateListeners(cfg.Listeners)
	if err != nil {
		return nil, err
	}
	var previousPolicies map[string]compiledPolicy
	if previous != nil {
		previousPolicies = previous.policies
	}
	policies, err := compilePolicies(cfg.Policies, previousPolicies)
	if err != nil {
		return nil, err
	}
	certificates, err := certificateDefinitions(cfg.Certificates)
	if err != nil {
		return nil, err
	}
	result := &snapshot{
		config:       cfg,
		handlers:     make(map[string]http.Handler),
		certificates: make(map[string]*certificateIndex),
		listeners:    listeners,
		policies:     policies,
	}

	type hostForListener struct {
		host VirtualHost
	}
	hostsByListener := make(map[string][]hostForListener)
	seenHosts := make(map[string]map[string]string)
	requiredCertificates := make(map[string]struct{})

	for _, host := range cfg.Hosts {
		if !enabled(host.Enabled) {
			continue
		}
		if host.Name == "" {
			return nil, errors.New("host name is required")
		}
		if len(host.Hostnames) == 0 {
			return nil, fmt.Errorf("host %q has no hostnames", host.Name)
		}
		if len(host.Listeners) == 0 {
			return nil, fmt.Errorf("host %q has no listeners", host.Name)
		}

		for _, listenerName := range host.Listeners {
			listener, ok := listeners[listenerName]
			if !ok {
				return nil, fmt.Errorf("host %q references unknown listener %q", host.Name, listenerName)
			}
			if !enabled(listener.Enabled) {
				continue
			}

			if seenHosts[listenerName] == nil {
				seenHosts[listenerName] = make(map[string]string)
			}
			for _, rawHostname := range host.Hostnames {
				hostname := normalizedHostname(rawHostname)
				if err := validateHostname(hostname); err != nil {
					return nil, fmt.Errorf("host %q: %w", host.Name, err)
				}
				if previous, exists := seenHosts[listenerName][hostname]; exists {
					return nil, fmt.Errorf("hostname %q is assigned to hosts %q and %q on listener %q", hostname, previous, host.Name, listenerName)
				}
				seenHosts[listenerName][hostname] = host.Name
			}

			if listener.Protocol == ProtocolHTTPS {
				certificateName := ""
				if host.TLS != nil {
					certificateName = host.TLS.Certificate
				}
				if certificateName == "" && listener.TLS != nil {
					certificateName = listener.TLS.DefaultCertificate
				}
				if certificateName == "" {
					return nil, fmt.Errorf("HTTPS host %q has no certificate", host.Name)
				}
				if _, ok := certificates[certificateName]; !ok {
					return nil, fmt.Errorf("host %q references unknown certificate %q", host.Name, certificateName)
				}
				requiredCertificates[certificateName] = struct{}{}
			}
			hostsByListener[listenerName] = append(hostsByListener[listenerName], hostForListener{host: host})
		}
	}

	for _, listener := range listeners {
		if !enabled(listener.Enabled) || listener.Protocol != ProtocolHTTPS || listener.TLS == nil || listener.TLS.DefaultCertificate == "" {
			continue
		}
		if _, ok := certificates[listener.TLS.DefaultCertificate]; !ok {
			return nil, fmt.Errorf("listener %q references unknown default certificate %q", listener.Name, listener.TLS.DefaultCertificate)
		}
		requiredCertificates[listener.TLS.DefaultCertificate] = struct{}{}
	}

	loadedCertificates := make(map[string]*tls.Certificate, len(requiredCertificates))
	for name := range requiredCertificates {
		cert, err := loader.LoadCertificate(certificates[name])
		if err != nil {
			return nil, fmt.Errorf("load certificate %q: %w", name, err)
		}
		if err := prepareCertificate(cert); err != nil {
			return nil, fmt.Errorf("load certificate %q: %w", name, err)
		}
		loadedCertificates[name] = cert
	}

	for name, listener := range listeners {
		if !enabled(listener.Enabled) {
			continue
		}
		dispatch := &hostDispatch{
			exact: make(map[string]http.Handler),
		}
		var index *certificateIndex
		if listener.Protocol == ProtocolHTTPS {
			index = &certificateIndex{exact: make(map[string]*tls.Certificate)}
			if listener.TLS != nil && listener.TLS.DefaultCertificate != "" {
				index.fallback = loadedCertificates[listener.TLS.DefaultCertificate]
			}
		}

		for _, item := range hostsByListener[name] {
			hostHandler, err := compileHost(item.host, listener, policies, result)
			if err != nil {
				return nil, err
			}

			var hostCertificate *tls.Certificate
			if listener.Protocol == ProtocolHTTPS {
				certificateName := ""
				if item.host.TLS != nil {
					certificateName = item.host.TLS.Certificate
				}
				if certificateName != "" {
					hostCertificate = loadedCertificates[certificateName]
				} else {
					hostCertificate = index.fallback
				}
			}

			for _, rawHostname := range item.host.Hostnames {
				hostname := normalizedHostname(rawHostname)
				dispatch.add(hostname, hostHandler)
				if hostCertificate != nil && hostname != "*" {
					if err := verifyCertificateHostname(hostCertificate, hostname); err != nil {
						return nil, fmt.Errorf("host %q: %w", item.host.Name, err)
					}
					index.add(hostname, hostCertificate)
				}
			}
		}

		dispatch.sort()
		handler, err := applyPolicies(dispatch, listener.Policies, policies, fmt.Sprintf("listener %q", listener.Name))
		if err != nil {
			return nil, err
		}
		resolver, err := newClientIPResolver(listener.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("listener %q: %w", listener.Name, err)
		}
		result.handlers[name] = resolver.middleware(handler)
		if index != nil {
			index.sort()
			result.certificates[name] = index
		}
	}

	return result, nil
}

func validateServerConfig(config ServerConfig) error {
	for name, value := range map[string]time.Duration{
		"shutdown_timeout":    config.ShutdownTimeout,
		"read_timeout":        config.ReadTimeout,
		"read_header_timeout": config.ReadHeaderTimeout,
		"write_timeout":       config.WriteTimeout,
		"idle_timeout":        config.IdleTimeout,
	} {
		if value < 0 {
			return fmt.Errorf("server %s cannot be negative", name)
		}
	}
	if config.MaxHeaderBytes < 0 {
		return errors.New("server max_header_bytes cannot be negative")
	}
	return nil
}

func validateListeners(input []Listener) (map[string]Listener, error) {
	listeners := make(map[string]Listener, len(input))
	addresses := make(map[string]string)
	for _, listener := range input {
		if listener.Name == "" {
			return nil, errors.New("listener name is required")
		}
		if _, exists := listeners[listener.Name]; exists {
			return nil, fmt.Errorf("duplicate listener name %q", listener.Name)
		}
		if listener.Address == "" {
			return nil, fmt.Errorf("listener %q has no address", listener.Name)
		}
		switch listener.Protocol {
		case ProtocolHTTP:
			if listener.TLS != nil {
				return nil, fmt.Errorf("HTTP listener %q cannot have TLS settings", listener.Name)
			}
		case ProtocolHTTPS:
			if listener.TLS == nil {
				listener.TLS = &TLSConfig{}
			}
			if _, err := tlsVersion(listener.TLS.MinVersion); err != nil {
				return nil, fmt.Errorf("listener %q: %w", listener.Name, err)
			}
		default:
			return nil, fmt.Errorf("listener %q has invalid protocol %q", listener.Name, listener.Protocol)
		}
		if enabled(listener.Enabled) {
			if previous, exists := addresses[listener.Address]; exists {
				return nil, fmt.Errorf("listeners %q and %q use the same address %q", previous, listener.Name, listener.Address)
			}
			addresses[listener.Address] = listener.Name
		}
		listeners[listener.Name] = listener
	}
	return listeners, nil
}

func certificateDefinitions(input []Certificate) (map[string]Certificate, error) {
	certificates := make(map[string]Certificate, len(input))
	for _, certificate := range input {
		if certificate.Name == "" {
			return nil, errors.New("certificate name is required")
		}
		if _, exists := certificates[certificate.Name]; exists {
			return nil, fmt.Errorf("duplicate certificate name %q", certificate.Name)
		}
		certificates[certificate.Name] = certificate
	}
	return certificates, nil
}

func prepareCertificate(cert *tls.Certificate) error {
	if cert == nil {
		return errors.New("certificate loader returned nil")
	}
	if len(cert.Certificate) == 0 {
		return errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	cert.Leaf = leaf
	return nil
}

func verifyCertificateHostname(certificate *tls.Certificate, hostname string) error {
	if certificate.Leaf == nil {
		return errors.New("certificate leaf is unavailable")
	}
	if err := certificate.Leaf.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("certificate does not cover hostname %q: %w", hostname, err)
	}
	return nil
}

func compileHost(
	host VirtualHost,
	listener Listener,
	policies map[string]compiledPolicy,
	result *snapshot,
) (handler http.Handler, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("host %q has conflicting routes: %v", host.Name, recovered)
		}
	}()

	mux := http.NewServeMux()
	routeNames := make(map[string]struct{})
	for _, route := range host.Routes {
		if !enabled(route.Enabled) {
			continue
		}
		if route.Name == "" {
			return nil, fmt.Errorf("host %q has a route without a name", host.Name)
		}
		if _, exists := routeNames[route.Name]; exists {
			return nil, fmt.Errorf("host %q has duplicate route name %q", host.Name, route.Name)
		}
		routeNames[route.Name] = struct{}{}

		path := route.Match.Path
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("route %q path must start with /", route.Name)
		}
		method := strings.ToUpper(strings.TrimSpace(route.Match.Method))
		pattern := path
		if method != "" {
			pattern = method + " " + path
		}
		routeHandler, err := compileHandler(route, result)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", route.Name, err)
		}
		routeHandler, err = applyPolicies(routeHandler, route.Policies, policies, fmt.Sprintf("route %q", route.Name))
		if err != nil {
			return nil, err
		}
		routeHandler = withRoute(route.Name, routeHandler)
		mux.Handle(pattern, routeHandler)
	}

	if listener.Protocol == ProtocolHTTP && host.HTTP != nil && host.HTTP.RedirectToHTTPS {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := *r.URL
			target.Scheme = "https"
			target.Host = requestHostname(r.Host)
			if port := httpsPortForHost(host); port != "" && port != "443" {
				target.Host = net.JoinHostPort(target.Host, port)
			}
			http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
		})
	} else {
		handler = mux
	}
	handler, err = applyPolicies(handler, host.Policies, policies, fmt.Sprintf("host %q", host.Name))
	if err != nil {
		return nil, err
	}
	return withHost(host.Name, handler), nil
}

func compileHandler(route Route, result *snapshot) (http.Handler, error) {
	count := 0
	if route.Handle.ReverseProxy != nil {
		count++
	}
	if route.Handle.FileServer != nil {
		count++
	}
	if route.Handle.StaticResponse != nil {
		count++
	}
	if route.Handle.Redirect != nil {
		count++
	}
	if route.Handle.Worker != nil {
		count++
	}
	if count != 1 {
		return nil, errors.New("handle must contain exactly one handler")
	}

	if config := route.Handle.ReverseProxy; config != nil {
		target, err := url.Parse(config.URL)
		if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
			return nil, fmt.Errorf("invalid reverse proxy URL %q", config.URL)
		}
		stripPrefix := config.StripPrefix
		transport, err := reverseProxyTransport(*config)
		if err != nil {
			return nil, err
		}
		result.transports = append(result.transports, transport)
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				if stripPrefix != "" {
					request.Out.URL.Path = strings.TrimPrefix(request.Out.URL.Path, stripPrefix)
					if request.Out.URL.Path == "" {
						request.Out.URL.Path = "/"
					}
				}
				request.SetURL(target)
				request.SetXForwarded()
				if clientIP := ClientIP(request.In); clientIP != "" {
					request.Out.Header.Set("X-Forwarded-For", clientIP)
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				var maxBytesError *http.MaxBytesError
				if errors.As(err, &maxBytesError) {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded) {
					http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
					return
				}
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
		}
		if config.RequestTimeout <= 0 {
			return proxy, nil
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), config.RequestTimeout)
			defer cancel()
			proxy.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	}

	if config := route.Handle.FileServer; config != nil {
		if config.Root == "" {
			return nil, errors.New("file server root is required")
		}
		handler := http.FileServer(http.Dir(config.Root))
		if config.StripPrefix != "" {
			handler = http.StripPrefix(config.StripPrefix, handler)
		}
		return handler, nil
	}

	if config := route.Handle.StaticResponse; config != nil {
		status := config.Status
		if status == 0 {
			status = http.StatusOK
		}
		if status < 200 || status > 599 {
			return nil, fmt.Errorf("invalid response status %d", status)
		}
		headers := make(http.Header, len(config.Headers))
		for name, value := range config.Headers {
			headers.Set(name, value)
		}
		body := config.Body
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for name, values := range headers {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}), nil
	}

	if config := route.Handle.Redirect; config != nil {
		if config.Location == "" {
			return nil, errors.New("redirect location is required")
		}
		status := config.Status
		if status == 0 {
			status = http.StatusPermanentRedirect
		}
		if status < 300 || status > 399 {
			return nil, fmt.Errorf("redirect status must be 3xx, got %d", status)
		}
		return http.RedirectHandler(config.Location, status), nil
	}

	config := route.Handle.Worker
	return NewWorkerHandler(config.Script)
}

func reverseProxyTransport(config ReverseProxy) (*http.Transport, error) {
	for name, value := range map[string]time.Duration{
		"dial_timeout":            config.DialTimeout,
		"tls_handshake_timeout":   config.TLSHandshakeTimeout,
		"response_header_timeout": config.ResponseHeaderTimeout,
		"idle_conn_timeout":       config.IdleConnTimeout,
		"expect_continue_timeout": config.ExpectContinueTimeout,
		"request_timeout":         config.RequestTimeout,
	} {
		if value < 0 {
			return nil, fmt.Errorf("%s cannot be negative", name)
		}
	}
	for name, value := range map[string]int{
		"max_idle_conns":          config.MaxIdleConns,
		"max_idle_conns_per_host": config.MaxIdleConnsPerHost,
		"max_conns_per_host":      config.MaxConnsPerHost,
	} {
		if value < 0 {
			return nil, fmt.Errorf("%s cannot be negative", name)
		}
	}
	if config.MaxResponseHeaderBytes < 0 {
		return nil, errors.New("max_response_header_bytes cannot be negative")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialTimeout := durationOr(config.DialTimeout, 5*time.Second)
	transport.DialContext = (&net.Dialer{
		Timeout: dialTimeout, KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = durationOr(config.TLSHandshakeTimeout, 10*time.Second)
	transport.ResponseHeaderTimeout = durationOr(config.ResponseHeaderTimeout, 30*time.Second)
	transport.IdleConnTimeout = durationOr(config.IdleConnTimeout, 90*time.Second)
	transport.ExpectContinueTimeout = durationOr(config.ExpectContinueTimeout, time.Second)
	transport.MaxIdleConns = intOr(config.MaxIdleConns, 100)
	transport.MaxIdleConnsPerHost = intOr(config.MaxIdleConnsPerHost, 10)
	transport.MaxConnsPerHost = config.MaxConnsPerHost
	transport.MaxResponseHeaderBytes = config.MaxResponseHeaderBytes
	return transport, nil
}

func intOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// NewWorkerHandler creates the same Worker runtime used by configured routes.
func NewWorkerHandler(script string) (http.Handler, error) {
	if strings.TrimSpace(script) == "" {
		return nil, errors.New("worker script is required")
	}
	return workerruntime.New(script).Handler(), nil
}

func validateHostname(hostname string) error {
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if hostname == "*" {
		return nil
	}
	if strings.ContainsAny(hostname, "/ \t\r\n") {
		return fmt.Errorf("invalid hostname %q", hostname)
	}
	if strings.HasPrefix(hostname, "*.") {
		if strings.Count(hostname, "*") != 1 || len(hostname) <= 2 {
			return fmt.Errorf("invalid wildcard hostname %q", hostname)
		}
		return nil
	}
	if strings.Contains(hostname, "*") {
		return fmt.Errorf("invalid wildcard hostname %q", hostname)
	}
	return nil
}

func tlsVersion(value string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "TLS1.2", "TLS12":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLS13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS minimum version %q", value)
	}
}

func runtimeTopologyEqual(a, b *snapshot) bool {
	if a.config.Server.ReadTimeout != b.config.Server.ReadTimeout ||
		durationOr(a.config.Server.ReadHeaderTimeout, 5*time.Second) != durationOr(b.config.Server.ReadHeaderTimeout, 5*time.Second) ||
		a.config.Server.WriteTimeout != b.config.Server.WriteTimeout ||
		durationOr(a.config.Server.IdleTimeout, 60*time.Second) != durationOr(b.config.Server.IdleTimeout, 60*time.Second) ||
		intOr(a.config.Server.MaxHeaderBytes, 64<<10) != intOr(b.config.Server.MaxHeaderBytes, 64<<10) {
		return false
	}
	if len(a.listeners) != len(b.listeners) {
		return false
	}
	for name, left := range a.listeners {
		right, ok := b.listeners[name]
		if !ok ||
			left.Address != right.Address ||
			left.Protocol != right.Protocol ||
			enabled(left.Enabled) != enabled(right.Enabled) ||
			tlsMinimum(left) != tlsMinimum(right) {
			return false
		}
	}
	return true
}

func tlsMinimum(listener Listener) uint16 {
	if listener.Protocol != ProtocolHTTPS {
		return 0
	}
	value := ""
	if listener.TLS != nil {
		value = listener.TLS.MinVersion
	}
	version, _ := tlsVersion(value)
	return version
}

func httpsPortForHost(VirtualHost) string {
	// Listener references are names rather than addresses. Redirects therefore
	// use the standard HTTPS port; deployments on another port can use an
	// explicit redirect route.
	return "443"
}

func requestHostname(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return normalizedHostname(host)
	}
	return normalizedHostname(hostport)
}

type hostDispatch struct {
	exact     map[string]http.Handler
	wildcards []wildcardHandler
	fallback  http.Handler
}

type wildcardHandler struct {
	suffix  string
	handler http.Handler
}

func (d *hostDispatch) add(hostname string, handler http.Handler) {
	switch {
	case hostname == "*":
		d.fallback = handler
	case strings.HasPrefix(hostname, "*."):
		d.wildcards = append(d.wildcards, wildcardHandler{
			suffix:  strings.TrimPrefix(hostname, "*."),
			handler: handler,
		})
	default:
		d.exact[hostname] = handler
	}
}

func (d *hostDispatch) sort() {
	sort.Slice(d.wildcards, func(i, j int) bool {
		return len(d.wildcards[i].suffix) > len(d.wildcards[j].suffix)
	})
}

func (d *hostDispatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hostname := requestHostname(r.Host)
	if handler := d.exact[hostname]; handler != nil {
		handler.ServeHTTP(w, r)
		return
	}
	for _, wildcard := range d.wildcards {
		if wildcardMatches(hostname, wildcard.suffix) {
			wildcard.handler.ServeHTTP(w, r)
			return
		}
	}
	if d.fallback != nil {
		d.fallback.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func wildcardMatches(hostname, suffix string) bool {
	prefix, ok := strings.CutSuffix(hostname, "."+suffix)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

func (i *certificateIndex) add(hostname string, certificate *tls.Certificate) {
	if strings.HasPrefix(hostname, "*.") {
		i.wildcards = append(i.wildcards, wildcardCertificate{
			suffix:      strings.TrimPrefix(hostname, "*."),
			certificate: certificate,
		})
		return
	}
	i.exact[hostname] = certificate
}

func (i *certificateIndex) sort() {
	sort.Slice(i.wildcards, func(a, b int) bool {
		return len(i.wildcards[a].suffix) > len(i.wildcards[b].suffix)
	})
}

func (i *certificateIndex) get(serverName string) (*tls.Certificate, error) {
	hostname := normalizedHostname(serverName)
	if certificate := i.exact[hostname]; certificate != nil {
		return certificate, nil
	}
	for _, wildcard := range i.wildcards {
		if wildcardMatches(hostname, wildcard.suffix) {
			return wildcard.certificate, nil
		}
	}
	if i.fallback != nil {
		return i.fallback, nil
	}
	return nil, fmt.Errorf("no certificate for server name %q", serverName)
}
