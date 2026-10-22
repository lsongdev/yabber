package yabber

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// snapshot is an immutable, compiled configuration. Server swaps snapshots
// atomically, so requests always see one consistent configuration.
type snapshot struct {
	config     Config
	server     ServerConfig // config.Server with defaults applied
	listeners  map[string]*listenerRuntime
	certs      *certificateStore
	minTLS     uint16
	policies   map[string]*compiledPolicy
	transports map[transportKey]*http.Transport
	// tlsHosts are all hosts served on TLS listeners. acme manages
	// certificates for managedHosts, those no current listed certificate
	// covers; see managedHosts.
	tlsHosts     []string
	acme         *acmeManager
	managedHosts []string
}

// listenerSpec is everything that requires rebinding a listener when it
// changes. Comparable, so Apply can diff listeners with ==.
type listenerSpec struct {
	address string
	tls     bool
	minTLS  uint16
	server  ServerConfig
}

type listenerRuntime struct {
	spec     listenerSpec
	handler  http.Handler
	clientIP *clientIPResolver
}

type siteEntry struct {
	name    string
	handler http.Handler
}

type compiler struct {
	opts     *options
	prev     *snapshot
	snap     *snapshot
	tlsHosts map[string]bool
}

// compile validates cfg and builds a snapshot. State that should outlive a
// reload, such as rate-limit buckets and upstream connection pools, is taken
// from prev when its definition is unchanged.
func compile(cfg Config, opts *options, prev *snapshot) (*snapshot, error) {
	cfg = cfg.Clone()
	if cfg.Version != 0 && cfg.Version != ConfigVersion {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	server, err := cfg.Server.withDefaults()
	if err != nil {
		return nil, err
	}
	minTLS, err := tlsVersion(cfg.TLS.MinVersion)
	if err != nil {
		return nil, err
	}
	certs, err := loadCertificates(cfg.TLS.Certificates, opts.certificates, opts.logger)
	if err != nil {
		return nil, err
	}
	var prevPolicies map[string]*compiledPolicy
	if prev != nil {
		prevPolicies = prev.policies
	}
	policies, err := compilePolicies(cfg.Policies, prevPolicies)
	if err != nil {
		return nil, err
	}
	manager, err := acmeManagerFor(cfg.TLS.ACME, opts, prev)
	if err != nil {
		return nil, err
	}
	c := &compiler{opts: opts, prev: prev, tlsHosts: make(map[string]bool), snap: &snapshot{
		config:     cfg,
		server:     server,
		listeners:  make(map[string]*listenerRuntime),
		certs:      certs,
		minTLS:     minTLS,
		policies:   policies,
		transports: make(map[transportKey]*http.Transport),
		acme:       manager,
	}}

	listeners := cfg.Listeners
	if len(listeners) == 0 {
		listeners = defaultListeners(!certs.empty() || manager != nil)
	}
	byName, err := c.listeners(listeners)
	if err != nil {
		return nil, err
	}
	tables := make(map[string]*hostTable[siteEntry], len(listeners))
	for _, listener := range listeners {
		tables[listener.Name] = newHostTable[siteEntry]()
	}
	siteIDs := make(map[string]bool, len(cfg.Sites))
	for i, site := range cfg.Sites {
		id := site.ID()
		if id != "" && siteIDs[id] {
			return nil, fmt.Errorf("duplicate site %q; give one of them a distinct name", id)
		}
		siteIDs[id] = true
		if err := c.site(site, listeners, byName, tables); err != nil {
			label := id
			if label == "" {
				label = fmt.Sprintf("#%d", i+1)
			}
			return nil, fmt.Errorf("site %q: %w", label, err)
		}
	}
	c.snap.tlsHosts = slices.Sorted(maps.Keys(c.tlsHosts))
	c.snap.managedHosts = managedHosts(c.snap.tlsHosts, certs, manager)
	if len(c.snap.managedHosts) > 0 && !slices.ContainsFunc(listeners, func(l Listener) bool { return !l.TLS }) {
		return nil, errors.New("tls.acme needs a plain HTTP listener to answer HTTP-01 challenges")
	}
	for _, listener := range listeners {
		handler, err := applyPolicies(hostDispatcher{tables[listener.Name]}, listener.Policies, policies)
		if err != nil {
			return nil, fmt.Errorf("listener %q: %w", listener.Name, err)
		}
		runtime := c.snap.listeners[listener.Name]
		runtime.handler = Chain(handler, opts.middleware...)
	}
	return c.snap, nil
}

func defaultListeners(withTLS bool) []Listener {
	listeners := []Listener{{Name: "http", Address: ":80"}}
	if withTLS {
		listeners = append(listeners, Listener{Name: "https", Address: ":443", TLS: true})
	}
	return listeners
}

func (s ServerConfig) withDefaults() (ServerConfig, error) {
	for name, value := range map[string]Duration{
		"read_header_timeout": s.ReadHeaderTimeout,
		"read_timeout":        s.ReadTimeout,
		"write_timeout":       s.WriteTimeout,
		"idle_timeout":        s.IdleTimeout,
		"shutdown_timeout":    s.ShutdownTimeout,
	} {
		if value < 0 {
			return s, fmt.Errorf("server %s cannot be negative", name)
		}
	}
	if s.MaxHeaderBytes < 0 {
		return s, errors.New("server max_header_bytes cannot be negative")
	}
	s.ReadHeaderTimeout = Duration(durationOr(s.ReadHeaderTimeout, 10*time.Second))
	s.IdleTimeout = Duration(durationOr(s.IdleTimeout, 2*time.Minute))
	s.ShutdownTimeout = Duration(durationOr(s.ShutdownTimeout, 10*time.Second))
	if s.MaxHeaderBytes == 0 {
		s.MaxHeaderBytes = 64 << 10
	}
	return s, nil
}

func (c *compiler) listeners(listeners []Listener) (map[string]Listener, error) {
	byName := make(map[string]Listener, len(listeners))
	addresses := make(map[string]string, len(listeners))
	for _, listener := range listeners {
		if listener.Name == "" {
			return nil, errors.New("listener name is required")
		}
		if _, exists := byName[listener.Name]; exists {
			return nil, fmt.Errorf("duplicate listener name %q", listener.Name)
		}
		if listener.Address == "" {
			return nil, fmt.Errorf("listener %q has no address", listener.Name)
		}
		if other, exists := addresses[listener.Address]; exists && !strings.HasSuffix(listener.Address, ":0") {
			return nil, fmt.Errorf("listeners %q and %q use the same address %q", other, listener.Name, listener.Address)
		}
		resolver, err := newClientIPResolver(listener.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("listener %q: %w", listener.Name, err)
		}
		byName[listener.Name] = listener
		addresses[listener.Address] = listener.Name
		spec := listenerSpec{address: listener.Address, tls: listener.TLS, server: c.snap.server}
		if listener.TLS {
			spec.minTLS = c.snap.minTLS
		}
		c.snap.listeners[listener.Name] = &listenerRuntime{spec: spec, clientIP: resolver}
	}
	return byName, nil
}

func (c *compiler) site(site Site, listeners []Listener, byName map[string]Listener, tables map[string]*hostTable[siteEntry]) error {
	if len(site.Hosts) == 0 {
		return errors.New("at least one host is required")
	}
	hosts := make([]string, len(site.Hosts))
	for i, host := range site.Hosts {
		hosts[i] = normalizeHost(host)
		if err := validateHostPattern(hosts[i]); err != nil {
			return err
		}
	}
	name := site.ID()
	if err := c.checkExtensions(site.Extensions); err != nil {
		return err
	}

	routes := site.Routes
	if site.Handler.defined() {
		if len(routes) > 0 {
			return errors.New("set either routes or a single handler, not both")
		}
		routes = []Route{{Handler: site.Handler}}
	}
	if len(routes) == 0 {
		return errors.New("no routes")
	}
	mux := http.NewServeMux()
	routeNames := make(map[string]bool, len(routes))
	for _, route := range routes {
		pattern, routeName, handler, err := c.route(route)
		if err != nil {
			return err
		}
		if routeNames[routeName] {
			return fmt.Errorf("duplicate route name %q", routeName)
		}
		routeNames[routeName] = true
		if err := register(mux, pattern, handler); err != nil {
			return fmt.Errorf("route %q: %w", routeName, err)
		}
	}
	handler, err := applyPolicies(mux, site.Policies, c.snap.policies)
	if err != nil {
		return err
	}
	handler = withSite(name, handler)

	served := site.Listeners
	if len(served) == 0 {
		for _, listener := range listeners {
			served = append(served, listener.Name)
		}
	}
	httpsPort := ""
	for _, listenerName := range served {
		listener, ok := byName[listenerName]
		if !ok {
			return fmt.Errorf("unknown listener %q", listenerName)
		}
		if listener.TLS && httpsPort == "" {
			_, httpsPort, _ = net.SplitHostPort(listener.Address)
		}
	}
	for _, listenerName := range served {
		listenerHandler := handler
		if byName[listenerName].TLS {
			for _, host := range hosts {
				if err := c.requireCertificate(host, listenerName); err != nil {
					return err
				}
			}
		} else if httpsPort != "" && !site.AllowHTTP {
			listenerHandler = withSite(name, withRoute("https-redirect", httpsRedirect(httpsPort)))
		}
		table := tables[listenerName]
		for _, host := range hosts {
			if other, exists := table.get(host); exists {
				return fmt.Errorf("host %q on listener %q is already served by site %q", host, listenerName, other.name)
			}
			table.set(host, siteEntry{name: name, handler: listenerHandler})
		}
	}
	return nil
}

// requireCertificate checks that a TLS host can be served: by a current
// listed certificate, by ACME, or at worst by a stale listed certificate.
func (c *compiler) requireCertificate(host, listener string) error {
	c.tlsHosts[host] = true
	certs := c.snap.certs
	switch {
	case covers(certs.current, host), c.snap.acme != nil && acmeEligible(host), covers(certs.stale, host):
		return nil
	case c.snap.acme == nil:
		return fmt.Errorf("no certificate covers %q on TLS listener %q; add one or enable tls.acme", host, listener)
	default:
		return fmt.Errorf("no certificate covers %q on TLS listener %q, and ACME HTTP-01 cannot issue wildcard or IP certificates", host, listener)
	}
}

// managedHosts returns the TLS hosts ACME must manage: those it can issue
// for that no current listed certificate covers.
func managedHosts(tlsHosts []string, certs *certificateStore, manager *acmeManager) []string {
	if manager == nil {
		return nil
	}
	var managed []string
	for _, host := range tlsHosts {
		if acmeEligible(host) && !covers(certs.current, host) {
			managed = append(managed, host)
		}
	}
	return managed
}

// acmeManagerFor reuses the previous manager when its configuration is
// unchanged, keeping its certificates, account and retry state.
func acmeManagerFor(config *ACMEConfig, opts *options, prev *snapshot) (*acmeManager, error) {
	if config == nil {
		return nil, nil
	}
	want := *config
	if want.Directory == "" {
		want.Directory = letsEncryptDirectory
	}
	if prev != nil && prev.acme != nil && prev.acme.config == want {
		return prev.acme, nil
	}
	return newACMEManager(want, opts.dataDir, opts.logger)
}

func (c *compiler) route(route Route) (pattern, name string, handler http.Handler, err error) {
	path := route.Path
	if path == "" {
		path = "/"
	}
	pattern = path
	if method := strings.ToUpper(strings.TrimSpace(route.Method)); method != "" {
		pattern = method + " " + path
	}
	name = route.Name
	if name == "" {
		name = pattern
	}
	if !strings.HasPrefix(path, "/") {
		return "", "", nil, fmt.Errorf("route %q: path must start with /", name)
	}
	if err := c.checkExtensions(route.Extensions); err != nil {
		return "", "", nil, fmt.Errorf("route %q: %w", name, err)
	}
	handler, err = c.handler(route.Handler)
	if err == nil {
		handler, err = applyPolicies(handler, route.Policies, c.snap.policies)
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("route %q: %w", name, err)
	}
	return pattern, name, withRoute(name, handler), nil
}

// register adds a ServeMux pattern, converting its panics on invalid or
// conflicting patterns into errors.
func register(mux *http.ServeMux, pattern string, handler http.Handler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%v", recovered)
		}
	}()
	mux.Handle(pattern, handler)
	return nil
}

func (c *compiler) transport(key transportKey) *http.Transport {
	transport, ok := c.snap.transports[key]
	if !ok && c.prev != nil {
		transport, ok = c.prev.transports[key]
	}
	if !ok {
		transport = newTransport(key)
	}
	c.snap.transports[key] = transport
	return transport
}

type hostDispatcher struct {
	sites *hostTable[siteEntry]
}

func (d hostDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	site, ok := d.sites.match(requestHost(r.Host))
	if !ok {
		http.NotFound(w, r)
		return
	}
	site.handler.ServeHTTP(w, r)
}

func httpsRedirect(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := requestHost(r.Host)
		if port != "443" {
			host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		target := *r.URL
		target.Scheme, target.Host = "https", host
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
}

func durationOr(value Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return time.Duration(value)
	}
	return fallback
}
