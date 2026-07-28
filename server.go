package yabber

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrAlreadyRunning  = errors.New("yabber is already running")
	ErrRestartRequired = errors.New("listener changes require restart")
)

type Server struct {
	mu      sync.Mutex
	current atomic.Pointer[snapshot]
	running map[string]*runningListener
	started bool
	errors  chan error
	loader  CertificateLoader
	http01  HTTP01Store
}

type runningListener struct {
	server   *http.Server
	listener net.Listener
}

type ListenerError struct {
	Listener string
	Err      error
}

func (e *ListenerError) Error() string {
	return fmt.Sprintf("listener %q: %v", e.Listener, e.Err)
}

func (e *ListenerError) Unwrap() error {
	return e.Err
}

type Option func(*serverOptions)

type serverOptions struct {
	certificateLoader CertificateLoader
	http01Store       HTTP01Store
}

// HTTP01Store provides temporary ACME HTTP-01 key authorizations.
type HTTP01Store interface {
	GetHTTP01Token(host, token string) (keyAuthorization string, ok bool)
}

// WithCertificateLoader replaces the default PEM file loader.
func WithCertificateLoader(loader CertificateLoader) Option {
	return func(options *serverOptions) {
		options.certificateLoader = loader
	}
}

// WithHTTP01Store installs an ACME challenge responder ahead of redirects and
// user routes on every HTTP listener.
func WithHTTP01Store(store HTTP01Store) Option {
	return func(options *serverOptions) {
		options.http01Store = store
	}
}

func New(config Config, options ...Option) (*Server, error) {
	settings := serverOptions{certificateLoader: FileCertificateLoader{}}
	for _, option := range options {
		option(&settings)
	}
	if settings.certificateLoader == nil {
		return nil, errors.New("certificate loader is nil")
	}
	compiled, err := compile(config, settings.certificateLoader)
	if err != nil {
		return nil, err
	}
	server := &Server{
		running: make(map[string]*runningListener),
		errors:  make(chan error, 16),
		loader:  settings.certificateLoader,
		http01:  settings.http01Store,
	}
	server.current.Store(compiled)
	return server, nil
}

// Handler returns a dynamic handler for one configured listener. The returned
// handler follows future successful Apply calls.
func (s *Server) Handler(listenerName string) (http.Handler, error) {
	if _, ok := s.current.Load().listeners[listenerName]; !ok {
		return nil, fmt.Errorf("unknown listener %q", listenerName)
	}
	return &listenerHandler{server: s, name: listenerName}, nil
}

// Apply validates and atomically installs routes, hosts, and certificates.
// Listener address, protocol, enabled state, and minimum TLS version cannot be
// changed while running; use Restart for those changes.
func (s *Server) Apply(config Config) error {
	compiled, err := compile(config, s.loader)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started && !runtimeTopologyEqual(s.current.Load(), compiled) {
		return ErrRestartRequired
	}
	s.current.Store(compiled)
	return nil
}

// Start binds every enabled listener. It returns only after all sockets have
// been bound successfully.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Server) startLocked() error {
	if s.started {
		return ErrAlreadyRunning
	}

	snapshot := s.current.Load()
	started := make(map[string]*runningListener)
	for name, listenerConfig := range snapshot.listeners {
		if !enabled(listenerConfig.Enabled) {
			continue
		}

		rawListener, err := net.Listen("tcp", listenerConfig.Address)
		if err != nil {
			closeRunning(started)
			return &ListenerError{Listener: name, Err: err}
		}

		httpServer := &http.Server{
			Handler:           &listenerHandler{server: s, name: name},
			ReadHeaderTimeout: durationOr(snapshot.config.Server.ReadHeaderTimeout, 5*time.Second),
			IdleTimeout:       durationOr(snapshot.config.Server.IdleTimeout, 60*time.Second),
		}
		serveListener := rawListener
		if listenerConfig.Protocol == ProtocolHTTPS {
			minVersion, _ := tlsVersion(listenerConfig.TLS.MinVersion)
			tlsConfig := &tls.Config{
				MinVersion: minVersion,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					current := s.current.Load()
					index := current.certificates[name]
					if index == nil {
						return nil, fmt.Errorf("listener %q has no certificate index", name)
					}
					return index.get(hello.ServerName)
				},
			}
			serveListener = tls.NewListener(rawListener, tlsConfig)
		}
		started[name] = &runningListener{
			server:   httpServer,
			listener: rawListener,
		}

		go func(name string, server *http.Server, listener net.Listener) {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case s.errors <- &ListenerError{Listener: name, Err: err}:
				default:
				}
			}
		}(name, httpServer, serveListener)
	}

	s.running = started
	s.started = true
	return nil
}

// Shutdown gracefully stops every listener.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdownLocked(ctx)
}

func (s *Server) shutdownLocked(ctx context.Context) error {
	if !s.started {
		return nil
	}
	running := s.running
	s.running = make(map[string]*runningListener)
	s.started = false

	var errs []error
	for name, listener := range running {
		if err := listener.server.Shutdown(ctx); err != nil {
			_ = listener.listener.Close()
			errs = append(errs, &ListenerError{Listener: name, Err: err})
		}
	}
	return errors.Join(errs...)
}

// Restart validates config before stopping the current listeners. If the new
// listeners cannot start, Yabber makes a best-effort attempt to restore the
// previous configuration.
func (s *Server) Restart(ctx context.Context, config Config) error {
	compiled, err := compile(config, s.loader)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		s.current.Store(compiled)
		return nil
	}

	previous := s.current.Load()
	if err := s.shutdownLocked(ctx); err != nil {
		return err
	}
	s.current.Store(compiled)
	if err := s.startLocked(); err != nil {
		s.current.Store(previous)
		if restoreErr := s.startLocked(); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous configuration: %w", restoreErr))
		}
		return err
	}
	return nil
}

// Errors reports unexpected listener failures. The channel remains open for
// the lifetime of the Server.
func (s *Server) Errors() <-chan error {
	return s.errors
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// Addresses returns the actual bound address of each running listener.
func (s *Server) Addresses() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	addresses := make(map[string]string, len(s.running))
	for name, listener := range s.running {
		addresses[name] = listener.listener.Addr().String()
	}
	return addresses
}

// Close stops all listeners using the configured shutdown timeout.
func (s *Server) Close() error {
	timeout := durationOr(s.current.Load().config.Server.ShutdownTimeout, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.Shutdown(ctx)
}

type listenerHandler struct {
	server *Server
	name   string
}

func (h *listenerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if h.server.http01 != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.HasPrefix(r.URL.Path, prefix) {
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if token != "" && !strings.Contains(token, "/") {
			host := r.Host
			if name, _, err := net.SplitHostPort(host); err == nil {
				host = name
			}
			if keyAuthorization, ok := h.server.http01.GetHTTP01Token(strings.ToLower(strings.TrimSuffix(host, ".")), token); ok {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Cache-Control", "no-store")
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(keyAuthorization))
				}
				return
			}
		}
	}
	handler := h.server.current.Load().handlers[h.name]
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func closeRunning(running map[string]*runningListener) {
	for _, listener := range running {
		_ = listener.listener.Close()
	}
}
