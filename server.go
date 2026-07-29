package yabber

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	mu               sync.Mutex
	current          atomic.Pointer[snapshot]
	running          map[string]*runningListener
	listenerFailures map[string]error
	started          bool
	errors           chan error
	loader           CertificateLoader
	http01           HTTP01Store
	metrics          *Metrics
	observers        []Observer
	middleware       []Middleware
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
	observers         []Observer
	middleware        []Middleware
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

// WithObserver registers a completed-request observer.
func WithObserver(observer Observer) Option {
	return func(options *serverOptions) {
		if observer != nil {
			options.observers = append(options.observers, observer)
		}
	}
}

// WithAccessLog writes structured JSON access records to writer.
func WithAccessLog(writer io.Writer) Option {
	return WithObserver(NewAccessLog(writer))
}

// WithMiddleware installs application middleware on every non-ACME request.
func WithMiddleware(middleware ...Middleware) Option {
	return func(options *serverOptions) {
		options.middleware = append(options.middleware, middleware...)
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
		running:          make(map[string]*runningListener),
		listenerFailures: make(map[string]error),
		errors:           make(chan error, 16),
		loader:           settings.certificateLoader,
		http01:           settings.http01Store,
		metrics:          newMetrics(),
		observers:        settings.observers,
		middleware:       settings.middleware,
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
	compiled, err := compileWithPrevious(config, s.loader, s.current.Load())
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started && !runtimeTopologyEqual(s.current.Load(), compiled) {
		return ErrRestartRequired
	}
	previous := s.current.Load()
	s.current.Store(compiled)
	for _, transport := range previous.transports {
		transport.CloseIdleConnections()
	}
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
	s.listenerFailures = make(map[string]error)
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
			ReadTimeout:       snapshot.config.Server.ReadTimeout,
			ReadHeaderTimeout: durationOr(snapshot.config.Server.ReadHeaderTimeout, 5*time.Second),
			WriteTimeout:      snapshot.config.Server.WriteTimeout,
			IdleTimeout:       durationOr(snapshot.config.Server.IdleTimeout, 60*time.Second),
			MaxHeaderBytes:    intOr(snapshot.config.Server.MaxHeaderBytes, 64<<10),
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
				listenerError := &ListenerError{Listener: name, Err: err}
				s.mu.Lock()
				s.listenerFailures[name] = listenerError
				s.mu.Unlock()
				select {
				case s.errors <- listenerError:
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
	for _, transport := range s.current.Load().transports {
		transport.CloseIdleConnections()
	}
	return errors.Join(errs...)
}

// Restart validates config before stopping the current listeners. If the new
// listeners cannot start, Yabber makes a best-effort attempt to restore the
// previous configuration.
func (s *Server) Restart(ctx context.Context, config Config) error {
	compiled, err := compileWithPrevious(config, s.loader, s.current.Load())
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

// Healthy reports whether the server is started and every listener is healthy.
func (s *Server) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || len(s.listenerFailures) != 0 {
		return false
	}
	enabledListeners := 0
	for name, config := range s.current.Load().listeners {
		if !enabled(config.Enabled) {
			continue
		}
		enabledListeners++
		if s.running[name] == nil {
			return false
		}
	}
	return enabledListeners > 0
}

type ListenerStatus struct {
	Address string
	Enabled bool
	Running bool
	Error   string
}

// ListenerStatuses returns current runtime state for configured listeners.
func (s *Server) ListenerStatuses() map[string]ListenerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.current.Load()
	statuses := make(map[string]ListenerStatus, len(snapshot.listeners))
	for name, config := range snapshot.listeners {
		status := ListenerStatus{Address: config.Address, Enabled: enabled(config.Enabled)}
		if running := s.running[name]; running != nil && s.listenerFailures[name] == nil {
			status.Address = running.listener.Addr().String()
			status.Running = true
		}
		if err := s.listenerFailures[name]; err != nil {
			status.Error = err.Error()
		}
		statuses[name] = status
	}
	return statuses
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

// Metrics returns a point-in-time request metrics snapshot.
func (s *Server) Metrics() MetricsSnapshot {
	return s.metrics.Snapshot()
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
	started := time.Now()
	clientIP := ""
	if address := remoteAddress(r.RemoteAddr); address.IsValid() {
		clientIP = address.String()
	}
	state := &requestState{
		RequestID: requestID(r),
		Listener:  h.name,
		ClientIP:  clientIP,
		Applied:   make(map[string]struct{}),
	}
	r.Header.Set("X-Request-ID", state.RequestID)
	w.Header().Set("X-Request-ID", state.RequestID)
	r = withRequestState(r, state)
	tracker := &responseTracker{ResponseWriter: w}
	h.server.metrics.begin()
	defer func() {
		recovered := recover()
		if recovered != nil && tracker.status == 0 {
			http.Error(tracker, "internal server error", http.StatusInternalServerError)
		}
		h.server.metrics.end()
		status := tracker.status
		if status == 0 {
			status = http.StatusOK
		}
		record := RequestRecord{
			Time: started.UTC(), Duration: time.Since(started),
			RequestID: state.RequestID, Listener: state.Listener,
			Host: state.Host, Route: state.Route, ClientIP: state.ClientIP,
			Method: r.Method, Path: r.URL.Path, Status: status,
			Bytes: tracker.bytes, RejectedBy: state.RejectedBy,
			Panicked: recovered != nil,
		}
		h.server.metrics.ObserveRequest(record)
		for _, observer := range h.server.observers {
			func() {
				defer func() { _ = recover() }()
				observer.ObserveRequest(record)
			}()
		}
	}()

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
				state.Route = "acme-http-01"
				tracker.Header().Set("Content-Type", "text/plain")
				tracker.Header().Set("Cache-Control", "no-store")
				if r.Method != http.MethodHead {
					_, _ = tracker.Write([]byte(keyAuthorization))
				}
				return
			}
		}
	}
	handler := h.server.current.Load().handlers[h.name]
	if handler == nil {
		http.NotFound(tracker, r)
		return
	}
	chain(handler, h.server.middleware...).ServeHTTP(tracker, r)
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
