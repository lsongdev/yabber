package yabber

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ErrAlreadyRunning is returned by Start on a running server.
var ErrAlreadyRunning = errors.New("yabber: server is already running")

// Server is a gateway. All methods are safe for concurrent use.
//
// The zero value is not usable; create servers with New.
type Server struct {
	opts    options
	current atomic.Pointer[snapshot]
	metrics *metrics

	mu       sync.Mutex // serializes lifecycle and configuration changes
	running  map[string]*runningListener
	started  bool
	draining sync.WaitGroup // replaced listeners finishing in-flight requests
	issuer   *acmeIssuer    // the ACME loop, while started
}

type acmeIssuer struct {
	manager *acmeManager
	cancel  context.CancelFunc
	done    chan struct{}
}

type runningListener struct {
	spec    listenerSpec
	server  *http.Server
	ln      net.Listener
	closing atomic.Bool
	failure atomic.Pointer[error]
}

// ListenerError reports a listener that failed to bind or serve.
type ListenerError struct {
	Listener string
	Err      error
}

func (e *ListenerError) Error() string { return fmt.Sprintf("listener %q: %v", e.Listener, e.Err) }

func (e *ListenerError) Unwrap() error { return e.Err }

// Option configures a Server.
type Option func(*options)

type options struct {
	logger       *slog.Logger
	certificates CertificateSource
	http01       HTTP01Store
	observers    []Observer
	middleware   []Middleware
	handlers     map[string]HandlerFactory
}

// WithLogger sets the logger for warnings and errors. The default discards
// everything.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// WithCertificateSource adds certificates from outside the configuration.
func WithCertificateSource(source CertificateSource) Option {
	return func(o *options) { o.certificates = source }
}

// WithObserver receives a record for every completed request.
func WithObserver(observer Observer) Option {
	return func(o *options) { o.observers = append(o.observers, observer) }
}

// WithAccessLog writes JSON access records to writer.
func WithAccessLog(writer io.Writer) Option {
	return WithObserver(NewAccessLog(writer))
}

// WithMiddleware wraps every routed request, outside all policies.
func WithMiddleware(middleware ...Middleware) Option {
	return func(o *options) { o.middleware = append(o.middleware, middleware...) }
}

// WithHandler registers an extension handler. Sites and routes then accept
// name as a handler key whose value is passed to factory.
func WithHandler(name string, factory HandlerFactory) Option {
	return func(o *options) {
		if o.handlers == nil {
			o.handlers = make(map[string]HandlerFactory)
		}
		o.handlers[name] = factory
	}
}

func newOptions(list []Option) options {
	var o options
	for _, option := range list {
		option(&o)
	}
	if o.logger == nil {
		o.logger = slog.New(slog.DiscardHandler)
	}
	return o
}

// New compiles config into a stopped server.
func New(config Config, options ...Option) (*Server, error) {
	s := &Server{opts: newOptions(options), metrics: newMetrics()}
	compiled, err := compile(config, &s.opts, nil)
	if err != nil {
		return nil, err
	}
	s.commitLocked(nil, compiled)
	return s, nil
}

// Validate reports whether config compiles with the given options. It reads
// certificates and file roots but binds nothing.
func Validate(config Config, options ...Option) error {
	o := newOptions(options)
	_, err := compile(config, &o, nil)
	return err
}

// Config returns a copy of the active configuration.
func (s *Server) Config() Config {
	return s.current.Load().config.Clone()
}

// Handler returns the handler for one listener, for serving through an
// http.Server the caller owns. It follows later configuration changes.
func (s *Server) Handler(listener string) (http.Handler, error) {
	if s.current.Load().listeners[listener] == nil {
		return nil, fmt.Errorf("unknown listener %q", listener)
	}
	return &listenerHandler{server: s, name: listener}, nil
}

// Apply validates config and switches to it atomically. On a running server,
// listeners whose address, TLS mode or server limits changed are rebound and
// the old ones drain in the background; all other listeners keep their
// connections. If anything fails, the previous configuration stays active.
func (s *Server) Apply(config Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(config)
}

// Update applies the result of modifying a copy of the active configuration.
// Concurrent updates are serialized, so read-modify-write cycles such as API
// calls that add one site never lose each other's changes.
func (s *Server) Update(modify func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.current.Load().config.Clone()
	if err := modify(&config); err != nil {
		return err
	}
	return s.applyLocked(config)
}

func (s *Server) applyLocked(config Config) error {
	previous := s.current.Load()
	next, err := compile(config, &s.opts, previous)
	if err != nil {
		return err
	}
	if !s.started {
		s.commitLocked(previous, next)
		return nil
	}

	var stale []string
	for name, running := range s.running {
		if listener := next.listeners[name]; listener == nil || listener.spec != running.spec {
			stale = append(stale, name)
		}
	}
	// Stop accepting on changed listeners first, so their addresses can be
	// reused; their open connections keep being served until drained.
	for _, name := range stale {
		s.running[name].stopAccepting()
	}
	started := make(map[string]*runningListener)
	for name, listener := range next.listeners {
		if running := s.running[name]; running != nil && running.spec == listener.spec {
			continue
		}
		running, err := s.listen(name, listener.spec)
		if err != nil {
			for _, running := range started {
				running.stopAccepting()
				running.server.Close()
			}
			return errors.Join(err, s.rebindLocked(stale))
		}
		started[name] = running
	}

	s.commitLocked(previous, next)
	for _, name := range stale {
		s.drain(s.running[name], next.server)
		delete(s.running, name)
	}
	for name, running := range started {
		s.running[name] = running
	}
	return nil
}

// commitLocked makes next the active snapshot.
func (s *Server) commitLocked(previous, next *snapshot) {
	if next.acme != nil {
		next.acme.setHosts(next.managedHosts)
	}
	s.current.Store(next)
	s.syncIssuerLocked()
	if previous != nil {
		closeUnusedTransports(previous, next)
	}
}

// syncIssuerLocked runs the active snapshot's ACME manager while the server
// is started, stopping a replaced one first.
func (s *Server) syncIssuerLocked() {
	var want *acmeManager
	if s.started {
		want = s.current.Load().acme
	}
	if s.issuer != nil && s.issuer.manager == want {
		return
	}
	if s.issuer != nil {
		s.issuer.cancel()
		<-s.issuer.done
		s.issuer = nil
	}
	if want != nil {
		ctx, cancel := context.WithCancel(context.Background())
		issuer := &acmeIssuer{manager: want, cancel: cancel, done: make(chan struct{})}
		go func() {
			defer close(issuer.done)
			want.run(ctx)
		}()
		s.issuer = issuer
	}
}

// rebindLocked restores listeners that Apply stopped before failing.
func (s *Server) rebindLocked(names []string) error {
	snap := s.current.Load()
	var errs []error
	for _, name := range names {
		old := s.running[name]
		running, err := s.listen(name, old.spec)
		s.drain(old, snap.server)
		if err != nil {
			delete(s.running, name)
			errs = append(errs, fmt.Errorf("restore previous listener: %w", err))
			continue
		}
		s.running[name] = running
	}
	return errors.Join(errs...)
}

// Start binds every listener. It returns once all sockets are bound, or
// with an error and nothing bound.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrAlreadyRunning
	}
	snap := s.current.Load()
	running := make(map[string]*runningListener, len(snap.listeners))
	for name, listener := range snap.listeners {
		listener, err := s.listen(name, listener.spec)
		if err != nil {
			for _, listener := range running {
				listener.stopAccepting()
				listener.server.Close()
			}
			return err
		}
		running[name] = listener
	}
	s.running = running
	s.started = true
	s.syncIssuerLocked()
	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests.
// When ctx expires, remaining connections are closed forcibly, so the
// server is always fully stopped on return.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	running := s.running
	s.running, s.started = nil, false
	s.syncIssuerLocked()
	s.mu.Unlock()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for name, listener := range running {
		listener.closing.Store(true)
		wg.Go(func() {
			if err := listener.server.Shutdown(ctx); err != nil {
				listener.server.Close()
				mu.Lock()
				errs = append(errs, &ListenerError{Listener: name, Err: err})
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	drained := make(chan struct{})
	go func() {
		s.draining.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-ctx.Done():
		errs = append(errs, fmt.Errorf("draining replaced listeners: %w", ctx.Err()))
	}
	for _, transport := range s.current.Load().transports {
		transport.CloseIdleConnections()
	}
	return errors.Join(errs...)
}

// Close shuts down within the configured shutdown timeout.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.current.Load().server.ShutdownTimeout))
	defer cancel()
	return s.Shutdown(ctx)
}

// Status describes the server's listeners.
type Status struct {
	Running   bool             `json:"running"`
	Listeners []ListenerStatus `json:"listeners"`
}

type ListenerStatus struct {
	Name string `json:"name"`
	// Address is the bound address while running, else the configured one.
	Address string `json:"address"`
	TLS     bool   `json:"tls"`
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
}

// Status returns the current state of every configured listener.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.current.Load()
	status := Status{Running: s.started}
	for name, listener := range snap.listeners {
		item := ListenerStatus{Name: name, Address: listener.spec.address, TLS: listener.spec.tls}
		if running := s.running[name]; running != nil {
			item.Address = running.ln.Addr().String()
			item.Running = true
			if failure := running.failure.Load(); failure != nil {
				item.Running = false
				item.Error = (*failure).Error()
			}
		}
		status.Listeners = append(status.Listeners, item)
	}
	slices.SortFunc(status.Listeners, func(a, b ListenerStatus) int { return cmp.Compare(a.Name, b.Name) })
	return status
}

// Healthy reports whether the server is running and every listener serves.
func (s *Server) Healthy() bool {
	status := s.Status()
	if !status.Running {
		return false
	}
	for _, listener := range status.Listeners {
		if !listener.Running {
			return false
		}
	}
	return true
}

// Metrics returns request metrics accumulated since New.
func (s *Server) Metrics() MetricsSnapshot {
	return s.metrics.snapshot()
}

func (s *Server) listen(name string, spec listenerSpec) (*runningListener, error) {
	ln, err := net.Listen("tcp", spec.address)
	if err != nil {
		return nil, &ListenerError{Listener: name, Err: err}
	}
	server := &http.Server{
		Handler:           &listenerHandler{server: s, name: name},
		ReadHeaderTimeout: time.Duration(spec.server.ReadHeaderTimeout),
		ReadTimeout:       time.Duration(spec.server.ReadTimeout),
		WriteTimeout:      time.Duration(spec.server.WriteTimeout),
		IdleTimeout:       time.Duration(spec.server.IdleTimeout),
		MaxHeaderBytes:    spec.server.MaxHeaderBytes,
		// Handshake failures from scanners are routine; keep them at debug.
		ErrorLog: slog.NewLogLogger(s.opts.logger.Handler(), slog.LevelDebug),
	}
	if spec.tls {
		server.TLSConfig = &tls.Config{MinVersion: spec.minTLS, GetCertificate: s.certificate}
	}
	running := &runningListener{spec: spec, server: server, ln: ln}
	go func() {
		var err error
		if spec.tls {
			// ServeTLS adds "h2" to the ALPN protocols, enabling HTTP/2.
			err = server.ServeTLS(ln, "", "")
		} else {
			err = server.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !running.closing.Load() {
			err = &ListenerError{Listener: name, Err: err}
			running.failure.Store(&err)
			s.opts.logger.Error("listener stopped", "listener", name, "error", err)
		}
	}()
	return running, nil
}

func (r *runningListener) stopAccepting() {
	r.closing.Store(true)
	_ = r.ln.Close()
}

// drain gracefully shuts down a replaced listener in the background.
func (s *Server) drain(running *runningListener, config ServerConfig) {
	running.closing.Store(true)
	s.draining.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.ShutdownTimeout))
		defer cancel()
		if err := running.server.Shutdown(ctx); err != nil {
			running.server.Close()
		}
	})
}

// certificate selects a listed certificate by SNI, then an ACME one.
func (s *Server) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	snap := s.current.Load()
	host := requestHost(hello.ServerName)
	if certificate, ok := snap.certs.match(host); ok {
		return certificate, nil
	}
	if snap.acme != nil {
		if certificate, ok := snap.acme.certificate(host); ok {
			return certificate, nil
		}
	}
	return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
}

// Certificates lists the certificates the server can present, including
// ACME-managed hosts still waiting for theirs.
func (s *Server) Certificates() []CertificateStatus {
	snap := s.current.Load()
	statuses := staticCertificateStatuses(snap.certs)
	if snap.acme != nil {
		statuses = append(statuses, snap.acme.statuses()...)
	}
	slices.SortFunc(statuses, func(a, b CertificateStatus) int {
		return cmp.Or(cmp.Compare(a.Names[0], b.Names[0]), cmp.Compare(a.NotAfter.Unix(), b.NotAfter.Unix()))
	})
	return statuses
}

// closeUnusedTransports releases idle upstream connections of transports
// that the new snapshot no longer uses. Requests still in flight on them
// complete normally.
func closeUnusedTransports(previous, next *snapshot) {
	for key, transport := range previous.transports {
		if next.transports[key] != transport {
			transport.CloseIdleConnections()
		}
	}
}
