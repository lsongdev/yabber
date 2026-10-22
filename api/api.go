// Package api serves a JSON management API for a yabber.Server, for
// dashboards and automation. It is a layer over the server's public methods:
// it reads state with Config, Status, Certificates, Events and Metrics, and
// changes configuration with Update.
//
//	GET    /healthz                   liveness, no authentication
//	GET    /metrics                   Prometheus text, no authentication
//	GET    /api/status                listeners and health
//	GET    /api/config                the configuration (ETag)
//	PUT    /api/config                replace the configuration (If-Match)
//	GET    /api/sites                 sites
//	POST   /api/sites                 add a site
//	GET    /api/sites/{id}            one site
//	PUT    /api/sites/{id}            replace a site (If-Match)
//	DELETE /api/sites/{id}            remove a site (If-Match)
//	GET    /api/certificates          certificates and ACME state
//	GET    /api/events                recent events
//	GET    /api/metrics               request metrics as JSON
//
// Every /api request needs "Authorization: Bearer TOKEN". Writes are checked
// like any configuration change: an invalid one returns 422 and changes
// nothing. The configuration's ETag changes with every write; sending it
// back in If-Match turns a conflicting concurrent edit into 412 instead of a
// lost update.
//
// Serve the handler on a private address: it can change everything the
// gateway does.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/lsongdev/yabber"
)

// maxBodyBytes bounds request bodies.
const maxBodyBytes = 1 << 20

// Options configures the API.
type Options struct {
	// Token authenticates /api requests. It is required.
	Token string
	// Save persists a configuration once it has been applied, typically by
	// writing the configuration file, so that a restart or reload keeps API
	// changes. A Save error is reported to the client; the change stays
	// applied. Nil keeps changes in memory only.
	Save func(yabber.Config) error
}

// API is the management API of one server.
type API struct {
	server *yabber.Server
	opts   Options
	mux    *http.ServeMux
	// writes serializes changes with their Save, so the saved file always
	// matches the applied configuration.
	writes sync.Mutex
}

// New returns the API for server.
func New(server *yabber.Server, opts Options) (*API, error) {
	if opts.Token == "" {
		return nil, errors.New("api: a token is required")
	}
	a := &API{server: server, opts: opts, mux: http.NewServeMux()}
	a.mux.HandleFunc("GET /healthz", a.healthz)
	a.mux.HandleFunc("GET /metrics", a.prometheus)
	a.handle("GET /api/status", a.status)
	a.handle("GET /api/config", a.getConfig)
	a.handle("PUT /api/config", a.putConfig)
	a.handle("GET /api/sites", a.listSites)
	a.handle("POST /api/sites", a.createSite)
	a.handle("GET /api/sites/{id}", a.getSite)
	a.handle("PUT /api/sites/{id}", a.putSite)
	a.handle("DELETE /api/sites/{id}", a.deleteSite)
	a.handle("GET /api/certificates", a.certificates)
	a.handle("GET /api/events", a.events)
	a.handle("GET /api/metrics", a.metrics)
	a.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if a.authorized(w, r) {
			writeError(w, http.StatusNotFound, errors.New("no such endpoint"))
		}
	})
	return a, nil
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// Apply applies config through the API's write lock without saving it. Use
// it for changes from elsewhere, such as reloading the configuration file,
// so they never interleave with an API change and its Save.
func (a *API) Apply(config yabber.Config) error {
	a.writes.Lock()
	defer a.writes.Unlock()
	return a.server.Apply(config)
}

// handle registers an authenticated endpoint.
func (a *API) handle(pattern string, handler http.HandlerFunc) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if a.authorized(w, r) {
			handler(w, r)
		}
	})
}

func (a *API) authorized(w http.ResponseWriter, r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && subtle.ConstantTimeCompare([]byte(token), []byte(a.opts.Token)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="yabber"`)
	writeError(w, http.StatusUnauthorized, errors.New("missing or invalid token"))
	return false
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request) {
	if !a.server.Healthy() {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

func (a *API) prometheus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_ = a.server.Metrics().WritePrometheus(w)
}

func (a *API) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		yabber.Status
		Healthy bool `json:"healthy"`
	}{a.server.Status(), a.server.Healthy()})
}

func (a *API) certificates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, nonNil(a.server.Certificates()))
}

func (a *API) events(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, nonNil(a.server.Events()))
}

func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.server.Metrics())
}

// errPrecondition reports a stale If-Match.
var errPrecondition = errors.New("the configuration changed since it was read; fetch it again")

// statusError carries an HTTP status out of an Update callback.
type statusError struct {
	status int
	err    error
}

func (e *statusError) Error() string { return e.err.Error() }

// change applies modify to the configuration if the request's If-Match is
// current, saves the result, and writes the new configuration's ETag. It
// reports whether the change succeeded; on failure it has written the
// error response.
func (a *API) change(w http.ResponseWriter, r *http.Request, modify func(*yabber.Config) error) bool {
	a.writes.Lock()
	defer a.writes.Unlock()
	ifMatch := r.Header.Get("If-Match")
	var applied yabber.Config
	err := a.server.Update(func(config *yabber.Config) error {
		if ifMatch != "" && ifMatch != "*" && ifMatch != etag(*config) {
			return &statusError{http.StatusPreconditionFailed, errPrecondition}
		}
		if err := modify(config); err != nil {
			return err
		}
		applied = config.Clone()
		return nil
	})
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			writeError(w, se.status, se.err)
		} else {
			// Anything else is the configuration failing to compile or bind.
			writeError(w, http.StatusUnprocessableEntity, err)
		}
		return false
	}
	if a.opts.Save != nil {
		if err := a.opts.Save(applied); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("applied, but saving failed: %w", err))
			return false
		}
	}
	w.Header().Set("ETag", etag(applied))
	return true
}

func (a *API) getConfig(w http.ResponseWriter, _ *http.Request) {
	config := a.server.Config()
	w.Header().Set("ETag", etag(config))
	writeJSON(w, http.StatusOK, config)
}

func (a *API) putConfig(w http.ResponseWriter, r *http.Request) {
	var next yabber.Config
	if !readJSON(w, r, &next) {
		return
	}
	if a.change(w, r, func(config *yabber.Config) error {
		*config = next
		return nil
	}) {
		writeJSON(w, http.StatusOK, a.server.Config())
	}
}

// etag identifies a configuration's content.
func etag(config yabber.Config) string {
	data, _ := json.Marshal(config)
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON: unexpected data after the value"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// nonNil makes empty lists encode as [] rather than null.
func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}
