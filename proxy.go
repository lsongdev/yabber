package yabber

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// statusClientClosedRequest records requests abandoned by the client, as
// nginx does.
const statusClientClosedRequest = 499

// transportKey identifies interchangeable upstream transports. Routes with
// equal keys share one connection pool, and pools survive Apply.
type transportKey struct {
	socket                string // Unix socket path, or empty for TCP
	insecureSkipVerify    bool
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	maxConns              int
}

func newTransport(key transportKey) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Upstreams are local services; never route them through HTTP_PROXY.
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: key.dialTimeout, KeepAlive: 30 * time.Second}
	transport.DialContext = dialer.DialContext
	if key.socket != "" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", key.socket)
		}
	}
	transport.ResponseHeaderTimeout = key.responseHeaderTimeout
	transport.MaxConnsPerHost = key.maxConns
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64
	if key.insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport
}

func (c *compiler) proxy(config Proxy) (http.Handler, error) {
	target, socket, err := parseUpstream(config.Upstream)
	if err != nil {
		return nil, err
	}
	if config.DialTimeout < 0 || config.ResponseHeaderTimeout < 0 || config.MaxConns < 0 {
		return nil, errors.New("proxy timeouts and max_conns cannot be negative")
	}
	transport := c.transport(transportKey{
		socket:                socket,
		insecureSkipVerify:    config.InsecureSkipVerify,
		dialTimeout:           durationOr(config.DialTimeout, 5*time.Second),
		responseHeaderTimeout: time.Duration(config.ResponseHeaderTimeout),
		maxConns:              config.MaxConns,
	})
	logger := c.opts.logger
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			if config.StripPrefix != "" {
				stripPathPrefix(r.Out.URL, config.StripPrefix)
			}
			r.SetURL(target)
			r.Out.Host = r.In.Host
			if config.HostHeader != "" {
				r.Out.Host = config.HostHeader
			}
			setForwardedHeaders(r)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status := proxyErrorStatus(r, err)
			if status != statusClientClosedRequest {
				logger.Warn("upstream request failed", "upstream", config.Upstream,
					"request_id", Info(r).RequestID, "error", err)
			}
			w.WriteHeader(status)
		},
	}, nil
}

// parseUpstream returns the URL requests are rewritten to and, for
// unix:/path.sock upstreams, the socket to dial.
func parseUpstream(raw string) (*url.URL, string, error) {
	if socket, ok := strings.CutPrefix(raw, "unix:"); ok {
		socket = strings.TrimPrefix(socket, "//")
		if !strings.HasPrefix(socket, "/") {
			return nil, "", fmt.Errorf("invalid upstream %q: unix socket path must be absolute", raw)
		}
		return &url.URL{Scheme: "http", Host: "localhost"}, socket, nil
	}
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, "", fmt.Errorf("invalid upstream %q: want http://, https:// or unix:", raw)
	}
	return target, "", nil
}

// setForwardedHeaders sets X-Forwarded-* and X-Real-IP. Headers from a
// trusted proxy are extended; anything else from the client is discarded.
func setForwardedHeaders(r *httputil.ProxyRequest) {
	state := requestStateFrom(r.In.Context())
	trusted := state != nil && state.trustedPeer
	if trusted {
		r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
	}
	r.SetXForwarded()
	if trusted {
		for _, name := range []string{"X-Forwarded-Host", "X-Forwarded-Proto"} {
			if value := r.In.Header.Get(name); value != "" {
				r.Out.Header.Set(name, value)
			}
		}
	}
	r.Out.Header.Del("X-Real-IP")
	if state != nil && state.clientIP.IsValid() {
		r.Out.Header.Set("X-Real-IP", state.clientIP.String())
	}
}

func proxyErrorStatus(r *http.Request, err error) int {
	var maxBytes *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytes):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(r.Context().Err(), context.Canceled):
		return statusClientClosedRequest
	default:
		return http.StatusBadGateway
	}
}

// stripPathPrefix removes prefix from u when it matches whole path segments,
// keeping the escaped form in sync so encoded characters such as %2F
// survive.
func stripPathPrefix(u *url.URL, prefix string) {
	prefix = strings.TrimSuffix(prefix, "/")
	path, ok := cutPathPrefix(u.Path, prefix)
	if !ok {
		return
	}
	u.Path = path
	if u.RawPath != "" {
		if raw, ok := cutPathPrefix(u.RawPath, prefix); ok {
			u.RawPath = raw
		} else {
			u.RawPath = ""
		}
	}
}

func cutPathPrefix(path, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || (rest != "" && rest[0] != '/') {
		return path, false
	}
	if rest == "" {
		rest = "/"
	}
	return rest, true
}

// stripPrefix is a segment-aware http.StripPrefix that leaves non-matching
// paths unchanged.
func stripPrefix(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *r.URL
		stripPathPrefix(&u, prefix)
		stripped := new(http.Request)
		*stripped = *r
		stripped.URL = &u
		next.ServeHTTP(w, stripped)
	})
}
