# Yabber

Yabber is a small embeddable HTTP and HTTPS server built on Go's
`http.ServeMux`, `httputil.ReverseProxy`, and `tls.Config`.

Its configuration has five resources:

- certificates describe reusable certificate sources;
- listeners bind HTTP or HTTPS addresses;
- hosts bind domain names and certificates to listeners;
- routes map methods and paths to handlers, including inline JavaScript Workers;
- policies are reusable request, rate, and concurrency middleware bundles.

```go
cfg, err := yabber.Load("yabber.yaml")
if err != nil {
    return err
}

server, err := yabber.New(cfg)
if err != nil {
    return err
}
if err := server.Start(); err != nil {
    return err
}

defer server.Close()
```

`Apply` validates and atomically replaces hosts, routes, and certificates while
listeners keep running. Listener topology changes return
`ErrRestartRequired`; use `Restart` when those changes are intentional.
Unchanged policies retain their runtime state across `Apply`, so reloading an
unrelated route does not reset rate-limit buckets.

Standalone configurations use `FileCertificateLoader`. Embedded applications
can provide `WithCertificateLoader` to resolve only the certificates referenced
by enabled HTTPS hosts from a database or another store.

See [`config.example.yaml`](config.example.yaml) for a complete configuration.

## Policies

Policies can be attached to listeners, hosts, and routes. The scopes nest in
that order, and policy names are applied in declaration order.

```yaml
policies:
  - name: api
    request:
      max_body_bytes: 10485760
      timeout: 30s
    rate_limit:
      requests_per_second: 100
      burst: 200
      key: client_ip
    concurrency:
      max: 64

hosts:
  - name: example
    # ...
    routes:
      - name: api
        policies: [api]
        # ...
```

Rate limits use an in-process token bucket. `client_ip` and `global` keys are
supported. Client-provided forwarding headers are ignored unless the direct
peer belongs to a listener's `trusted_proxies`. Identity maps have bounded
size and idle entries are removed. A named policy represents one shared bucket
or concurrency pool across all of its references. If the same policy is
inherited from more than one scope on a request, it is applied only once.

Custom application middleware can be installed without extending the config
schema:

```go
server, err := yabber.New(cfg, yabber.WithMiddleware(
    func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            next.ServeHTTP(w, r)
        })
    },
))
```

## Reverse proxy limits

Each reverse proxy uses a reusable transport with safe connect, TLS handshake,
response-header, and idle defaults. Routes may override those values and set a
whole-request timeout. A zero server `write_timeout` is intentional for
WebSocket, SSE, and streaming responses; use route request timeouts when the
operation has a known upper bound.

## Observability

Every server records request counts, active requests, errors, rejections,
response bytes, duration, and per-route aggregates:

```go
snapshot := server.Metrics()
statuses := server.ListenerStatuses()
healthy := server.Healthy()
adminMux.Handle("/metrics", server.MetricsHandler())
```

Use `WithAccessLog(writer)` for JSON-lines access logs or `WithObserver` to
export `RequestRecord` values to another metrics or logging system. Request
records include listener, host, route, trusted client IP, status, latency,
bytes, rejection policy, and request ID. Unexpected listener failures remain
available through `Errors()` and are also reflected by `ListenerStatuses`.

`MetricsHandler` emits Prometheus-compatible text and should be mounted only on
a private administration listener, not on a public virtual host.
