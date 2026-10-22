# Yabber

Yabber is a small HTTP and HTTPS gateway for routers and home servers. It
terminates TLS, matches requests by hostname and path, and forwards them to
local services, Docker containers, static files, redirects or fixed
responses, and obtains certificates automatically over ACME. It is built on
`net/http` and `httputil.ReverseProxy`, and is meant to replace Caddy or nginx
where all you need is "this domain goes to that port".

It is both a command and a Go library: the gateway can be embedded in another
program and reconfigured at runtime through its API.

## Command

Download a binary from the [releases](https://github.com/lsongdev/yabber/releases)
(one per day, tagged with the date), or build it:

```sh
go install github.com/lsongdev/yabber/cmd/yabber@latest
make build            # dist/yabber for this machine
make -j dist          # every platform, plus SHA256SUMS
yabber -config /etc/yabber/yabber.yaml
```

| Flag | Meaning |
| --- | --- |
| `-config` | configuration file (default `yabber.yaml`) |
| `-check` | validate the configuration, including certificates, and exit |
| `-admin 127.0.0.1:9180` | serve `/metrics` (Prometheus) and `/healthz` |
| `-access-log` | write JSON access logs to stdout |
| `-debug` | debug logging, including TLS handshake failures |
| `-version` | print the version and exit |

`SIGHUP` reloads the configuration and certificates without dropping
connections; an invalid file is logged and the running configuration is kept.
`SIGINT` and `SIGTERM` drain in-flight requests and exit.

Inline JavaScript Worker handlers add about 10 MB to the binary and are
opt-in: `go build -tags worker ./cmd/yabber`.

## Automatic HTTPS

```yaml
tls:
  acme:
    email: admin@example.com

sites:
  - hosts: [app.example.com]
    proxy: http://127.0.0.1:3000
```

With `tls.acme`, every host served over TLS that no listed certificate covers
gets its own certificate through ACME HTTP-01. Yabber listens on `:80` and
`:443`, registers an account (agreeing to the CA's terms), answers challenges
ahead of the HTTP-to-HTTPS redirect, and renews each certificate two thirds
into its lifetime. Failed attempts back off from 5 minutes to 12 hours; a
reload (SIGHUP or `Apply`) retries failing hosts after at most a minute, so
fixing DNS and reloading takes effect at once.

`/metrics` exports `yabber_certificate_expiry_timestamp_seconds` for every
certificate (0 while a managed one is pending) and
`yabber_certificate_acme_error` for managed names. Alert on
`yabber_certificate_expiry_timestamp_seconds - time() < 14 * 86400`.

| Field | Meaning |
| --- | --- |
| `email` | account contact, optional |
| `directory` | ACME directory; Let's Encrypt production by default. Use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing. |
| `ca_root` | PEM roots to trust for the directory, for a private CA such as step-ca |
| `storage` | account and certificates, `acme/` beside the configuration file by default |

The CA must reach a plain HTTP listener on port 80 (directly or through port
forwarding). HTTP-01 cannot issue wildcard certificates, so wildcard hosts
still need a listed certificate.

## Configuration

The smallest useful configuration:

```yaml
sites:
  - hosts: [app.example.com]
    proxy: http://127.0.0.1:3000
```

A fuller one:

```yaml
tls:
  certificates:
    - cert: certs/example.com/fullchain.pem
      key: certs/example.com/privkey.pem

sites:
  - hosts: [example.com, www.example.com]
    routes:
      - path: /api/
        proxy:
          upstream: http://127.0.0.1:8080
          strip_prefix: /api
      - path: /
        files: /srv/www

  - hosts: [git.example.com]
    proxy: unix:/var/run/gitea.sock
```

See [`config.example.yaml`](config.example.yaml) for every section. Unknown
fields are errors, and relative paths are resolved against the configuration
file.

**Listeners.** Without a `listeners` section, Yabber listens on `:80`, plus
`:443` when any certificate or `tls.acme` is configured. Every site is served on every
listener unless it lists `listeners: [...]`.

**HTTPS.** Certificates are matched to hostnames by their DNS names; sites
never reference certificates. A site served on a TLS listener must be covered
by a certificate or by ACME, which is checked when the configuration loads. When several
certificates cover a name, the one that expires last wins, so a renewed
certificate can simply be added. Listed certificates are re-read every hour,
so renewals written to disk (by certbot, for example) are picked up without a
reload. A listed certificate that is expired, not yet valid, or within a day
of expiry no longer covers its names: with `tls.acme` they move to ACME, and
otherwise it is still served with a warning, so one stale file never blocks a
reload. HTTP/2 is
negotiated automatically. A site that is also served over TLS redirects
plain HTTP to HTTPS unless it sets `allow_http: true`.

**Hosts** are exact names, single-label wildcards (`*.example.com`), or `*`
for anything else.

**Routes** use `net/http.ServeMux` patterns: `/api/` matches a subtree,
`/health` matches exactly, `/{$}` matches only the root, and `method: GET`
restricts the method. A site with a single handler is shorthand for one route
on `/`.

**Handlers.** Each route has exactly one:

| Handler | Shorthand | Notes |
| --- | --- | --- |
| `proxy` | upstream URL | `http://`, `https://` (with an optional base path) or `unix:/path.sock`. Keeps the client's `Host` unless `host_header` is set. Sets `X-Forwarded-*` and `X-Real-IP`. `strip_prefix` removes whole path segments only. |
| `files` | root directory | Hides dotfiles other than `.well-known`; directories need an `index.html` unless `browse: true`. |
| `respond` | body | Optional `status` and `headers`. |
| `redirect` | target | `status` defaults to 308; `preserve_path` appends the request path. |

**Policies** are named request limits attached to listeners, sites or routes:

```yaml
policies:
  - name: api
    request: {max_body_bytes: 10485760, timeout: 30s}
    rate_limit: {requests_per_second: 100, burst: 200}
    concurrency: {max: 64}
```

A request timeout cancels the request context and never buffers the
response, so streaming keeps working; it does bound WebSocket lifetimes,
so leave it off those routes. Rate limits key on the client IP (IPv6 by /64)
or `key: global`, and evict the least recently seen client when full instead
of locking new clients out. A policy reached from several scopes applies once
per request, and unchanged policies keep their state across reloads.

**Client addresses.** `X-Forwarded-For`, `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Request-ID` are believed only from peers listed in
a listener's `trusted_proxies`.

## Library

```go
config, err := yabber.Load("yabber.yaml")
if err != nil {
	return err
}
server, err := yabber.New(config,
	yabber.WithLogger(slog.Default()),
	yabber.WithAccessLog(os.Stdout),
)
if err != nil {
	return err
}
if err := server.Start(); err != nil {
	return err
}
defer server.Close()
```

Configurations can also be built as Go values, and every configuration type
encodes to YAML and JSON with the same field names, so they can be stored or
sent over an API as they are.

| Method | Purpose |
| --- | --- |
| `Apply(config)` | Validate and switch atomically. Changed listeners are rebound and the old ones drain in the background; on any error nothing changes. |
| `Update(func(*Config) error)` | Read-modify-write on a copy of the active configuration, serialized against other changes. |
| `Config()` | A copy of the active configuration. |
| `Status()`, `Healthy()` | Listener state, including bind or serve errors. |
| `Certificates()` | Every certificate in use, with expiry and the last ACME error. |
| `Metrics()` | Per-route counters; `WritePrometheus` renders them. |
| `Handler(listener)` | Serve a listener through your own `http.Server`. |
| `Shutdown(ctx)`, `Close()` | Graceful stop; remaining connections are closed when the context expires. |
| `Validate(config, options...)` | Check a configuration without a server. |

Options extend the gateway without growing the configuration schema:

- `WithCertificateSource` supplies certificates from a database;
  `WithHTTP01Store` answers HTTP-01 challenges for an external ACME client.
- `WithObserver` receives a `RequestRecord` for every request.
- `WithMiddleware` wraps every routed request.
- `WithHandler(name, factory)` registers a handler type that sites and routes
  can then use by name. The `workers` package is one:

  ```go
  server, err := yabber.New(config, workers.Option())
  ```

  ```yaml
  sites:
    - hosts: [hello.example.com]
      worker: |
        export default {
          async fetch(request, env) {
            return Response.json({ url: request.url })
          }
        }
  ```

  Scripts use the Cloudflare Workers module syntax with `Request`,
  `Response` and `Headers` (string bodies, no outbound `fetch`). They are
  compiled when the configuration loads, so syntax errors fail validation,
  and a script stops when its request is cancelled or times out.

## Layout

The core package only routes and serves. Anything that talks to people or
other systems is a separate layer on top of the public API:

- `cmd/yabber` maps files, signals and flags onto `Load`, `Apply` and
  `Close`.
- `workers` is an optional handler registered through `WithHandler`; only
  binaries that import it link the JavaScript engine.
- A management web API or dashboard belongs in its own package. It would
  call `Config`, `Update`, `Status` and `Metrics`, and persist configurations
  as YAML or JSON.
