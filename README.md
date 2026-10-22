# Yabber

Yabber is a small HTTP and HTTPS gateway for routers and home servers. It
terminates TLS, matches requests by hostname and path, and forwards them to
local services, Docker containers, static files, redirects or fixed
responses, and obtains certificates automatically over ACME. It is built on
`net/http` and `httputil.ReverseProxy`, and is meant to replace Caddy or nginx
where all you need is "this domain goes to that port".

It is both a command and a Go library: the gateway can be embedded in another
program and reconfigured at runtime through its API.

## Install

```sh
curl -fsSL https://github.com/lsongdev/yabber/releases/latest/download/install.sh | sh
```

The installer picks the build for this machine, verifies it against the
release's `SHA256SUMS`, and installs a service:

| | Binary | Configuration | Data | Service |
| --- | --- | --- | --- | --- |
| OpenWrt | `/usr/bin/yabber` | `/etc/yabber/config.yaml` | `/etc/yabber` | [`/etc/init.d/yabber`](contrib/openwrt/yabber.init), kept across sysupgrade |
| systemd | `/usr/local/bin/yabber` | `/var/lib/yabber/config.yaml` | `/var/lib/yabber` | [`yabber.service`](contrib/systemd/yabber.service), user `yabber`, API on `127.0.0.1:9180` |

A first install writes a starter configuration and leaves the service
stopped; running the installer again upgrades the binary and service files
and restarts the service without touching the configuration. `-v VERSION`
installs a specific release, `-n` only the binary, and `YABBER_MIRROR` points
it at a mirror. The installer checks the release signature when `openssl`
supports Ed25519 (`opkg install openssl-util` on OpenWrt) and refuses a mirror
it cannot verify.

On OpenWrt, move LuCI off ports 80 and 443 first (the installer prints how).
To serve the [management panel](#management-panel) on the LAN, set the
address in `/etc/config/yabber` and restart:

```sh
uci set yabber.main.admin=192.168.1.1:9180 && uci commit yabber && /etc/init.d/yabber restart
```

## Command

Download a binary from the [releases](https://github.com/lsongdev/yabber/releases)
(one per day, tagged with the date), or build it:

```sh
go install github.com/lsongdev/yabber/cmd/yabber@latest
make build            # dist/yabber for this machine
make -j dist          # every platform, plus SHA256SUMS
```

```sh
yabber run -d /var/lib/yabber -c /etc/yabber/config.yaml
yabber check -d /var/lib/yabber -c /etc/yabber/config.yaml
yabber reload -d /var/lib/yabber
yabber update            # or: yabber update -check
yabber version
```

`run` is the default command. Every command takes:

| Flag | Meaning |
| --- | --- |
| `-d DIR` | data directory: state yabber writes (ACME accounts and certificates, `yabber.pid`) |
| `-c FILE` | configuration file, `DIR/config.yaml` by default |

Without `-d`, the data directory is the configuration file's directory, so
`yabber -d /etc/yabber` and `yabber -c /etc/yabber/config.yaml` are the same.
Keeping the configuration in the data directory, as the installer does, lets
the management API save changes; the systemd unit leaves `/etc` read-only to
the service.

`run` also takes `-admin 127.0.0.1:9180` (the [management API](#management-api),
`/metrics` and `/healthz`), `-access-log` (JSON access logs on stdout) and
`-debug`.

**One instance per data directory.** `run` holds an exclusive lock on
`DIR/yabber.pid`, so two instances can never share ACME state; instances with
different directories run side by side. `reload` signals the instance holding
the lock, and a pid file left behind by a crash is recognized as stale.
`SIGHUP` (`systemctl reload`, `/etc/init.d/yabber reload`) does the same:
the configuration and certificates are reloaded without dropping
connections, and an invalid file is logged while the running configuration
stays. `SIGINT` and `SIGTERM` drain in-flight requests and exit.

**Updates.** `update` downloads the release build for this platform,
verifies it against `SHA256SUMS`, runs it once, and atomically replaces the
binary; restart the service afterwards. Builds on the same day share a date
tag, so it compares checksums rather than versions.

Releases are signed: CI signs `SHA256SUMS` with an Ed25519 key
(`SHA256SUMS.sig`) whose public half is compiled into yabber, and `update`
refuses anything it cannot verify. That makes any mirror safe to use, such as
a GitHub proxy where GitHub itself is slow or blocked:

```sh
yabber update -mirror https://ghfast.top/https://github.com/lsongdev/yabber/releases/latest/download
# or set YABBER_MIRROR, which install.sh honors too
```

A mirror is a URL of a directory holding one release's files.

**Logs** go to stderr. Yabber writes no log files of its own: journald and
OpenWrt's logd already keep, rotate and cap them. Access logs are off by
default; on OpenWrt, where logd is a small RAM ring, they would push out the
system log. Important events (certificates issued or failing, ACME account
changes, applied configurations, listener failures) are also kept in memory
for `Server.Events`.

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
| `email` | contact for a generated account, optional |
| `directory` | ACME directory; Let's Encrypt production by default. Use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing. |
| `ca_root` | PEM roots to trust for the directory, for a private CA such as step-ca |
| `account_key` | PEM key file of an existing account; the CA finds the account by its key |
| `account_url` | that account's URL, optional, requires `account_key` |

Accounts and certificates are stored in the data directory under `acme/`.
Without `account_key`, Yabber generates an account; if the CA later reports it
gone, Yabber archives it, registers a new one and logs a warning event. An
account given with `account_key` is never replaced: if the CA rejects it,
certificate requests fail with an error event until you fix the
configuration.

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
for anything else. Requests for hosts no site serves get a plain 404 over
HTTP, and over HTTPS the handshake is refused without presenting a
certificate, so the server never reveals which names it hosts. A `*` site
replaces that, for example with a redirect to your main site.

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
config, err := yabber.Load("/etc/yabber/config.yaml")
if err != nil {
	return err
}
server, err := yabber.New(config,
	yabber.WithDataDir("/var/lib/yabber"),
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
| `Events()` | The last 256 notable events: certificates, ACME accounts, applied configurations, listener failures. |
| `Metrics()` | Per-route counters; `WritePrometheus` renders them. |
| `Handler(listener)` | Serve a listener through your own `http.Server`. |
| `Shutdown(ctx)`, `Close()` | Graceful stop; remaining connections are closed when the context expires. |
| `Validate(config, options...)` | Check a configuration without a server. |

Options extend the gateway without growing the configuration schema:

- `WithDataDir` sets where state is stored; `tls.acme` requires it.
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

## Management panel

`yabber run -admin 127.0.0.1:9180` also serves a web panel at
`http://127.0.0.1:9180/`: an overview of health, listeners and traffic,
site editing (a form for single-handler sites, JSON for everything else),
certificates with their expiry and ACME errors, recent events, and the whole
configuration. Sign in with the token from `DIR/admin.token`. To reach a
server's panel from your machine, tunnel it: `ssh -L 9180:127.0.0.1:9180 host`.

The panel ([`web/`](web/)) is plain ES modules on Preact and htm with no
build step. The two libraries are vendored unmodified by
[`web/vendor.sh`](web/vendor.sh), which checks the npm registry's integrity
hashes, and loaded through an import map that the server allows by its hash
in a strict Content-Security-Policy. Everything is embedded in the binary.

## Management API

The panel uses a JSON API for dashboards and automation (package
[`api`](api/api.go)). Requests need the token that is
generated into `DIR/admin.token` on first start:

```sh
TOKEN=$(cat /var/lib/yabber/admin.token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9180/api/sites
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:9180/api/sites \
  -d '{"hosts": ["app.example.com"], "proxy": "http://127.0.0.1:3000"}'
```

| Endpoint | |
| --- | --- |
| `GET /api/status` | listeners and health |
| `GET`, `PUT /api/config` | the whole configuration |
| `GET`, `POST /api/sites` | list or add sites |
| `GET`, `PUT`, `DELETE /api/sites/{id}` | one site, by name or first host |
| `GET /api/certificates` | certificates, expiry, ACME errors |
| `GET /api/events` | recent events |
| `GET /api/metrics` | request metrics |
| `GET /healthz`, `GET /metrics` | health and Prometheus, without a token |

Bodies use the configuration's JSON form, the same fields as YAML. A change
is validated and applied like a reload: an invalid one returns 422 and
changes nothing. Responses carry the configuration's `ETag`; sending it back
as `If-Match` makes a write fail with 412 if someone else changed the
configuration in between. Applied changes are saved to the configuration
file (comments are not preserved; the previous file is kept as `.bak`), and
`SIGHUP` reloads are serialized with API writes. Bind the API to a private
address: it controls the whole gateway.

## Layout

The core package only routes and serves. Anything that talks to people or
other systems is a separate layer on top of the public API:

- `cmd/yabber` maps files, signals and flags onto `Load`, `Apply` and
  `Close`.
- `workers` is an optional handler registered through `WithHandler`; only
  binaries that import it link the JavaScript engine.
- `api` is the management API over `Config`, `Update`, `Status`,
  `Certificates`, `Events` and `Metrics`; `cmd/yabber` serves it with
  `-admin` and saves changes to the configuration file.
- `web` is the panel, static files over `api`, served by `cmd/yabber`
  next to it.
