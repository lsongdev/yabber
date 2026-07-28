# Yabber

Yabber is a small embeddable HTTP and HTTPS server built on Go's
`http.ServeMux`, `httputil.ReverseProxy`, and `tls.Config`.

Its configuration has four resources:

- certificates describe reusable certificate sources;
- listeners bind HTTP or HTTPS addresses;
- hosts bind domain names and certificates to listeners;
- routes map methods and paths to handlers, including inline JavaScript Workers.

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

Standalone configurations use `FileCertificateLoader`. Embedded applications
can provide `WithCertificateLoader` to resolve only the certificates referenced
by enabled HTTPS hosts from a database or another store.

See [`config.example.yaml`](config.example.yaml) for a complete configuration.
