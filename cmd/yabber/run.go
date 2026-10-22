package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lsongdev/yabber"
	"github.com/lsongdev/yabber/api"
	"github.com/lsongdev/yabber/web"
)

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	var p paths
	p.register(flags)
	admin := flags.String("admin", "", "serve the management API, /metrics and /healthz on this private address, e.g. 127.0.0.1:9180")
	accessLog := flags.Bool("access-log", false, "write JSON access logs to stdout")
	debug := flags.Bool("debug", false, "enable debug logging")
	flags.Parse(args)
	p.resolve()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	// Logs go to stderr; the service manager (journald, OpenWrt logd) keeps
	// and rotates them.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	lock, err := acquirePidFile(p.pidFile())
	if err != nil {
		return err
	}
	defer lock.release()

	config, err := yabber.Load(p.config)
	if err != nil {
		return err
	}
	options := append([]yabber.Option{yabber.WithLogger(logger), yabber.WithDataDir(p.dir)}, extensions...)
	if *accessLog {
		options = append(options, yabber.WithAccessLog(os.Stdout))
	}
	server, err := yabber.New(config, options...)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	logger.Info("yabber started", "version", version, "config", p.config, "data", p.dir)
	for _, listener := range server.Status().Listeners {
		logger.Info("listening", "listener", listener.Name, "address", listener.Address, "tls", listener.TLS)
	}

	apply := server.Apply
	var adminServer *http.Server
	if *admin != "" {
		token, err := adminToken(p.tokenFile())
		if err != nil {
			return err
		}
		management, err := api.New(server, api.Options{Token: token, Save: saver(p.config)})
		if err != nil {
			return err
		}
		apply = management.Apply
		logger.Info("management panel and API enabled", "address", *admin, "token_file", p.tokenFile())
		mux := http.NewServeMux()
		mux.Handle("/", web.Handler())
		mux.Handle("/api/", management)
		mux.Handle("GET /healthz", management)
		mux.Handle("GET /metrics", management)
		adminServer = &http.Server{Addr: *admin, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("admin server stopped", "error", err)
			}
		}()
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for sig := range signals {
		if sig != syscall.SIGHUP {
			break
		}
		config, err := yabber.Load(p.config)
		if err == nil {
			err = apply(config)
		}
		if err != nil {
			logger.Error("reload failed; keeping the previous configuration", "error", err)
		}
	}

	logger.Info("shutting down")
	if adminServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = adminServer.Shutdown(ctx)
	}
	return server.Close()
}
