package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lsongdev/yabber"
)

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	var p paths
	p.register(flags)
	admin := flags.String("admin", "", "serve /metrics and /healthz on this address, e.g. 127.0.0.1:9180")
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

	var adminServer *http.Server
	if *admin != "" {
		adminServer = &http.Server{Addr: *admin, Handler: adminHandler(server), ReadHeaderTimeout: 10 * time.Second}
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
			err = server.Apply(config)
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

func adminHandler(server *yabber.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_ = server.Metrics().WritePrometheus(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !server.Healthy() {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}
