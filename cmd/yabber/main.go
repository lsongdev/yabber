// Command yabber runs a gateway from a YAML configuration file.
//
//	yabber -config /etc/yabber/yabber.yaml
//
// SIGHUP reloads the configuration (and certificates) without dropping
// connections; SIGINT and SIGTERM shut down gracefully.
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

// extensions lists optional handlers compiled in with build tags.
var extensions []yabber.Option

func main() {
	configPath := flag.String("config", "yabber.yaml", "configuration file")
	check := flag.Bool("check", false, "validate the configuration and exit")
	admin := flag.String("admin", "", "serve /metrics and /healthz on this address, e.g. 127.0.0.1:9180")
	accessLog := flag.Bool("access-log", false, "write JSON access logs to stdout")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	options := append([]yabber.Option{yabber.WithLogger(logger)}, extensions...)
	if *accessLog {
		options = append(options, yabber.WithAccessLog(os.Stdout))
	}
	if err := run(*configPath, *check, *admin, options, logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(configPath string, check bool, adminAddress string, options []yabber.Option, logger *slog.Logger) error {
	config, err := yabber.Load(configPath)
	if err != nil {
		return err
	}
	if check {
		if err := yabber.Validate(config, options...); err != nil {
			return err
		}
		fmt.Println("configuration ok")
		return nil
	}

	server, err := yabber.New(config, options...)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	for _, listener := range server.Status().Listeners {
		logger.Info("listening", "listener", listener.Name, "address", listener.Address, "tls", listener.TLS)
	}

	var adminServer *http.Server
	if adminAddress != "" {
		adminServer = &http.Server{Addr: adminAddress, Handler: adminHandler(server), ReadHeaderTimeout: 10 * time.Second}
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
		if err := reload(server, configPath); err != nil {
			logger.Error("reload failed; keeping the previous configuration", "error", err)
		} else {
			logger.Info("configuration reloaded")
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

func reload(server *yabber.Server, configPath string) error {
	config, err := yabber.Load(configPath)
	if err != nil {
		return err
	}
	return server.Apply(config)
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
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
