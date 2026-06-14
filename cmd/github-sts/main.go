// Package main is the entry point for the github-sts service.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/depthmark/github-sts/internal/config"
	"github.com/depthmark/github-sts/internal/server"
)

func main() {
	// Load configuration.
	configPath := os.Getenv("GITHUBSTS_CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize structured logger.
	slogger := initLogger(cfg.Server.LogLevel)
	slog.SetDefault(slogger)
	slogger.Info("application starting", "config_path", configPath, "log_level", cfg.Server.LogLevel)
	slogger.Info("configuration loaded", "config_path", configPath)

	// Create server.
	srv, err := server.New(cfg, slogger)
	if err != nil {
		slogger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	// Signal handling: SIGINT/SIGTERM cancel the server context;
	// SIGHUP triggers a bundle reload without restarting the broker.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				slogger.Info("SIGHUP received: reloading bundle")
				reloadCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				if err := srv.ReloadBundle(reloadCtx); err != nil {
					slogger.Warn("SIGHUP reload failed (keeping previous bundle)", "error", err)
				}
				cancel()
			}
		}
	}()

	// Start server (blocks until context is cancelled).
	if err := srv.ListenAndServe(ctx); err != nil {
		slogger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// initLogger creates a slog.Logger with JSON output at the specified level.
func initLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	})
	return slog.New(handler)
}
