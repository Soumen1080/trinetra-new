// Command scanner-egress is Trinetra's live TLS/SSH observation service.
//
// It discovers protocol versions, cipher suites and certificate key types by
// connecting to live endpoints. This is the fourth scanner service, on
// `scanner-egress` rather than `scanner-internal`, because it needs outbound
// network access — a different blast radius.
//
// Everything this scanner finds has `is_observed=true`, distinguishing it from
// declared configuration that the config engine produces.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/scanner-egress/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner-egress: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("TRINETRA_SCANNER_ADDR", ":8080"), "listen address")
		storeRoot = flag.String("artifact-store", envOr("TRINETRA_ARTIFACT_STORE", "/artifact-store"), "artifact store root")
	)
	flag.Parse()

	token := os.Getenv("TRINETRA_SCANNER_TOKEN")
	if len(token) < scannerapi.MinTokenLength {
		return fmt.Errorf("TRINETRA_SCANNER_TOKEN must be set and at least %d characters",
			scannerapi.MinTokenLength)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	registry := engine.NewRegistry(
		engine.NewTestSSLEngine(),
		engine.NewSSHEngine(),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*storeRoot))

	// Report engine availability at startup
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, e := range registry.Engines() {
		if err := e.Available(ctx); err != nil {
			logger.Warn("detection engine unavailable",
				"engine", e.Name(), "reason", err.Error())
			continue
		}
		logger.Info("detection engine ready",
			"engine", e.Name(), "version", e.Tool().Version)
	}

	server, err := scannerapi.NewServer(scannerapi.Config{
		Token:          token,
		ScannerName:    "egress",
		ScannerVersion: engine.ScannerVersion,
		Logger:         logger,
		Scan:           scanner.Scan,
	})
	if err != nil {
		return err
	}

	logger.Info("scanner-egress listening", "addr", *addr)
	return server.ListenAndServe(ctx, *addr)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
