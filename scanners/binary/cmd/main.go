// Command scanner-binary is Trinetra's binary analysis service.
//
// It runs Ghidra, OSV-Scanner, and Presidio over binaries to detect:
// - Crypto constants and API calls in stripped binaries
// - Known CVEs in dependencies
// - PII/sensitive data via NER
//
// This scanner runs on its own queue because binary analysis is slow and has
// a different resource profile. Following §7.4, each scanner remains an
// evidence source, never a verdict source.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/scanner-binary/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner-binary: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("TRINETRA_SCANNER_ADDR", ":8080"), "listen address")
		inputRoot = flag.String("input-root", envOr("TRINETRA_INPUT_ROOT", "/scan-workdir"), "read-only scan input root")
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
		engine.NewGhidraEngine(),
		engine.NewOSVEngine(),
		engine.NewPresidioEngine(),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*storeRoot), *inputRoot)

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
		ScannerName:    "binary",
		ScannerVersion: engine.ScannerVersion,
		Logger:         logger,
		Scan:           scanner.Scan,
	})
	if err != nil {
		return err
	}

	logger.Info("scanner-binary listening", "addr", *addr, "input_root", filepath.Clean(*inputRoot))
	return server.ListenAndServe(ctx, *addr)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
