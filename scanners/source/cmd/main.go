// Command scanner-source is Trinetra's source-code discovery service.
//
// It runs every available detection engine over a target and publishes one
// immutable CycloneDX 1.6 CBOM. It has no external route at all: the compose
// topology puts it on `scanner-internal`, and its port is never published to
// the host.
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
	"github.com/trinetra/scanner-source/internal/engine"
)

func main() {
	if err := run(); err != nil {
		// Errors reaching here are operator-facing, not client-facing, so the
		// detail is appropriate.
		fmt.Fprintf(os.Stderr, "scanner-source: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("TRINETRA_SCANNER_ADDR", ":8080"), "listen address")
		inputRoot = flag.String("input-root", envOr("TRINETRA_INPUT_ROOT", "/scan-workdir"), "read-only scan input root")
		storeRoot = flag.String("artifact-store", envOr("TRINETRA_ARTIFACT_STORE", "/artifact-store"), "artifact store root")
		rulesRoot = flag.String("rules", envOr("TRINETRA_RULES_ROOT", "/rules"), "rule pack root")
	)
	flag.Parse()

	token := os.Getenv("TRINETRA_SCANNER_TOKEN")
	if len(token) < scannerapi.MinTokenLength {
		return fmt.Errorf("TRINETRA_SCANNER_TOKEN must be set and at least %d characters",
			scannerapi.MinTokenLength)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	registry := engine.NewRegistry(
		// CBOMkit first: where both engines see the same call site, its
		// symbol-resolved key size wins the dedup merge over a pattern match.
		engine.NewCBOMkitEngine(),
		engine.NewSemgrepEngine([]string{
			filepath.Join(*rulesRoot, "crypto"),
			filepath.Join(*rulesRoot, "taint"),
		}),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*storeRoot), *inputRoot)

	// Report engine availability at startup so an operator learns about a
	// missing engine now rather than from a thin inventory later.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, e := range registry.Engines() {
		if err := e.Available(ctx); err != nil {
			logger.Warn("detection engine unavailable",
				"engine", e.Name(), "languages", e.Languages(), "reason", err.Error())
			continue
		}
		logger.Info("detection engine ready",
			"engine", e.Name(), "version", e.Tool().Version, "languages", e.Languages())
	}

	server, err := scannerapi.NewServer(scannerapi.Config{
		Token:          token,
		ScannerName:    "source",
		ScannerVersion: engine.ScannerVersion,
		Logger:         logger,
		Scan:           scanner.Scan,
	})
	if err != nil {
		return err
	}

	logger.Info("scanner-source listening", "addr", *addr, "input_root", *inputRoot)
	return server.ListenAndServe(ctx, *addr)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
