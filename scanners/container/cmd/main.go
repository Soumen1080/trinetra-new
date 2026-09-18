// Command scanner-container is Trinetra's deployment-artefact discovery service.
//
// It inspects container images and directories for crypto libraries,
// certificates, key material and declared TLS configuration, and publishes one
// immutable CycloneDX 1.6 CBOM per scan.
//
// Unlike the source scanner, this service sits on `scanner-egress`: it is the
// one service allowed to pull images. That is exactly why it is a separate
// binary — a compromised image pull must not be able to reach the source tree.
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
	"github.com/trinetra/scanner-container/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner-container: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("TRINETRA_SCANNER_ADDR", ":8080"), "listen address")
		inputRoot = flag.String("input-root", envOr("TRINETRA_INPUT_ROOT", "/scan-workdir"), "read-only scan input root")
		storeRoot = flag.String("artifact-store", envOr("TRINETRA_ARTIFACT_STORE", "/artifact-store"), "artifact store root")
		knowledge = flag.String("knowledge", envOr("TRINETRA_KNOWLEDGE_BASE", "/knowledge/crypto-libraries-2026.1.json"), "crypto-library knowledge base")
	)
	flag.Parse()

	token := os.Getenv("TRINETRA_SCANNER_TOKEN")
	if len(token) < scannerapi.MinTokenLength {
		return fmt.Errorf("TRINETRA_SCANNER_TOKEN must be set and at least %d characters",
			scannerapi.MinTokenLength)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// A malformed knowledge base fails at startup, not mid-scan: a profile that
	// silently mis-classifies packages is worse than a service that refuses to
	// start.
	kb, err := engine.LoadKnowledgeBase(*knowledge)
	if err != nil {
		return fmt.Errorf("knowledge base: %w", err)
	}
	logger.Info("knowledge base loaded",
		"version", kb.Version, "libraries", len(kb.Libraries))

	registry := engine.NewRegistry(
		// theia first: where it and our own engines see the same artefact, its
		// layer-attributed record wins the dedup merge.
		engine.NewTheiaEngine(),
		engine.NewSyftEngine(kb),
		engine.NewPKIEngine(),
		engine.NewConfigEngine(),
		// Last: an SBOM asserts components another tool observed, so where it
		// and Syft describe the same package, Syft's first-hand record wins the
		// dedup merge on confidence.
		engine.NewSBOMEngine(kb),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*storeRoot), *inputRoot)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Report engine availability at startup so an operator learns about a
	// missing engine now rather than from a thin inventory later.
	for _, e := range registry.Engines() {
		if err := e.Available(ctx); err != nil {
			logger.Warn("detection engine unavailable",
				"engine", e.Name(), "detects", e.Detects(), "reason", err.Error())
			continue
		}
		logger.Info("detection engine ready",
			"engine", e.Name(), "version", e.Tool().Version, "detects", e.Detects())
	}

	server, err := scannerapi.NewServer(scannerapi.Config{
		Token:          token,
		ScannerName:    "container",
		ScannerVersion: engine.ScannerVersion,
		Logger:         logger,
		Scan:           scanner.Scan,
	})
	if err != nil {
		return err
	}

	logger.Info("scanner-container listening", "addr", *addr, "input_root", *inputRoot)
	return server.ListenAndServe(ctx, *addr)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
