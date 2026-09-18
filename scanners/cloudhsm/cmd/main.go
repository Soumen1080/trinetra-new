// Command scanner-cloudhsm is Trinetra's cloud and HSM discovery service.
//
// It inventories key-bearing infrastructure — AWS KMS keys and PKCS#11 hardware
// modules — that neither source nor container scanning can reach, because a KMS
// key and an HSM slot leave no trace in a repository or an image.
//
// **It reads metadata and nothing else.** A cloud KMS and an HSM exist so that
// key material never leaves them; a scanner that extracted a key would defeat
// the control it is inventorying. Credentials are never logged, never written to
// the artifact store, and never placed in a finding.
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
	"github.com/trinetra/scanner-cloudhsm/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner-cloudhsm: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("TRINETRA_SCANNER_ADDR", ":8080"), "listen address")
		storeRoot = flag.String("artifact-store", envOr("TRINETRA_ARTIFACT_STORE", "/artifact-store"), "artifact store root")
		region    = flag.String("region", envOr("AWS_REGION", ""), "default AWS region")
	)
	flag.Parse()

	token := os.Getenv("TRINETRA_SCANNER_TOKEN")
	if len(token) < scannerapi.MinTokenLength {
		return fmt.Errorf("TRINETRA_SCANNER_TOKEN must be set and at least %d characters",
			scannerapi.MinTokenLength)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	kms := engine.NewKMSEngine()
	registry := engine.NewRegistry(
		kms,
		engine.NewAzureEngine(),
		engine.NewGCPEngine(),
		engine.NewPKCS11Engine(),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*storeRoot), *region)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Log which credential is in use, redacted. An operator needs to know the
	// scanner picked up the role they expected; nobody needs the secret.
	logger.Info("cloud credentials",
		"aws_key", kms.Credentials.Redacted(),
		"default_region", *region)

	// Startup availability is reported per engine, so a missing credential or
	// absent HSM export is visible now rather than as a thin inventory later.
	probe := engine.Target{Provider: "aws", Region: *region}
	for _, e := range registry.Engines() {
		if err := e.Available(ctx, probe); err != nil {
			logger.Warn("detection engine unavailable",
				"engine", e.Name(), "detects", e.Detects(), "reason", err.Error())
			continue
		}
		logger.Info("detection engine ready",
			"engine", e.Name(), "detects", e.Detects())
	}

	server, err := scannerapi.NewServer(scannerapi.Config{
		Token:          token,
		ScannerName:    "cloudhsm",
		ScannerVersion: engine.ScannerVersion,
		Logger:         logger,
		Scan:           scanner.Scan,
	})
	if err != nil {
		return err
	}

	logger.Info("scanner-cloudhsm listening", "addr", *addr)
	return server.ListenAndServe(ctx, *addr)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
