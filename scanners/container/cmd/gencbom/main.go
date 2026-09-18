// Command gencbom writes a container-scanner CBOM for a fixture tree.
//
// It regenerates the golden document the Python ingest tests read, so those
// tests consume real scanner output rather than a hand-written approximation.
// Golden files are reviewed on change, never regenerated blindly.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/scanner-container/internal/engine"
)

func main() {
	inputRoot := flag.String("input-root", "", "read-only scan input root")
	reference := flag.String("ref", "", "target reference within the input root")
	knowledge := flag.String("knowledge", "", "crypto-library knowledge base")
	out := flag.String("out", "", "artifact store root")
	scanID := flag.String("scan-id", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "scan id")
	flag.Parse()

	if *inputRoot == "" || *reference == "" || *knowledge == "" || *out == "" {
		fmt.Fprintln(os.Stderr,
			"usage: gencbom -input-root DIR -ref NAME -knowledge FILE -out DIR")
		os.Exit(2)
	}

	kb, err := engine.LoadKnowledgeBase(*knowledge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "knowledge base: %v\n", err)
		os.Exit(1)
	}

	registry := engine.NewRegistry(
		engine.NewSyftEngine(kb),
		engine.NewPKIEngine(),
		engine.NewConfigEngine(),
	)

	scanner := engine.NewScanner(registry, artifactstore.New(*out), *inputRoot)
	// Fixed clock so the golden file is stable across regenerations.
	scanner.Now = func() time.Time {
		return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC)
	}

	response, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          *scanID,
		TargetReference: *reference,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s findings=%d\n", response.ArtifactReference, response.FindingCount)
}
