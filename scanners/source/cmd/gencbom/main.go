// Command gencbom writes a CBOM for a fixture directory.
//
// It regenerates the golden documents the Python ingest tests read, so those
// tests consume real scanner output rather than a hand-written approximation
// that can drift from what the scanner actually emits.
//
// Golden files are reviewed on change, never regenerated blindly: a rule edit
// that quietly alters unrelated output is exactly what the diff is for.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/scanner-source/internal/engine"
)

func main() {
	inputRoot := flag.String("input-root", "", "read-only scan input root")
	ref := flag.String("ref", "", "target reference within the input root")
	rules := flag.String("rules", "", "rule pack root")
	out := flag.String("out", "", "artifact store root")
	scanID := flag.String("scan-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "scan id")
	flag.Parse()

	if *inputRoot == "" || *ref == "" || *rules == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: gencbom -input-root DIR -ref NAME -rules DIR -out DIR")
		os.Exit(2)
	}

	registry := engine.NewRegistry(engine.NewSemgrepEngine([]string{
		filepath.Join(*rules, "crypto"),
		filepath.Join(*rules, "taint"),
	}))

	scanner := engine.NewScanner(registry, artifactstore.New(*out), *inputRoot)
	// Fixed clock so the golden file is stable across regenerations.
	scanner.Now = func() time.Time {
		return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC)
	}

	resp, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          *scanID,
		TargetReference: *ref,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s findings=%d\n", resp.ArtifactReference, resp.FindingCount)
}
