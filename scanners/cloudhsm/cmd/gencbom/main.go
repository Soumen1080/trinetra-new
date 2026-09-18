// Command gencbom writes a cloud/HSM CBOM for a fixture target.
//
// It regenerates the golden document the Python ingest tests read, so those
// tests consume real scanner output. Golden files are reviewed on change, never
// regenerated blindly.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/scanner-cloudhsm/internal/engine"
)

func main() {
	reference := flag.String("ref", "hsm",
		"target reference: hsm[:EXPORT] or aws:REGION[@ENDPOINT]")
	export := flag.String("export", "", "PKCS#11 inventory export")
	region := flag.String("region", "ap-south-1", "default AWS region")
	out := flag.String("out", "", "artifact store root")
	scanID := flag.String("scan-id", "cccccccc-dddd-eeee-ffff-000000000000", "scan id")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr,
			"usage: gencbom -out DIR [-ref hsm|aws:REGION[@ENDPOINT]] [-export FILE]")
		os.Exit(2)
	}

	kms := engine.NewKMSEngine()
	kms.Client = &http.Client{Timeout: 30 * time.Second}
	if !kms.Credentials.IsComplete() {
		// A local emulator accepts any credential; obvious placeholders make it
		// plain in a diff that no real account was involved.
		kms.Credentials = engine.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
	}

	pkcs11 := engine.NewPKCS11Engine()
	if *export != "" {
		pkcs11.ExportPath = *export
	}

	scanner := engine.NewScanner(
		engine.NewRegistry(kms, pkcs11),
		artifactstore.New(*out),
		*region,
	)
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
