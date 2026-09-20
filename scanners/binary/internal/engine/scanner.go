package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/cbom-go/targetpath"
)

// Scanner orchestrates the engines and produces the final CBOM.
type Scanner struct {
	registry  *Registry
	store     *artifactstore.Store
	inputRoot string
}

// NewScanner builds a scanner.
func NewScanner(registry *Registry, store *artifactstore.Store, inputRoot string) *Scanner {
	return &Scanner{
		registry:  registry,
		store:     store,
		inputRoot: inputRoot,
	}
}

// Scan implements the scannerapi.ScanFunc contract.
func (s *Scanner) Scan(ctx context.Context, req scannerapi.ScanRequest) (scannerapi.ScanResponse, error) {
	// Resolve and validate the target path
	resolved, err := targetpath.Resolve(s.inputRoot, req.TargetRef)
	if err != nil {
		return scannerapi.ScanResponse{}, fmt.Errorf("target path: %w", err)
	}

	// Check if this exact scan already exists
	existing, err := s.store.Get(req.ScanID)
	if err == nil {
		return scannerapi.ScanResponse{
			ScanID:   req.ScanID,
			Status:   "completed",
			Location: existing,
		}, nil
	}

	// Run the engines
	result, tools, err := s.registry.RunAll(ctx, resolved)
	if err != nil {
		return scannerapi.ScanResponse{}, fmt.Errorf("engines: %w", err)
	}

	// Build the CBOM
	doc := cbom.Build(result.Findings, cbom.BuildOptions{
		ScanID:       req.ScanID,
		TargetRef:    req.TargetRef,
		Timestamp:    time.Now().UTC(),
		Tools:        tools,
		Gaps:         convertGaps(result.Gaps),
		ScannerName:  "binary",
		ScannerVer:   ScannerVersion,
		FilesScanned: result.FilesScanned,
	})

	// Validate before storing
	if err := cbom.Validate(doc); err != nil {
		return scannerapi.ScanResponse{}, fmt.Errorf("validation: %w", err)
	}

	// Store it
	location, err := s.store.Put(req.ScanID, doc)
	if err != nil {
		return scannerapi.ScanResponse{}, fmt.Errorf("store: %w", err)
	}

	return scannerapi.ScanResponse{
		ScanID:   req.ScanID,
		Status:   "completed",
		Location: location,
		Findings: len(result.Findings),
		Gaps:     len(result.Gaps),
	}, nil
}

func convertGaps(gaps []Gap) []cbom.Gap {
	out := make([]cbom.Gap, len(gaps))
	for i, g := range gaps {
		out[i] = cbom.Gap{
			Path:   g.Path,
			Kind:   g.Kind,
			Reason: g.Reason,
			Count:  g.Count,
		}
	}
	return out
}
