package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

// Scanner orchestrates the engines and produces the final CBOM.
type Scanner struct {
	registry *Registry
	store    *artifactstore.Store
}

// NewScanner builds a scanner.
func NewScanner(registry *Registry, store *artifactstore.Store) *Scanner {
	return &Scanner{registry: registry, store: store}
}

// Scan implements the scannerapi.ScanFunc contract.
func (s *Scanner) Scan(ctx context.Context, req scannerapi.ScanRequest) (scannerapi.ScanResponse, error) {
	// The endpoint is passed in the TargetRef field
	endpoint := req.TargetRef
	if endpoint == "" {
		return scannerapi.ScanResponse{}, fmt.Errorf("target_ref must specify an endpoint (e.g., example.com:443)")
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
	result, tools, err := s.registry.RunAll(ctx, endpoint)
	if err != nil {
		return scannerapi.ScanResponse{}, fmt.Errorf("engines: %w", err)
	}

	// Build the CBOM
	doc := cbom.Build(result.Findings, cbom.BuildOptions{
		ScanID:       req.ScanID,
		TargetRef:    endpoint,
		Timestamp:    time.Now().UTC(),
		Tools:        tools,
		Gaps:         convertGaps(result.Gaps),
		ScannerName:  "egress",
		ScannerVer:   ScannerVersion,
		FilesScanned: 0, // Not file-based
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
			Path:   g.Endpoint,
			Kind:   g.Kind,
			Reason: g.Reason,
			Count:  g.Count,
		}
	}
	return out
}
