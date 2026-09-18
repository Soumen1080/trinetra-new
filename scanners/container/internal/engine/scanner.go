package engine

import (
	"context"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/cbom-go/targetpath"
)

// ScannerVersion identifies this service in responses and metadata.
const ScannerVersion = "0.1.0"

// imagePrefix marks a target reference as a registry image rather than a path
// inside the shared input volume.
const imagePrefix = "image:"

// Scanner ties the engine registry to the artifact store.
type Scanner struct {
	Registry  *Registry
	Store     *artifactstore.Store
	InputRoot string
	// Now is injected so tests get deterministic timestamps; the CBOM's
	// determinism depends on the timestamp not being read inside the builder.
	Now func() time.Time
}

// NewScanner returns a scanner.
func NewScanner(registry *Registry, store *artifactstore.Store, inputRoot string) *Scanner {
	return &Scanner{
		Registry:  registry,
		Store:     store,
		InputRoot: inputRoot,
		Now:       time.Now,
	}
}

// Scan implements scannerapi.ScanFunc.
func (s *Scanner) Scan(ctx context.Context, req scannerapi.ScanRequest) (scannerapi.ScanResponse, error) {
	// Redelivery safety: an immutable artifact from a previous attempt stands,
	// and the worker resumes at ingest rather than overwriting it.
	if s.Store.Exists(req.ScanID) {
		return scannerapi.ScanResponse{
			ArtifactReference: s.Store.Reference(req.ScanID),
			FindingCount:      -1, // ingest is authoritative
		}, nil
	}

	target, err := s.resolveTarget(req.TargetReference)
	if err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"invalid_target",
			"the target reference is not a valid image or a location inside the scan root",
			400, err)
	}

	result, tools, err := s.Registry.RunAll(ctx, target)
	if err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"no_engine_available",
			"no detection engine was available for this target",
			500, err)
	}

	doc := cbom.Build(result.Findings, cbom.BuildOptions{
		ScanID:     req.ScanID,
		TargetName: req.TargetReference,
		Timestamp:  s.Now().UTC().Format(time.RFC3339),
		Tools:      append(trinetraTool(), tools...),
	})

	// Validated in Go before the write, and again in Python on ingest.
	if err := cbom.Validate(doc); err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"invalid_cbom",
			"the generated document failed validation and was not published",
			500, err)
	}

	data, err := cbom.Marshal(doc)
	if err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"marshal_failed", "the document could not be serialised", 500, err)
	}

	if _, err := s.Store.WriteCBOM(req.ScanID, data); err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"write_failed", "the document could not be published", 500, err)
	}

	return scannerapi.ScanResponse{
		ArtifactReference: s.Store.Reference(req.ScanID),
		FindingCount:      len(doc.Components),
	}, nil
}

// resolveTarget decides whether a reference names an image or a path.
//
// An image reference is passed through untouched — it is a registry coordinate,
// not a filesystem location. A path is resolved against the input root, which is
// a security boundary: the reference arrives over HTTP.
func (s *Scanner) resolveTarget(reference string) (Target, error) {
	if rest, found := strings.CutPrefix(reference, imagePrefix); found {
		trimmed := strings.TrimSpace(rest)
		if trimmed == "" {
			return Target{}, targetpath.ErrEmpty
		}
		return Target{ImageReference: trimmed}, nil
	}

	path, err := targetpath.Resolve(s.InputRoot, reference)
	if err != nil {
		return Target{}, err
	}
	return Target{Path: path}, nil
}

func trinetraTool() []cbom.Tool {
	return []cbom.Tool{{
		Vendor:  "Trinetra",
		Name:    "container-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}}
}
