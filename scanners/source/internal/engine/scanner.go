package engine

import (
	"context"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
	"github.com/trinetra/cbom-go/targetpath"
)

// ScannerVersion identifies this service in responses and metadata.
const ScannerVersion = "0.2.0"

// Scanner ties the engine registry to the artifact store.
type Scanner struct {
	Registry  *Registry
	Store     *artifactstore.Store
	InputRoot string
	// Now is injected so tests get deterministic timestamps. The CBOM's
	// determinism property depends on the timestamp not being read from the
	// clock inside the builder.
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
//
// Ordering matters here: resolve the path (a security boundary), check for an
// already-published artifact (redelivery safety), run the engines, validate,
// then write.
func (s *Scanner) Scan(ctx context.Context, req scannerapi.ScanRequest) (scannerapi.ScanResponse, error) {
	// Redelivery safety: if a previous attempt already published a CBOM, the
	// immutable artifact stands and the worker resumes at ingest. Re-running
	// would either fail on the immutable write or produce a second document.
	if s.Store.Exists(req.ScanID) {
		return scannerapi.ScanResponse{
			ArtifactReference: s.Store.Reference(req.ScanID),
			FindingCount:      -1, // unknown without re-reading; ingest is authoritative
		}, nil
	}

	root, err := targetpath.Resolve(s.InputRoot, req.TargetReference)
	if err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"invalid_target",
			"the target reference is not a valid location inside the scan root",
			400, err)
	}

	result, tools, err := s.Registry.RunAll(ctx, root)
	if err != nil {
		return scannerapi.ScanResponse{}, scannerapi.NewScanError(
			"no_engine_available",
			"no detection engine was available to run this scan",
			500, err)
	}

	doc := cbom.Build(result.Findings, cbom.BuildOptions{
		ScanID:     req.ScanID,
		TargetName: req.TargetReference,
		Timestamp:  s.Now().UTC().Format(time.RFC3339),
		Tools:      append(trinetraTool(), tools...),
	})

	// Validated in Go before the file is written, and again in Python on
	// ingest. Defence in depth: drift on either side is caught at the boundary.
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

func trinetraTool() []cbom.Tool {
	return []cbom.Tool{{
		Vendor:  "Trinetra",
		Name:    "source-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}}
}

// CoverageReport summarises what was and was not inspected, for the scan
// envelope. Anything the scanner could not see is stated rather than omitted.
type CoverageReport struct {
	FilesScanned int      `json:"files_scanned"`
	Gaps         []Gap    `json:"gaps"`
	Languages    []string `json:"languages_covered"`
}

// Coverage builds the report from a result and the registry's engines.
func (s *Scanner) Coverage(ctx context.Context, result Result) CoverageReport {
	seen := map[string]bool{}
	var languages []string
	for _, e := range s.Registry.Engines() {
		if err := e.Available(ctx); err != nil {
			continue
		}
		for _, lang := range e.Languages() {
			if !seen[lang] {
				seen[lang] = true
				languages = append(languages, lang)
			}
		}
	}
	return CoverageReport{
		FilesScanned: result.FilesScanned,
		Gaps:         result.Gaps,
		Languages:    languages,
	}
}
