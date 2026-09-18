package engine

import (
	"context"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

// ScannerVersion identifies this service in responses and metadata.
const ScannerVersion = "0.1.0"

// Scanner ties the engine registry to the artifact store.
type Scanner struct {
	Registry *Registry
	Store    *artifactstore.Store
	// DefaultRegion is used when a target reference names no region.
	DefaultRegion string
	// Now is injected so tests get deterministic timestamps.
	Now func() time.Time
}

// NewScanner returns a scanner.
func NewScanner(registry *Registry, store *artifactstore.Store, defaultRegion string) *Scanner {
	return &Scanner{
		Registry:      registry,
		Store:         store,
		DefaultRegion: defaultRegion,
		Now:           time.Now,
	}
}

// Scan implements scannerapi.ScanFunc.
func (s *Scanner) Scan(ctx context.Context, req scannerapi.ScanRequest) (scannerapi.ScanResponse, error) {
	// Redelivery safety: an immutable artifact from a previous attempt stands.
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
			"the target reference is not a recognised cloud account or HSM token",
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

// resolveTarget parses a target reference.
//
// There is no filesystem path here, so no traversal boundary: the reference
// names an account, a region or a token. Accepted forms:
//
//	aws:ap-south-1      an AWS region
//	aws                 AWS in the scanner's default region
//	hsm                 the configured PKCS#11 inventory export
//	hsm:/path/export    a specific export
func (s *Scanner) resolveTarget(reference string) (Target, error) {
	trimmed := strings.TrimSpace(reference)
	if trimmed == "" {
		return Target{}, errEmptyTarget
	}

	scheme, rest, _ := strings.Cut(trimmed, ":")
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	rest = strings.TrimSpace(rest)

	switch scheme {
	case "aws":
		// An optional endpoint follows the region after '@'. A private-cloud
		// deployment or an on-premise KMS-compatible service needs this, and it
		// is also what lets a test point at a local emulator.
		region, endpoint, _ := strings.Cut(rest, "@")
		region = strings.TrimSpace(region)
		if region == "" {
			region = s.DefaultRegion
		}
		return Target{
			Provider: "aws",
			Region:   region,
			Endpoint: strings.TrimSpace(endpoint),
		}, nil

	case "hsm", "pkcs11":
		return Target{Provider: "pkcs11", ModulePath: rest}, nil

	default:
		return Target{}, errUnknownTarget
	}
}

func trinetraTool() []cbom.Tool {
	return []cbom.Tool{{
		Vendor:  "Trinetra",
		Name:    "cloudhsm-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}}
}

type targetError string

func (e targetError) Error() string { return string(e) }

const (
	errEmptyTarget   = targetError("target reference is empty")
	errUnknownTarget = targetError("target reference must start with aws: or hsm:")
)
