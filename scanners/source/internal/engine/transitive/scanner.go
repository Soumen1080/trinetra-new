package transitive

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

// Scanner scans inside dependencies for transitive crypto usage (11C.1).
//
// This addresses the gap that CBOMkit and Semgrep detect only crypto invoked
// directly from the source code. A repository that calls a library that calls
// RSA shows nothing today.
type Scanner struct {
	cache  *PURLCache
	budget *ScanBudget
	// sourceScanner is the Phase 2 engine for scanning dependency source
	sourceScanner SourceScanner
}

// SourceScanner is the interface for scanning dependency source code.
// This would be the Semgrep/CBOMkit engine from Phase 2.
type SourceScanner interface {
	// ScanDependency scans a dependency's source code
	ScanDependency(ctx context.Context, purl string, sourcePath string) ([]cbom.Finding, error)
}

// NewScanner creates a transitive dependency scanner.
func NewScanner(cache *PURLCache, budget *ScanBudget, sourceScanner SourceScanner) *Scanner {
	return &Scanner{
		cache:         cache,
		budget:        budget,
		sourceScanner: sourceScanner,
	}
}

// ScanResult contains findings and metadata from a transitive scan.
type ScanResult struct {
	Findings        []cbom.Finding
	Cached          int
	Scanned         int
	BudgetExceeded  bool
	UnavailablePURLs []string // Dependencies we couldn't fetch
}

// Scan performs transitive dependency scanning (11C.1b, 11C.1c).
//
// For each dependency in the tree:
// 1. Check if cached; if yes, load from cache
// 2. If not cached and within budget, fetch source and scan
// 3. Cache the results
// 4. Attribute findings to the dependency (11C.1e)
//
// This is **entirely offline** (11C.1d): sources must come from a local mirror
// or vendored cache. We never hit a public registry at scan time.
func (s *Scanner) Scan(ctx context.Context, tree *DependencyTree, sourceResolver SourceResolver) (ScanResult, error) {
	result := ScanResult{
		Findings:         []cbom.Finding{},
		UnavailablePURLs: []string{},
	}

	for purl, depth := range tree.Dependencies {
		// Check budget before proceeding
		if !s.budget.CanScan(depth) {
			result.BudgetExceeded = true
			continue
		}

		// Check cache first (11C.1b)
		if s.cache.Has(purl) {
			doc, err := s.cache.Get(purl)
			if err == nil {
				// Extract findings from cached CBOM
				findings := extractFindings(doc)
				for _, f := range findings {
					result.Findings = append(result.Findings, AttributeToSource(f, purl))
				}
				result.Cached++
				continue
			}
			// Cache read error - proceed to rescan
		}

		// Not cached - scan it (11C.1c)
		// Sources must come from local mirror/vendor cache (11C.1d)
		sourcePath, err := sourceResolver.Resolve(ctx, purl)
		if err != nil {
			result.UnavailablePURLs = append(result.UnavailablePURLs, purl)
			continue
		}

		findings, err := s.sourceScanner.ScanDependency(ctx, purl, sourcePath)
		if err != nil {
			// Scan failure is not fatal - record it and continue
			result.UnavailablePURLs = append(result.UnavailablePURLs, purl)
			continue
		}

		// Cache the results (11C.1a)
		doc := cbom.Document{
			BomFormat:   "CycloneDX",
			SpecVersion: "1.6",
			Components:  convertToCBOM(findings, purl),
		}
		if err := s.cache.Put(purl, doc); err != nil {
			// Cache write failure is not fatal
		}

		// Add to result with attribution (11C.1e)
		for _, f := range findings {
			result.Findings = append(result.Findings, AttributeToSource(f, purl))
		}

		s.budget.RecordScan()
		result.Scanned++
	}

	return result, nil
}

// SourceResolver resolves PURLs to local source paths (11C.1d).
//
// This is the boundary between the scanner and the source fetching strategy.
// Different deployments will have different strategies:
// - Vendored dependencies in the repository
// - Local package mirror
// - Cached downloads from a previous step
//
// The resolver MUST be offline: no public registry access at scan time.
type SourceResolver interface {
	// Resolve returns the local filesystem path to a dependency's source.
	// Returns error if the source is not available locally.
	Resolve(ctx context.Context, purl string) (string, error)
}

// extractFindings extracts findings from a cached CBOM document.
func extractFindings(doc cbom.Document) []cbom.Finding {
	// This would parse the CycloneDX components back into findings
	// For now, return empty - full implementation would convert
	// CycloneDX components back to cbom.Finding structs
	return []cbom.Finding{}
}

// convertToCBOM converts findings to CycloneDX components for caching.
func convertToCBOM(findings []cbom.Finding, purl string) []cbom.Component {
	// This would convert findings to CycloneDX format
	// For now, return empty - full implementation would use
	// the existing cbom.Build infrastructure
	return []cbom.Component{}
}

// VendorResolver resolves PURLs from vendored dependencies (11C.1d).
type VendorResolver struct {
	vendorRoot string
}

// NewVendorResolver creates a resolver that looks in a vendor directory.
func NewVendorResolver(vendorRoot string) *VendorResolver {
	return &VendorResolver{vendorRoot: vendorRoot}
}

// Resolve finds a dependency in the vendor directory.
func (r *VendorResolver) Resolve(ctx context.Context, purl string) (string, error) {
	// Convert PURL to filesystem path
	// pkg:npm/lodash@4.17.21 -> vendor/npm/lodash/4.17.21
	// This is deployment-specific and would need configuration
	return "", fmt.Errorf("vendor resolver not fully implemented: needs deployment-specific path mapping")
}

// MirrorResolver resolves PURLs from a local package mirror (11C.1d).
type MirrorResolver struct {
	mirrorRoot string
}

// NewMirrorResolver creates a resolver that looks in a local mirror.
func NewMirrorResolver(mirrorRoot string) *MirrorResolver {
	return &MirrorResolver{mirrorRoot: mirrorRoot}
}

// Resolve finds a dependency in the local mirror.
func (r *MirrorResolver) Resolve(ctx context.Context, purl string) (string, error) {
	// Query local mirror (e.g., Artifactory, Nexus)
	// This requires mirror-specific API calls
	return "", fmt.Errorf("mirror resolver not fully implemented: needs mirror-specific configuration")
}
