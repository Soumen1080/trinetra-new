package transitive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// PURLCache stores per-PURL CBOMs keyed by purl@version (11C.1a).
//
// A transitive dependency scan multiplies scan time by the dependency count.
// Caching means a dependency scanned once is never scanned again, even across
// different applications.
type PURLCache struct {
	storeRoot string
}

// NewPURLCache creates a cache rooted at the artifact store.
func NewPURLCache(storeRoot string) *PURLCache {
	return &PURLCache{storeRoot: storeRoot}
}

// Get retrieves a cached CBOM for a PURL, if one exists.
func (c *PURLCache) Get(purl string) (cbom.Document, error) {
	path := c.cachePath(purl)
	data, err := os.ReadFile(path)
	if err != nil {
		return cbom.Document{}, fmt.Errorf("cache miss: %w", err)
	}

	var doc cbom.Document
	if err := cbom.Unmarshal(data, &doc); err != nil {
		return cbom.Document{}, fmt.Errorf("unmarshal cached CBOM: %w", err)
	}

	return doc, nil
}

// Put stores a CBOM for a PURL.
func (c *PURLCache) Put(purl string, doc cbom.Document) error {
	path := c.cachePath(purl)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Marshal and write atomically
	data, err := cbom.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal CBOM: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("atomic rename: %w", err)
	}

	return nil
}

// Has checks if a PURL is cached without loading it.
func (c *PURLCache) Has(purl string) bool {
	_, err := os.Stat(c.cachePath(purl))
	return err == nil
}

// cachePath computes the filesystem path for a PURL.
//
// PURLs can contain characters unsafe for filenames, so we hash them.
// Format: <store>/purl-cache/<first-2-hex>/<hash>.cbom
func (c *PURLCache) cachePath(purl string) string {
	hash := sha256.Sum256([]byte(purl))
	hex := hex.EncodeToString(hash[:])

	return filepath.Join(c.storeRoot, "purl-cache", hex[:2], hex+".cbom")
}

// DependencyTree represents a resolved dependency tree.
type DependencyTree struct {
	// Root is the application being scanned
	Root string
	// Dependencies maps PURL to depth in the tree (0 = direct dependency)
	Dependencies map[string]int
}

// ResolveDependencies extracts PURLs from a Syft CBOM and builds a dependency tree.
//
// This is Phase 11C.1b: resolve the dependency tree from Syft output; skip any
// PURL already cached.
func ResolveDependencies(syftCBOM cbom.Document, maxDepth int) (*DependencyTree, error) {
	tree := &DependencyTree{
		Dependencies: make(map[string]int),
	}

	// Extract PURLs from components
	for _, comp := range syftCBOM.Components {
		if comp.Purl != "" {
			// All Syft components are direct dependencies (depth 0)
			// Full transitive resolution would require fetching and parsing
			// each dependency's own dependency manifest
			tree.Dependencies[comp.Purl] = 0
		}
	}

	return tree, nil
}

// AttributeToSource marks a finding as coming from a dependency, not the application.
//
// This is 11C.1e: attribute transitive findings to the dependency so a reader
// can tell "our code does this" from "something we depend on does this".
func AttributeToSource(finding cbom.Finding, purl string) cbom.Finding {
	// Add dependency attribution to the note
	source := extractPackageName(purl)
	prefix := fmt.Sprintf("From dependency %s: ", source)

	if finding.Note == "" {
		finding.Note = prefix + "transitive crypto usage"
	} else if !strings.HasPrefix(finding.Note, "From dependency") {
		finding.Note = prefix + finding.Note
	}

	// Store the PURL in extra properties for traceability
	if finding.Extra == nil {
		finding.Extra = make(map[string]string)
	}
	finding.Extra["trinetra:source-purl"] = purl
	finding.Extra["trinetra:provenance"] = "transitive-dependency"

	return finding
}

// extractPackageName extracts a human-readable package name from a PURL.
// pkg:npm/lodash@4.17.21 -> lodash@4.17.21
func extractPackageName(purl string) string {
	// PURL format: pkg:type/namespace/name@version
	parts := strings.Split(purl, "/")
	if len(parts) > 0 {
		// Get the last part (name@version)
		last := parts[len(parts)-1]
		// Remove pkg:type/ prefix if present
		if idx := strings.Index(last, ":"); idx >= 0 {
			last = last[idx+1:]
		}
		return last
	}
	return purl
}

// ScanBudget limits the work done in transitive scanning (11C.1f).
type ScanBudget struct {
	MaxDependencies int  // Maximum number of dependencies to scan
	MaxDepth        int  // Maximum depth in the dependency tree
	TimeoutSeconds  int  // Per-dependency scan timeout
	Scanned         int  // Dependencies scanned so far
	Exceeded        bool // Budget exceeded flag
}

// NewScanBudget creates a default budget for transitive scanning.
func NewScanBudget() *ScanBudget {
	return &ScanBudget{
		MaxDependencies: 50,   // Reasonable default
		MaxDepth:        2,    // Direct + one level of transitive
		TimeoutSeconds:  300,  // 5 minutes per dependency
		Scanned:         0,
		Exceeded:        false,
	}
}

// CanScan checks if the budget allows scanning another dependency.
func (b *ScanBudget) CanScan(depth int) bool {
	if b.Exceeded {
		return false
	}
	if depth > b.MaxDepth {
		return false
	}
	if b.Scanned >= b.MaxDependencies {
		b.Exceeded = true
		return false
	}
	return true
}

// RecordScan increments the scanned counter.
func (b *ScanBudget) RecordScan() {
	b.Scanned++
}
