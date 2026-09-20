package transitive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

func TestPURLCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "purl-cache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cache := NewPURLCache(tmpDir)

	purl := "pkg:npm/lodash@4.17.21"

	// Initially not cached
	if cache.Has(purl) {
		t.Error("PURL should not be cached initially")
	}

	// Cache a document
	doc := cbom.Document{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.6",
		SerialNumber: "urn:uuid:test",
	}

	if err := cache.Put(purl, doc); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Now it should be cached
	if !cache.Has(purl) {
		t.Error("PURL should be cached after Put")
	}

	// Retrieve it
	retrieved, err := cache.Get(purl)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.SpecVersion != "1.6" {
		t.Errorf("Retrieved document has wrong spec version: got %q, want 1.6", retrieved.SpecVersion)
	}
}

func TestCachePathHashing(t *testing.T) {
	cache := NewPURLCache("/tmp/test")

	purl1 := "pkg:npm/lodash@4.17.21"
	purl2 := "pkg:npm/lodash@4.17.20"

	path1 := cache.cachePath(purl1)
	path2 := cache.cachePath(purl2)

	// Different PURLs should have different paths
	if path1 == path2 {
		t.Error("Different PURLs should have different cache paths")
	}

	// Paths should be in the purl-cache directory
	if !contains(path1, "purl-cache") {
		t.Errorf("Cache path should contain 'purl-cache': %s", path1)
	}

	// Same PURL should always produce the same path
	if cache.cachePath(purl1) != path1 {
		t.Error("Same PURL should produce consistent cache path")
	}
}

func TestAttributeToSource(t *testing.T) {
	finding := cbom.Finding{
		AssetType: cbom.AssetAlgorithm,
		Name:      "AES",
		Algorithm: "AES-256-GCM",
		Note:      "Original note",
	}

	purl := "pkg:npm/crypto-lib@1.0.0"

	attributed := AttributeToSource(finding, purl)

	// Should have dependency attribution in note
	if !contains(attributed.Note, "From dependency") {
		t.Errorf("Note should contain attribution: %s", attributed.Note)
	}

	// Should preserve original note
	if !contains(attributed.Note, "Original note") {
		t.Errorf("Note should preserve original: %s", attributed.Note)
	}

	// Should have PURL in extra
	if attributed.Extra["trinetra:source-purl"] != purl {
		t.Errorf("Extra should contain source PURL: %v", attributed.Extra)
	}

	if attributed.Extra["trinetra:provenance"] != "transitive-dependency" {
		t.Error("Extra should mark provenance as transitive-dependency")
	}
}

func TestScanBudget(t *testing.T) {
	budget := &ScanBudget{
		MaxDependencies: 3,
		MaxDepth:        1,
	}

	// Can scan within budget
	if !budget.CanScan(0) {
		t.Error("Should be able to scan at depth 0")
	}
	if !budget.CanScan(1) {
		t.Error("Should be able to scan at depth 1")
	}

	// Cannot scan beyond max depth
	if budget.CanScan(2) {
		t.Error("Should not be able to scan at depth 2")
	}

	// Can scan up to max dependencies
	budget.RecordScan()
	if !budget.CanScan(0) {
		t.Error("Should be able to scan 1st dependency")
	}

	budget.RecordScan()
	if !budget.CanScan(0) {
		t.Error("Should be able to scan 2nd dependency")
	}

	budget.RecordScan()
	if !budget.CanScan(0) {
		t.Error("Should be able to scan 3rd dependency")
	}

	// Cannot exceed budget
	budget.RecordScan()
	if budget.CanScan(0) {
		t.Error("Should not be able to scan 4th dependency (over budget)")
	}

	if !budget.Exceeded {
		t.Error("Budget should be marked as exceeded")
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:npm/lodash@4.17.21", "lodash@4.17.21"},
		{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "jackson-databind@2.13.0"},
		{"pkg:pypi/requests@2.28.0", "requests@2.28.0"},
		{"pkg:cargo/serde@1.0.0", "serde@1.0.0"},
	}

	for _, tt := range tests {
		got := extractPackageName(tt.purl)
		if got != tt.want {
			t.Errorf("extractPackageName(%q) = %q, want %q", tt.purl, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
