package engine

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

const testScanID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// repoRoot walks up to the repository root so fixtures resolve regardless of
// where `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "plan.md")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repository root not found")
	return ""
}

func requireSemgrep(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep is not installed; skipping integration test")
	}
}

// newFixtureScanner copies the fixture corpus into an isolated input root, so
// the scanner exercises the same path-resolution boundary it uses in production.
func newFixtureScanner(t *testing.T, fixture string) (*Scanner, string) {
	t.Helper()
	root := repoRoot(t)

	inputRoot := t.TempDir()
	src := filepath.Join(root, "tests", "fixtures", fixture)
	dest := filepath.Join(inputRoot, "target")

	if err := copyTree(src, dest); err != nil {
		t.Fatalf("stage fixture: %v", err)
	}

	registry := NewRegistry(NewSemgrepEngine([]string{
		filepath.Join(root, "rules", "crypto"),
		filepath.Join(root, "rules", "taint"),
	}))

	scanner := NewScanner(registry, artifactstore.New(t.TempDir()), inputRoot)
	// Fixed clock: the determinism property depends on the timestamp not being
	// read from the wall clock.
	scanner.Now = func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }
	return scanner, "target"
}

func copyTree(src, dest string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// The Phase 2 exit criterion: a fixture repo produces a schema-valid CBOM with
// key sizes and modes intact.
func TestScanPositiveFixturesProducesValidCBOM(t *testing.T) {
	requireSemgrep(t)
	scanner, ref := newFixtureScanner(t, "positive")

	resp, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: ref,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if resp.FindingCount == 0 {
		t.Fatal("the positive fixture corpus produced no findings")
	}

	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read published cbom: %v", err)
	}

	doc, err := unmarshalDocument(raw)
	if err != nil {
		t.Fatalf("published document is not valid json: %v", err)
	}
	if err := cbom.Validate(doc); err != nil {
		t.Fatalf("published document failed validation: %v", err)
	}

	// R19: versions and modes must survive to the document. "AES" alone is not
	// an answer.
	var sawKeySize, sawMode bool
	for _, c := range doc.Components {
		if c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		if c.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
			sawKeySize = true
		}
		if c.CryptoProperties.AlgorithmProperties.Mode != "" {
			sawMode = true
		}
	}
	if !sawKeySize {
		t.Error("no component carried a key size; message interpolation may be broken")
	}
	if !sawMode {
		t.Error("no component carried a cipher mode")
	}

	t.Logf("positive corpus: %d components", len(doc.Components))
}

// Negative fixtures must produce ZERO findings. This is the false-positive
// guard: a rule matching a bare identifier would fire on `rsa = "some string"`.
func TestScanNegativeFixturesProducesNoFindings(t *testing.T) {
	requireSemgrep(t)
	scanner, ref := newFixtureScanner(t, "negative")

	resp, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: ref,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if resp.FindingCount != 0 {
		raw, _ := os.ReadFile(scanner.Store.CBOMPath(testScanID))
		t.Errorf("negative fixtures produced %d findings (want 0):\n%s",
			resp.FindingCount, raw)
	}

	// An empty result is still a valid, published document: a repository
	// genuinely free of cryptography is a real answer, not an error.
	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("an empty scan must still publish a document: %v", err)
	}
	doc, err := unmarshalDocument(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := cbom.Validate(doc); err != nil {
		t.Errorf("empty document failed validation: %v", err)
	}
}

// Determinism: the same input must yield a byte-identical document, or golden
// diffs are meaningless.
func TestScanIsDeterministic(t *testing.T) {
	requireSemgrep(t)

	first, firstRef := newFixtureScanner(t, "positive")
	if _, err := first.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: firstRef,
	}); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	a, err := os.ReadFile(first.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read first: %v", err)
	}

	second, secondRef := newFixtureScanner(t, "positive")
	if _, err := second.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: secondRef,
	}); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	b, err := os.ReadFile(second.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read second: %v", err)
	}

	if !bytes.Equal(a, b) {
		t.Error("two scans of identical input produced different documents")
	}
}

// Taint evidence is what gives Mosca's X its scanner-evidence tier.
func TestScanAttachesDataCategoryFromTaint(t *testing.T) {
	requireSemgrep(t)
	scanner, ref := newFixtureScanner(t, "positive")

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: ref,
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Contains(raw, []byte(cbom.TrinetraDataCategoryProperty)) {
		t.Error("no data-category property was attached; taint rules may not be running")
	}
}

// Path resolution is a security boundary: the reference arrives over HTTP.
func TestScanRejectsTraversal(t *testing.T) {
	scanner, _ := newFixtureScanner(t, "positive")

	_, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: "../../../etc",
	})
	if err == nil {
		t.Fatal("expected a traversal reference to be rejected")
	}

	var scanErr *scannerapi.ScanError
	if !asScanError(err, &scanErr) {
		t.Fatalf("expected a ScanError, got %T", err)
	}
	if scanErr.Code != "invalid_target" {
		t.Errorf("code = %q, want invalid_target", scanErr.Code)
	}
	// The client-facing message must not echo the rejected path or any host
	// path back to the caller.
	if bytes.Contains([]byte(scanErr.Message), []byte("etc")) {
		t.Errorf("error message leaked the target: %q", scanErr.Message)
	}
}

// Redelivery safety: a retried scan must not overwrite an immutable artifact.
func TestScanResumesWhenArtifactAlreadyPublished(t *testing.T) {
	scanner, ref := newFixtureScanner(t, "negative")

	if _, err := scanner.Store.WriteCBOM(testScanID, []byte(`{"pre":"existing"}`)); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	resp, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: ref,
	})
	if err != nil {
		t.Fatalf("a redelivered scan must succeed, got: %v", err)
	}
	if resp.ArtifactReference == "" {
		t.Error("no artifact reference returned on redelivery")
	}

	data, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != `{"pre":"existing"}` {
		t.Error("the existing immutable artifact was overwritten")
	}
}

// A scan with no available engine must fail loudly rather than publish an empty
// inventory that looks like a clean repository.
func TestScanFailsWhenNoEngineAvailable(t *testing.T) {
	inputRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(inputRoot, "target"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	unavailable := NewSemgrepEngine(nil)
	unavailable.Binary = "definitely-not-a-real-binary-xyz"

	scanner := NewScanner(NewRegistry(unavailable), artifactstore.New(t.TempDir()), inputRoot)

	_, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "target",
	})
	if err == nil {
		t.Fatal("expected a scan with no engine to fail")
	}
	if scanner.Store.Exists(testScanID) {
		t.Error("a failed scan published a document")
	}
}
