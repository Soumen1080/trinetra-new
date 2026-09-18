package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

const testScanID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

// newFixtureScanner stages a realistic deployment tree inside an input root, so
// the scanner exercises the same path-resolution boundary it uses in production.
func newFixtureScanner(t *testing.T) (*Scanner, string) {
	t.Helper()

	inputRoot := t.TempDir()
	target := filepath.Join(inputRoot, "image-rootfs")

	certDir := filepath.Join(target, "etc", "ssl", "certs")
	keyDir := filepath.Join(target, "etc", "ssl", "private")
	confDir := filepath.Join(target, "etc", "nginx")
	appDir := filepath.Join(target, "opt", "app")

	for _, dir := range []string{certDir, keyDir, confDir, appDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	writeRSACertificate(t, certDir, 2048)
	writeECCertificate(t, certDir)
	writeFile(t, confDir, "nginx.conf", nginxConfig)
	writeFile(t, appDir, "requirements.txt", "cryptography==41.0.7\nrequests==2.31.0\n")

	registry := NewRegistry(
		NewSyftEngine(loadKB(t)),
		NewPKIEngine(),
		NewConfigEngine(),
	)

	scanner := NewScanner(registry, artifactstore.New(t.TempDir()), inputRoot)
	// Fixed clock: determinism depends on the timestamp not coming from the
	// wall clock.
	scanner.Now = func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }

	return scanner, "image-rootfs"
}

func readPublished(t *testing.T, scanner *Scanner) cbom.Document {
	t.Helper()
	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read published cbom: %v", err)
	}
	var doc cbom.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("published document is not valid json: %v", err)
	}
	return doc
}

// The Phase 3 exit criterion: a deployment tree yields library, certificate and
// key artefacts, all with empty algorithm on libraries and no secret material.
func TestScanDeploymentTreeProducesValidCBOM(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	response, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: reference,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if response.FindingCount == 0 {
		t.Fatal("the deployment fixture produced no findings")
	}

	doc := readPublished(t, scanner)
	if err := cbom.Validate(doc); err != nil {
		t.Fatalf("published document failed validation: %v", err)
	}

	types := map[string]int{}
	for _, component := range doc.Components {
		types[component.CryptoProperties.AssetType]++
	}

	if types["certificate"] < 2 {
		t.Errorf("expected at least 2 certificates, got %d", types["certificate"])
	}
	if types["related-crypto-material"] < 1 {
		t.Errorf("expected at least one key artefact, got %d", types["related-crypto-material"])
	}
	if types["protocol"] < 1 {
		t.Errorf("expected at least one declared protocol, got %d", types["protocol"])
	}

	t.Logf("deployment fixture: %d components %v", len(doc.Components), types)
}

// A library component must never carry algorithmProperties. Enforced in
// Normalise, in Validate, and asserted here on the published document.
func TestPublishedLibrariesCarryNoAlgorithm(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, component := range readPublished(t, scanner).Components {
		if component.CryptoProperties.AssetType != "library" {
			continue
		}
		if component.CryptoProperties.AlgorithmProperties != nil {
			t.Errorf("library %q published algorithmProperties", component.Name)
		}
	}
}

// The single most important property of this scanner.
func TestPublishedDocumentContainsNoSecretMaterial(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, forbidden := range []string{
		"PRIVATE KEY-----",
		"BEGIN RSA PRIVATE",
		"BEGIN EC PRIVATE",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("published document contains %q", forbidden)
		}
	}
}

// Determinism means the same INPUT yields the same document. Each call to
// newFixtureScanner generates fresh certificates, so scanning two fixtures
// would compare different inputs; the same tree is scanned twice instead.
func TestScanIsDeterministic(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	first, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read first: %v", err)
	}

	// A second scanner over the same input tree, with its own artifact store so
	// the immutable-write guard does not short-circuit the run.
	rescan := NewScanner(scanner.Registry, artifactstore.New(t.TempDir()), scanner.InputRoot)
	rescan.Now = scanner.Now

	if _, err := rescan.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	second, err := os.ReadFile(rescan.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read second: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("two scans of identical input produced different documents")
	}
}

// Path resolution is a security boundary: the reference arrives over HTTP.
func TestScanRejectsTraversal(t *testing.T) {
	scanner, _ := newFixtureScanner(t)

	_, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: "../../../etc",
	})
	if err == nil {
		t.Fatal("expected a traversal reference to be rejected")
	}

	var scanErr *scannerapi.ScanError
	if !errors.As(err, &scanErr) {
		t.Fatalf("expected a ScanError, got %T", err)
	}
	if scanErr.Code != "invalid_target" {
		t.Errorf("code = %q, want invalid_target", scanErr.Code)
	}
	if strings.Contains(scanErr.Message, "etc") {
		t.Errorf("error message echoed the target: %q", scanErr.Message)
	}
}

// An image reference is a registry coordinate, not a filesystem path, so it
// must not be resolved against the input root.
func TestImageReferencesAreNotPathResolved(t *testing.T) {
	scanner, _ := newFixtureScanner(t)

	target, err := scanner.resolveTarget("image:registry.example.org/app:1.2.3")
	if err != nil {
		t.Fatalf("image reference rejected: %v", err)
	}
	if !target.IsImage() {
		t.Error("image reference was not recognised as an image")
	}
	if target.ImageReference != "registry.example.org/app:1.2.3" {
		t.Errorf("image reference = %q", target.ImageReference)
	}
	if target.Path != "" {
		t.Errorf("image target acquired a filesystem path: %q", target.Path)
	}
}

func TestEmptyImageReferenceIsRejected(t *testing.T) {
	scanner, _ := newFixtureScanner(t)
	if _, err := scanner.resolveTarget("image:   "); err == nil {
		t.Error("an empty image reference was accepted")
	}
}

// An engine that cannot handle a target kind becomes a visible gap, so an image
// scan never silently loses certificate detection.
func TestFilesystemEnginesReportGapsOnImageTargets(t *testing.T) {
	registry := NewRegistry(NewPKIEngine(), NewConfigEngine(), NewSyftEngine(loadKB(t)))

	result, _, err := registry.RunAll(context.Background(),
		Target{ImageReference: "alpine:3.19"})

	// Syft may or may not be able to reach a registry here; what must hold is
	// that the filesystem engines reported why they were skipped.
	var notApplicable int
	for _, gap := range result.Gaps {
		if gap.Kind == "engine_not_applicable" {
			notApplicable++
			if !strings.Contains(gap.Reason, "cannot inspect a registry image") {
				t.Errorf("gap does not explain itself: %q", gap.Reason)
			}
		}
	}
	if notApplicable != 2 {
		t.Errorf("expected 2 not-applicable gaps (pki, config), got %d: %+v",
			notApplicable, result.Gaps)
	}
	_ = err // a registry failure is acceptable in this environment
}

// Redelivery safety: an immutable artifact from a previous attempt stands.
func TestScanResumesWhenArtifactAlreadyPublished(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	if _, err := scanner.Store.WriteCBOM(testScanID, []byte(`{"pre":"existing"}`)); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("a redelivered scan must succeed: %v", err)
	}

	data, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != `{"pre":"existing"}` {
		t.Error("the existing immutable artifact was overwritten")
	}
}

// A clean deployment tree is a valid result, not an error.
func TestScanCleanTreePublishesEmptyDocument(t *testing.T) {
	inputRoot := t.TempDir()
	target := filepath.Join(inputRoot, "clean")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, target, "README.md", "# Nothing cryptographic here\n")

	scanner := NewScanner(
		NewRegistry(NewPKIEngine(), NewConfigEngine()),
		artifactstore.New(t.TempDir()),
		inputRoot,
	)
	scanner.Now = func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }

	response, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "clean",
	})
	if err != nil {
		t.Fatalf("a clean tree must scan successfully: %v", err)
	}
	if response.FindingCount != 0 {
		t.Errorf("clean tree produced %d findings", response.FindingCount)
	}

	if err := cbom.Validate(readPublished(t, scanner)); err != nil {
		t.Errorf("empty document failed validation: %v", err)
	}
}

// Every contributing tool must be recorded, or the CBOM is not an audit
// artefact.
func TestPublishedDocumentRecordsEveryTool(t *testing.T) {
	scanner, reference := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: reference,
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	names := map[string]bool{}
	for _, tool := range readPublished(t, scanner).Metadata.Tools {
		names[tool.Name] = true
		if tool.Version == "" {
			t.Errorf("tool %q has no version", tool.Name)
		}
	}

	if !names["container-scanner"] {
		t.Error("the scanner itself is not recorded in metadata.tools")
	}
	for _, expected := range []string{"pki-scanner", "config-scanner"} {
		if !names[expected] {
			t.Errorf("%s ran but is not recorded in metadata.tools", expected)
		}
	}
}
