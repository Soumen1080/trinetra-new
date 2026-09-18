package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trinetra/cbom-go/artifactstore"
	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

const testScanID = "cccccccc-dddd-eeee-ffff-000000000000"

// localStackEndpoint is where a local KMS emulator listens. Set
// TRINETRA_TEST_KMS_ENDPOINT to point the live tests elsewhere.
func localStackEndpoint() string {
	if endpoint := os.Getenv("TRINETRA_TEST_KMS_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:4566"
}

// requireLocalKMS skips unless a KMS emulator is reachable. These tests are the
// only place the AWS path runs against a real API implementation rather than a
// stub, so they must run wherever one exists and skip cleanly where none does.
func requireLocalKMS(t *testing.T) string {
	t.Helper()
	endpoint := localStackEndpoint()

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(endpoint + "/_localstack/health")
	if err != nil {
		t.Skipf("no local KMS emulator at %s", endpoint)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Skipf("KMS emulator at %s is not healthy", endpoint)
	}
	return endpoint
}

func liveKMSEngine(t *testing.T) (*KMSEngine, Target) {
	t.Helper()
	endpoint := requireLocalKMS(t)

	return &KMSEngine{
		Credentials: testCredentials,
		Client:      &http.Client{Timeout: 20 * time.Second},
	}, Target{
		Provider: "aws",
		Region:   "ap-south-1",
		Endpoint: endpoint,
	}
}

// The Phase 4 exit criterion, AWS half: a KMS account yields cloud_service
// artefacts with no secret material anywhere in the output.
func TestLiveKMSInventoriesRealKeys(t *testing.T) {
	engine, target := liveKMSEngine(t)

	result, err := engine.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("live scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Skip("the emulator has no keys; create some to exercise this test")
	}

	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetCloudService {
			t.Errorf("%q is not a cloud-service artefact", finding.Name)
		}
		if finding.Location.Path == "" {
			t.Errorf("%q has no resource identifier", finding.Name)
		}
		if !strings.HasPrefix(finding.Location.Path, "aws/kms/") {
			t.Errorf("resource path = %q, want an aws/kms/ identifier", finding.Location.Path)
		}
	}

	t.Logf("live KMS: %d keys inventoried", len(result.Findings))
}

// The key spec must survive the real API, not just the stub: it is what makes
// RSA_2048 legible as Shor-breakable.
func TestLiveKMSResolvesKeySpecs(t *testing.T) {
	engine, target := liveKMSEngine(t)

	result, err := engine.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("live scan: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Skip("the emulator has no keys")
	}

	specs := map[string]bool{}
	for _, finding := range result.Findings {
		if finding.ParameterSet != "" {
			specs[finding.ParameterSet] = true
		}
	}
	if len(specs) == 0 {
		t.Fatal("no key spec survived the real API")
	}
	t.Logf("specs observed: %v", keysOfBool(specs))
}

// Credentials must never reach the published document.
func TestLiveKMSFindingsCarryNoCredentials(t *testing.T) {
	engine, target := liveKMSEngine(t)

	result, err := engine.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("live scan: %v", err)
	}

	serialised, err := json.Marshal(result.Findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{
		"AWS4-HMAC", "Authorization", "SecretAccessKey", "x-amz-security-token",
	} {
		if strings.Contains(string(serialised), forbidden) {
			t.Errorf("findings contain %q", forbidden)
		}
	}
}

// newFixtureScanner wires a scanner with both engines over a temp store.
func newFixtureScanner(t *testing.T) *Scanner {
	t.Helper()

	exportPath := filepath.Join(t.TempDir(), "hsm.json")
	if err := os.WriteFile(exportPath, []byte(hsmExport), 0o644); err != nil {
		t.Fatalf("write export: %v", err)
	}

	registry := NewRegistry(
		&KMSEngine{Credentials: testCredentials, Client: &http.Client{Timeout: 10 * time.Second}},
		&PKCS11Engine{ExportPath: exportPath},
	)

	scanner := NewScanner(registry, artifactstore.New(t.TempDir()), "ap-south-1")
	scanner.Now = func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }
	return scanner
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

// The Phase 4 exit criterion, HSM half.
func TestScanHSMTargetProducesValidCBOM(t *testing.T) {
	scanner := newFixtureScanner(t)

	response, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: "hsm",
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if response.FindingCount == 0 {
		t.Fatal("the HSM export produced no findings")
	}

	doc := readPublished(t, scanner)
	if err := cbom.Validate(doc); err != nil {
		t.Fatalf("published document failed validation: %v", err)
	}

	types := map[string]int{}
	for _, component := range doc.Components {
		types[component.CryptoProperties.AssetType]++
	}
	// Hardware modules and keys both map to related-crypto-material on the
	// wire; the trinetra:asset-type property disambiguates them on ingest.
	if types["related-crypto-material"] == 0 {
		t.Errorf("expected hardware-module and key artefacts, got %v", types)
	}

	t.Logf("hsm export: %d components %v", len(doc.Components), types)
}

// Hardware modules and cloud services share one CycloneDX spelling, so the
// disambiguating property must be present or they ingest as the wrong type.
func TestHardwareModulesCarryTheAssetTypeHint(t *testing.T) {
	scanner := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var hardware int
	for _, component := range readPublished(t, scanner).Components {
		for _, property := range component.Properties {
			if property.Name == cbom.TrinetraAssetTypeProperty &&
				property.Value == string(cbom.AssetHardwareModule) {
				hardware++
			}
		}
	}
	if hardware == 0 {
		t.Error("no component carries the hardware_module asset-type hint")
	}
}

// No secret material anywhere in the published document.
func TestPublishedDocumentContainsNoSecretMaterial(t *testing.T) {
	scanner := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	raw, err := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, forbidden := range []string{
		"CKA_VALUE", "PRIVATE KEY-----", "SecretAccessKey", "AWS4-HMAC",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("published document contains %q", forbidden)
		}
	}
}

func TestScanIsDeterministic(t *testing.T) {
	first := newFixtureScanner(t)
	if _, err := first.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
	}); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	second := NewScanner(first.Registry, artifactstore.New(t.TempDir()), first.DefaultRegion)
	second.Now = first.Now
	if _, err := second.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
	}); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	a, _ := os.ReadFile(first.Store.CBOMPath(testScanID))
	b, _ := os.ReadFile(second.Store.CBOMPath(testScanID))

	if !bytes.Equal(a, b) {
		t.Error("two scans of identical input produced different documents")
	}
}

func TestTargetReferenceParsing(t *testing.T) {
	scanner := newFixtureScanner(t)

	cases := []struct {
		reference string
		provider  string
		region    string
		module    string
	}{
		{"aws:eu-west-1", "aws", "eu-west-1", ""},
		{"aws", "aws", "ap-south-1", ""}, // falls back to the default region
		{"hsm", "pkcs11", "", ""},
		{"hsm:/exports/hsm-01.json", "pkcs11", "", "/exports/hsm-01.json"},
		{"pkcs11:/exports/x.json", "pkcs11", "", "/exports/x.json"},
	}

	for _, tc := range cases {
		t.Run(tc.reference, func(t *testing.T) {
			target, err := scanner.resolveTarget(tc.reference)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if target.Provider != tc.provider {
				t.Errorf("provider = %q, want %q", target.Provider, tc.provider)
			}
			if target.Region != tc.region {
				t.Errorf("region = %q, want %q", target.Region, tc.region)
			}
			if target.ModulePath != tc.module {
				t.Errorf("module = %q, want %q", target.ModulePath, tc.module)
			}
		})
	}
}

func TestUnknownTargetReferenceIsRejected(t *testing.T) {
	scanner := newFixtureScanner(t)

	for _, reference := range []string{"", "   ", "gcp:europe-west1", "/etc/passwd"} {
		if _, err := scanner.resolveTarget(reference); err == nil {
			t.Errorf("reference %q was accepted", reference)
		}
	}
}

// A client-facing error must not echo the target or any internal detail.
func TestScanErrorsDoNotLeakInternals(t *testing.T) {
	scanner := newFixtureScanner(t)

	_, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID:          testScanID,
		TargetReference: "gcp:secret-project-name",
	})
	if err == nil {
		t.Fatal("expected an unknown target to be rejected")
	}

	var scanErr *scannerapi.ScanError
	if !errors.As(err, &scanErr) {
		t.Fatalf("expected a ScanError, got %T", err)
	}
	if strings.Contains(scanErr.Message, "secret-project-name") {
		t.Errorf("error message echoed the target: %q", scanErr.Message)
	}
}

// Redelivery safety.
func TestScanResumesWhenArtifactAlreadyPublished(t *testing.T) {
	scanner := newFixtureScanner(t)

	if _, err := scanner.Store.WriteCBOM(testScanID, []byte(`{"pre":"existing"}`)); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
	}); err != nil {
		t.Fatalf("a redelivered scan must succeed: %v", err)
	}

	data, _ := os.ReadFile(scanner.Store.CBOMPath(testScanID))
	if string(data) != `{"pre":"existing"}` {
		t.Error("the existing immutable artifact was overwritten")
	}
}

// Every contributing tool must be recorded.
func TestPublishedDocumentRecordsEveryTool(t *testing.T) {
	scanner := newFixtureScanner(t)

	if _, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "hsm",
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

	if !names["cloudhsm-scanner"] {
		t.Error("the scanner itself is not recorded")
	}
	if !names["pkcs11-scanner"] {
		t.Error("the pkcs11 engine ran but is not recorded")
	}
}

// A scan whose only engine is unavailable must fail loudly rather than publish
// an empty inventory that reads as "you have no keys".
func TestScanFailsWhenNoEngineIsAvailable(t *testing.T) {
	scanner := NewScanner(
		NewRegistry(&KMSEngine{}), // no credentials
		artifactstore.New(t.TempDir()),
		"ap-south-1",
	)
	scanner.Now = func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }

	_, err := scanner.Scan(context.Background(), scannerapi.ScanRequest{
		ScanID: testScanID, TargetReference: "aws:ap-south-1",
	})
	if err == nil {
		t.Fatal("expected the scan to fail with no available engine")
	}
	if scanner.Store.Exists(testScanID) {
		t.Error("a failed scan published a document")
	}
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A private-cloud deployment or an on-premise KMS-compatible service needs an
// endpoint override, and it is what lets a test reach a local emulator.
func TestTargetReferenceCarriesEndpoint(t *testing.T) {
	scanner := newFixtureScanner(t)

	target, err := scanner.resolveTarget("aws:ap-south-1@http://localhost:4566")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.Region != "ap-south-1" {
		t.Errorf("region = %q", target.Region)
	}
	if target.Endpoint != "http://localhost:4566" {
		t.Errorf("endpoint = %q", target.Endpoint)
	}

	// Without an override the adapter must use the real AWS endpoint.
	plain, _ := scanner.resolveTarget("aws:eu-west-1")
	if plain.Endpoint != "" {
		t.Errorf("an endpoint appeared without being asked for: %q", plain.Endpoint)
	}
	if got := (&KMSEngine{}).endpointFor(plain); got != "https://kms.eu-west-1.amazonaws.com/" {
		t.Errorf("default endpoint = %q", got)
	}
}
