package cbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func baseOpts() BuildOptions {
	return BuildOptions{
		ScanID:     "11111111-2222-3333-4444-555555555555",
		TargetName: "payments-api",
		Timestamp:  "2026-03-14T10:30:00Z",
		Tools: []Tool{{
			Vendor: "Trinetra", Name: "source-scanner", Version: "0.2.0", Licence: "Apache-2.0",
		}},
	}
}

func sampleFinding() Finding {
	return Finding{
		AssetType:       AssetAlgorithm,
		Name:            "RSA-2048",
		Algorithm:       "rsa",
		Primitive:       PrimitivePKE,
		Purposes:        []Purpose{PurposeKeyEncapsulation},
		KeySizeBits:     IntPtr(2048),
		Location:        Location{Path: "svc/auth.py", Line: 20},
		DetectionMethod: DetectSemgrepPattern,
		Confidence:      ConfidenceHigh,
		RuleID:          "trinetra-python-rsa-generate",
	}
}

// Determinism is what makes golden-CBOM diffs meaningful. Without it, every
// scan produces a different document and a review cannot tell a real change
// from noise.
func TestBuildIsByteIdenticalForIdenticalInput(t *testing.T) {
	findings := []Finding{sampleFinding(), {
		AssetType: AssetAlgorithm, Name: "AES-CBC", Algorithm: "aes",
		Mode: "cbc", Location: Location{Path: "svc/crypto.py", Line: 9},
		DetectionMethod: DetectSemgrepPattern, Confidence: ConfidenceHigh,
	}}

	first, err := Marshal(Build(findings, baseOpts()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Reversed input must still produce the same document: ordering comes from
	// the sort, not from the order engines happened to report findings in.
	reversed := []Finding{findings[1], findings[0]}
	second, err := Marshal(Build(reversed, baseOpts()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("documents differ for identical input:\n%s\n---\n%s", first, second)
	}
}

func TestZeroComponentsIsValid(t *testing.T) {
	doc := Build(nil, baseOpts())
	if err := Validate(doc); err != nil {
		t.Fatalf("an empty document must be valid: %v", err)
	}
	if len(doc.Components) != 0 {
		t.Errorf("expected no components, got %d", len(doc.Components))
	}
}

func TestLibraryFindingsCarryNoAlgorithm(t *testing.T) {
	// The rule that keeps the risk engine honest: OpenSSL being installed
	// proves an implementation exists, not that any algorithm is used.
	f := Finding{
		AssetType: AssetLibrary, Name: "OpenSSL", Algorithm: "rsa",
		KeySizeBits: IntPtr(2048), Mode: "cbc",
		Location:        Location{Path: "go.mod", Line: 4},
		DetectionMethod: DetectDependency, Confidence: ConfidenceHigh,
	}.Normalise()

	if f.Algorithm != "" {
		t.Errorf("library finding kept algorithm %q", f.Algorithm)
	}
	if f.KeySizeBits != nil {
		t.Error("library finding kept a key size")
	}

	doc := Build([]Finding{f}, baseOpts())
	if doc.Components[0].CryptoProperties.AlgorithmProperties != nil {
		t.Error("library component emitted algorithmProperties")
	}
	if err := Validate(doc); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRejectsLibraryWithAlgorithmProperties(t *testing.T) {
	doc := Build([]Finding{sampleFinding()}, baseOpts())
	doc.Components[0].CryptoProperties.AssetType = "library"

	err := Validate(doc)
	if err == nil {
		t.Fatal("expected validation to reject a library with algorithmProperties")
	}
	if !strings.Contains(err.Error(), "library components must not carry") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Absent means unobserved (P3). AES.new(key, MODE_GCM) does not state a key
// size, and the document must not invent one.
func TestUnobservedKeySizeIsOmitted(t *testing.T) {
	f := Finding{
		AssetType: AssetAlgorithm, Name: "AES-GCM", Algorithm: "aes", Mode: "gcm",
		Location:        Location{Path: "svc/crypto.py", Line: 27},
		DetectionMethod: DetectSemgrepPattern, Confidence: ConfidenceHigh,
	}
	doc := Build([]Finding{f}, baseOpts())

	raw, err := Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(TrinetraKeySizeProperty)) {
		t.Error("a key-size property was emitted for an unobserved key size")
	}
	if got := doc.Components[0].CryptoProperties.AlgorithmProperties.ParameterSetIdentifier; got != "" {
		t.Errorf("parameterSetIdentifier should be empty, got %q", got)
	}
}

func TestObservedKeySizeSurvives(t *testing.T) {
	doc := Build([]Finding{sampleFinding()}, baseOpts())
	props := doc.Components[0].CryptoProperties.AlgorithmProperties

	if props.ParameterSetIdentifier != "2048" {
		t.Errorf("parameterSetIdentifier = %q, want 2048", props.ParameterSetIdentifier)
	}
	var found bool
	for _, p := range doc.Components[0].Properties {
		if p.Name == TrinetraKeySizeProperty && p.Value == "2048" {
			found = true
		}
	}
	if !found {
		t.Error("trinetra:key-size-bits property missing")
	}
}

// Two engines finding one asset is corroboration, not duplication. The merge
// must prefer the record that actually observed a key size.
func TestDedupePrefersObservedKeySize(t *testing.T) {
	withoutSize := Finding{
		AssetType: AssetAlgorithm, Name: "RSA-2048", Algorithm: "rsa",
		Location: Location{Path: "svc/auth.py", Line: 20},
		DetectionMethod: DetectSemgrepPattern, Confidence: ConfidenceMedium,
		RuleID: "trinetra-python-rsa-generate",
	}
	withSize := withoutSize
	withSize.KeySizeBits = IntPtr(2048)
	withSize.Confidence = ConfidenceHigh

	doc := Build([]Finding{withoutSize, withSize}, baseOpts())

	if len(doc.Components) != 1 {
		t.Fatalf("expected one merged component, got %d", len(doc.Components))
	}
	if got := doc.Components[0].CryptoProperties.AlgorithmProperties.ParameterSetIdentifier; got != "2048" {
		t.Errorf("merged component lost the key size, got %q", got)
	}
}

func TestPropertiesUseTrinetraNamespace(t *testing.T) {
	// Namespacing is what lets a consumer that does not know Trinetra ignore
	// the extensions safely while the document stays schema-valid.
	doc := Build([]Finding{sampleFinding()}, baseOpts())
	for _, p := range doc.Components[0].Properties {
		if !strings.HasPrefix(p.Name, "trinetra:") {
			t.Errorf("property %q escapes the trinetra namespace", p.Name)
		}
	}
}

func TestValidateRequiresToolMetadata(t *testing.T) {
	// A CBOM that cannot say which version of which tool produced it is not an
	// audit artefact.
	opts := baseOpts()
	opts.Tools = nil
	err := Validate(Build([]Finding{sampleFinding()}, opts))
	if err == nil || !strings.Contains(err.Error(), "metadata.tools") {
		t.Fatalf("expected a tools requirement error, got %v", err)
	}
}

func TestValidateRejectsAbsolutePaths(t *testing.T) {
	// An absolute path would leak the scanner's filesystem layout into evidence
	// that reaches the UI and exported reports.
	doc := Build([]Finding{sampleFinding()}, baseOpts())
	doc.Components[0].Evidence.Occurrences[0].Location = "/home/runner/work/svc/auth.py"

	err := Validate(doc)
	if err == nil || !strings.Contains(err.Error(), "relative to the target root") {
		t.Fatalf("expected an absolute-path rejection, got %v", err)
	}
}

func TestValidateRequiresEvidence(t *testing.T) {
	doc := Build([]Finding{sampleFinding()}, baseOpts())
	doc.Components[0].Evidence = nil

	err := Validate(doc)
	if err == nil || !strings.Contains(err.Error(), "must cite at least one occurrence") {
		t.Fatalf("expected an evidence requirement error, got %v", err)
	}
}

func TestSerialNumberIsStableForAScan(t *testing.T) {
	a := Build(nil, baseOpts())
	b := Build(nil, baseOpts())
	if a.SerialNumber != b.SerialNumber {
		t.Errorf("serial numbers differ across builds: %s vs %s", a.SerialNumber, b.SerialNumber)
	}
	if !strings.HasPrefix(a.SerialNumber, "urn:uuid:") {
		t.Errorf("serial number is not a urn:uuid: %s", a.SerialNumber)
	}
}

func TestDocumentIsValidJSON(t *testing.T) {
	raw, err := Marshal(Build([]Finding{sampleFinding()}, baseOpts()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("document is not valid json: %v", err)
	}
	if round["specVersion"] != SpecVersion {
		t.Errorf("specVersion = %v, want %s", round["specVersion"], SpecVersion)
	}
}
