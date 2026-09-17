package engine

import (
	"context"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// Recorded CBOMkit output. Testing the adapter against a fixture rather than a
// live engine is deliberate: it verifies the trust boundary on a machine with no
// JRE, and it pins the shape Trinetra expects so an upstream change is caught
// here rather than in production.
const recordedCBOMkitOutput = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "AES-128-CBC",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "parameterSetIdentifier": "128",
          "mode": "cbc",
          "padding": "pkcs7",
          "cryptoFunctions": ["encrypt", "decrypt"]
        }
      },
      "evidence": {
        "occurrences": [{ "location": "src/main/java/Crypto.java", "line": 42 }]
      }
    },
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "oid": "1.2.840.113549.1.1.1",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "cryptoFunctions": ["encapsulate"]
        }
      },
      "evidence": {
        "occurrences": [{ "location": "src/main/java/Keys.java", "line": 17 }]
      }
    },
    {
      "type": "library",
      "name": "bouncycastle",
      "version": "1.70"
    },
    {
      "type": "cryptographic-asset",
      "name": "SHA-256",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": { "primitive": "hash", "cryptoFunctions": ["digest"] }
      },
      "evidence": { "occurrences": [] }
    }
  ]
}`

func TestAdaptCBOMkitDocument(t *testing.T) {
	doc, err := parseCBOMkitOutput([]byte(recordedCBOMkitOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	result := AdaptCBOMkitDocument(doc)

	// Two algorithms with locations are adapted; the "library" component is
	// skipped as a non-cryptographic-asset, and the location-less SHA-256
	// becomes a gap rather than an unverifiable finding.
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	byName := map[string]cbom.Finding{}
	for _, f := range result.Findings {
		byName[f.Name] = f
	}

	aes, ok := byName["AES-128-CBC"]
	if !ok {
		t.Fatal("AES finding missing")
	}
	if size, has := aes.KeySize(); !has || size != 128 {
		t.Errorf("AES key size = %d (%v), want 128", size, has)
	}
	if aes.Mode != "cbc" {
		t.Errorf("AES mode = %q, want cbc", aes.Mode)
	}
	if aes.Padding != "pkcs7" {
		t.Errorf("AES padding = %q, want pkcs7", aes.Padding)
	}
	if aes.Primitive != cbom.PrimitiveBlockCipher {
		t.Errorf("AES primitive = %q, want block_cipher", aes.Primitive)
	}
	if aes.Algorithm != "aes" {
		t.Errorf("AES algorithm = %q, want aes", aes.Algorithm)
	}
	if aes.Location.Path != "src/main/java/Crypto.java" || aes.Location.Line != 42 {
		t.Errorf("AES location = %+v", aes.Location)
	}
	if aes.DetectionMethod != cbom.DetectCBOMkit {
		t.Errorf("detection method = %q, want cbomkit_engine", aes.DetectionMethod)
	}

	rsa, ok := byName["RSA-2048"]
	if !ok {
		t.Fatal("RSA finding missing")
	}
	if size, has := rsa.KeySize(); !has || size != 2048 {
		t.Errorf("RSA key size = %d (%v), want 2048", size, has)
	}
	if rsa.OID != "1.2.840.113549.1.1.1" {
		t.Errorf("RSA oid = %q", rsa.OID)
	}
	if len(rsa.Purposes) != 1 || rsa.Purposes[0] != cbom.PurposeKeyEncapsulation {
		t.Errorf("RSA purposes = %v", rsa.Purposes)
	}
}

// Non-cryptographic-asset components are legitimately present in a CBOM and
// must be skipped, not rejected — brittleness here would break ingest of any
// real-world document.
func TestAdaptSkipsNonCryptographicAssets(t *testing.T) {
	doc, _ := parseCBOMkitOutput([]byte(recordedCBOMkitOutput))
	for _, f := range AdaptCBOMkitDocument(doc).Findings {
		if f.Name == "bouncycastle" {
			t.Error("a plain library component was adapted as a crypto finding")
		}
	}
}

// An unsourced finding is a bug, not a low-quality artefact: a human cannot
// verify it, so it becomes a visible gap instead.
func TestAdaptReportsUnlocatableFindingsAsGaps(t *testing.T) {
	doc, _ := parseCBOMkitOutput([]byte(recordedCBOMkitOutput))
	result := AdaptCBOMkitDocument(doc)

	var found bool
	for _, g := range result.Gaps {
		if g.Kind == "unlocatable_finding" {
			found = true
		}
	}
	if !found {
		t.Error("a finding with no source location did not produce a gap")
	}
}

// Trinetra's namespaced properties survive a round trip through CBOMkit output.
func TestAdaptReadsTrinetraProperties(t *testing.T) {
	const withProps = `{
      "components": [{
        "type": "cryptographic-asset",
        "name": "AES",
        "cryptoProperties": { "assetType": "related-crypto-material" },
        "evidence": { "occurrences": [{ "location": "a.py", "line": 1 }] },
        "properties": [
          { "name": "trinetra:key-size-bits", "value": "256" },
          { "name": "trinetra:data-category", "value": "aadhaar_pii" },
          { "name": "trinetra:asset-type", "value": "key" }
        ]
      }]
    }`

	doc, err := parseCBOMkitOutput([]byte(withProps))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	findings := AdaptCBOMkitDocument(doc).Findings
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if size, ok := f.KeySize(); !ok || size != 256 {
		t.Errorf("key size = %d (%v), want 256", size, ok)
	}
	if f.DataCategory != "aadhaar_pii" {
		t.Errorf("data category = %q", f.DataCategory)
	}
	// The hint is what lets key/hardware_module/cloud_service survive a wire
	// format that spells all three "related-crypto-material".
	if f.AssetType != cbom.AssetKey {
		t.Errorf("asset type = %q, want key", f.AssetType)
	}
}

// The adapter is the trust boundary: malformed output is a scanner error, never
// a crash.
func TestParseCBOMkitOutputRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"", "not json", "{broken"} {
		if _, err := parseCBOMkitOutput([]byte(raw)); err == nil {
			t.Errorf("expected an error for %q", raw)
		}
	}
}

// An engine that is not configured must be skipped with a reason, not silently
// ignored: a missing engine means a smaller inventory, and the user must see it.
func TestCBOMkitUnavailableWhenNotConfigured(t *testing.T) {
	e := &CBOMkitEngine{}
	err := e.Available(context.Background())
	if err == nil {
		t.Fatal("expected an unavailable error when no binary is configured")
	}
}

func TestCBOMkitToolMetadataIsComplete(t *testing.T) {
	// A CBOM must be able to say which tool and licence produced a finding.
	tool := (&CBOMkitEngine{Version: "1.2.3"}).Tool()
	if tool.Name == "" || tool.Version != "1.2.3" || tool.Licence != "Apache-2.0" {
		t.Errorf("incomplete tool metadata: %+v", tool)
	}
}

// The honest language list. Claiming a language CBOMkit does not cover would be
// a false coverage claim.
func TestCBOMkitLanguagesAreHonest(t *testing.T) {
	got := (&CBOMkitEngine{}).Languages()
	want := map[string]bool{"java": true, "python": true, "go": true}

	if len(got) != len(want) {
		t.Fatalf("languages = %v, want exactly %v", got, want)
	}
	for _, lang := range got {
		if !want[lang] {
			t.Errorf("claims unsupported language %q", lang)
		}
	}
}

func TestCBOMkitAlgorithmName(t *testing.T) {
	cases := map[string]string{
		"AES-128-CBC": "aes",
		"RSA-2048":    "rsa",
		"SHA-256":     "sha",
		"MD5":         "md5",
		"":            "",
	}
	for in, want := range cases {
		if got := cbomkitAlgorithmName(in); got != want {
			t.Errorf("cbomkitAlgorithmName(%q) = %q, want %q", in, got, want)
		}
	}
}
