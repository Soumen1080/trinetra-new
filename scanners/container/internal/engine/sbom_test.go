package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// A CycloneDX 1.5 document as a third-party tool would emit it: the 1.5+
// metadata.tools object form, a mix of crypto and non-crypto components.
const externalCycloneDX15 = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "tools": {
      "components": [{"name": "syft", "version": "1.20.0", "type": "application"}]
    }
  },
  "components": [
    {"type": "library", "name": "openssl", "version": "3.0.11",
     "purl": "pkg:deb/debian/openssl@3.0.11"},
    {"type": "library", "name": "libjpeg-turbo", "version": "2.1.5",
     "purl": "pkg:deb/debian/libjpeg-turbo@2.1.5"},
    {"type": "library", "name": "bouncycastle", "version": "1.76",
     "purl": "pkg:maven/org.bouncycastle/bcprov@1.76"}
  ]
}`

// The 1.4 array form of metadata.tools, which CycloneDX changed in 1.5.
const externalCycloneDX14 = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {
    "tools": [{"vendor": "CycloneDX", "name": "cdxgen", "version": "9.5.1"}]
  },
  "components": [
    {"type": "library", "name": "cryptography", "version": "41.0.7",
     "purl": "pkg:pypi/cryptography@41.0.7"}
  ]
}`

const externalSPDX23 = `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Organization: Example Corp", "Tool: trivy-0.48.0"]
  },
  "packages": [
    {
      "name": "libgcrypt20",
      "versionInfo": "1.10.3",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
         "referenceLocator": "pkg:deb/debian/libgcrypt20@1.10.3"}
      ]
    },
    {"name": "zlib", "versionInfo": "1.2.13"}
  ]
}`

func ingestSBOM(t *testing.T, content, name string) Result {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, name, content)

	e := NewSBOMEngine(loadKB(t))
	if err := e.Available(context.Background()); err != nil {
		t.Fatalf("engine unavailable: %v", err)
	}
	result, err := e.Scan(context.Background(), Target{Path: dir})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

func TestSBOMIngestsCycloneDX(t *testing.T) {
	result := ingestSBOM(t, externalCycloneDX15, "sbom.json")

	// openssl and bouncycastle are crypto libraries; libjpeg-turbo is not.
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 crypto components, got %d: %+v",
			len(result.Findings), result.Findings)
	}
	for _, finding := range result.Findings {
		if strings.Contains(strings.ToLower(finding.Name), "jpeg") {
			t.Error("a non-crypto component was ingested")
		}
	}
}

func TestSBOMIngestsSPDX(t *testing.T) {
	result := ingestSBOM(t, externalSPDX23, "sbom.spdx.json")

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 crypto package, got %d: %+v",
			len(result.Findings), result.Findings)
	}
	if !strings.Contains(result.Findings[0].Name, "libgcrypt20") {
		t.Errorf("name = %q, want the package name", result.Findings[0].Name)
	}
}

// The property this engine exists to protect: Trinetra did not observe these
// components, and a finding's confidence must reflect who actually looked.
func TestIngestedComponentsAreMediumConfidence(t *testing.T) {
	for _, content := range []string{externalCycloneDX15, externalSPDX23} {
		result := ingestSBOM(t, content, "sbom.json")
		for _, finding := range result.Findings {
			if finding.Confidence != cbom.ConfidenceMedium {
				t.Errorf("%q has confidence %q; an unverified assertion must never be high",
					finding.Name, finding.Confidence)
			}
			if finding.DetectionMethod != cbom.DetectSBOMIngest {
				t.Errorf("%q detection method = %q, want sbom_ingest",
					finding.Name, finding.DetectionMethod)
			}
		}
	}
}

// A reader must be able to tell second-hand evidence from first-hand.
func TestIngestedEvidenceStatesItIsSecondHand(t *testing.T) {
	result := ingestSBOM(t, externalCycloneDX15, "sbom.json")

	for _, finding := range result.Findings {
		if !strings.Contains(finding.Snippet, "not observed by Trinetra") {
			t.Errorf("evidence does not mark itself second-hand: %q", finding.Snippet)
		}
	}
}

// The producing tool must be recorded, so a reader can judge the source.
func TestProducerIsRecordedForBothToolsShapes(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		filename string
		want     string
	}{
		// CycloneDX changed metadata.tools from an array (1.4) to an object
		// (1.5); both shapes must resolve.
		{"cyclonedx 1.5 object", externalCycloneDX15, "sbom.json", "syft@1.20.0"},
		{"cyclonedx 1.4 array", externalCycloneDX14, "bom.json", "cdxgen@9.5.1"},
		{"spdx creators", externalSPDX23, "sbom.spdx.json", "trivy-0.48.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ingestSBOM(t, tc.content, tc.filename)
			if len(result.Findings) == 0 {
				t.Fatal("no findings produced")
			}
			finding := result.Findings[0]

			if !strings.Contains(finding.Snippet, tc.want) {
				t.Errorf("producer %q missing from evidence: %q", tc.want, finding.Snippet)
			}
			if !strings.Contains(finding.RuleID, tc.want) {
				t.Errorf("rule id = %q, want it to name the producer", finding.RuleID)
			}
		})
	}
}

// An unnamed producer must say so rather than be omitted: a reader has to see
// that the source is unidentified.
func TestUnknownProducerIsStated(t *testing.T) {
	const noTools = `{
      "bomFormat": "CycloneDX", "specVersion": "1.6",
      "components": [{"type": "library", "name": "openssl", "version": "3.5.0"}]
    }`

	result := ingestSBOM(t, noTools, "sbom.json")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if !strings.Contains(result.Findings[0].Snippet, "unknown") {
		t.Errorf("an unidentified producer must be stated: %q", result.Findings[0].Snippet)
	}
}

// Library findings never carry an algorithm, however they were obtained.
func TestIngestedLibrariesCarryNoAlgorithm(t *testing.T) {
	result := ingestSBOM(t, externalCycloneDX15, "sbom.json")

	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetLibrary {
			t.Errorf("%q is not a library artefact", finding.Name)
		}
		if finding.Algorithm != "" {
			t.Errorf("library %q carries algorithm %q", finding.Name, finding.Algorithm)
		}
		if finding.KeySizeBits != nil {
			t.Errorf("library %q carries a key size", finding.Name)
		}
	}
}

// The knowledge base still decides PQC capability, and "not recorded" is not
// "unsupported" (P3).
func TestIngestedComponentsCarryPQCVerdicts(t *testing.T) {
	result := ingestSBOM(t, externalCycloneDX15, "sbom.json")

	var sawVerdict bool
	for _, finding := range result.Findings {
		if strings.Contains(finding.Snippet, "predates PQC support") ||
			strings.Contains(finding.Snippet, "PQC-capable since") ||
			strings.Contains(finding.Snippet, "not recorded") {
			sawVerdict = true
		}
	}
	if !sawVerdict {
		t.Error("no PQC verdict reached an ingested component")
	}
}

// An SBOM lists every dependency; a non-crypto package is not a coverage hole,
// and reporting it as one would bury the real gaps.
func TestNonCryptoComponentsAreNotGaps(t *testing.T) {
	result := ingestSBOM(t, externalCycloneDX15, "sbom.json")
	if len(result.Gaps) != 0 {
		t.Errorf("expected no gaps, got %+v", result.Gaps)
	}
}

// A file named like an SBOM that Trinetra cannot read is a hole the user should
// know about, not a silent skip.
func TestUnreadableSBOMBecomesAGap(t *testing.T) {
	cases := map[string]string{
		"not json":       "{not json at all",
		"unknown format": `{"someOtherFormat": true, "components": []}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			result := ingestSBOM(t, content, "sbom.json")
			if len(result.Gaps) != 1 {
				t.Fatalf("expected one gap, got %+v", result.Gaps)
			}
			if len(result.Findings) != 0 {
				t.Errorf("findings were produced from an unreadable document")
			}
		})
	}
}

// An unsupported spec version is refused with a stated reason rather than
// parsed optimistically: a silently partial ingest is worse than a refusal.
func TestUnsupportedVersionsAreRefusedWithAReason(t *testing.T) {
	cases := map[string]string{
		"cyclonedx 1.3": `{"bomFormat":"CycloneDX","specVersion":"1.3","components":[
          {"type":"library","name":"openssl","version":"3.0.0"}]}`,
		"spdx 3.0": `{"spdxVersion":"SPDX-3.0","SPDXID":"SPDXRef-DOCUMENT",
          "packages":[{"name":"openssl","versionInfo":"3.0.0"}]}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			result := ingestSBOM(t, content, "sbom.json")

			if len(result.Findings) != 0 {
				t.Errorf("an unsupported document produced %d findings", len(result.Findings))
			}
			if len(result.Gaps) != 1 {
				t.Fatalf("expected a gap explaining the refusal, got %+v", result.Gaps)
			}
			if result.Gaps[0].Kind != "unsupported_format" {
				t.Errorf("gap kind = %q", result.Gaps[0].Kind)
			}
			if !strings.Contains(result.Gaps[0].Reason, "not ingested") {
				t.Errorf("the gap does not say what was lost: %q", result.Gaps[0].Reason)
			}
		})
	}
}

func TestSupportedVersionRanges(t *testing.T) {
	for version, want := range map[string]bool{
		"1.4": true, "1.5": true, "1.6": true,
		"1.3": false, "1.2": false, "2.0": false, "": false,
	} {
		if got := supportedCycloneDXVersion(version); got != want {
			t.Errorf("supportedCycloneDXVersion(%q) = %v, want %v", version, got, want)
		}
	}

	for version, want := range map[string]bool{
		"SPDX-2.2": true, "SPDX-2.3": true,
		"SPDX-3.0": false, "": false,
	} {
		if got := supportedSPDXVersion(version); got != want {
			t.Errorf("supportedSPDXVersion(%q) = %v, want %v", version, got, want)
		}
	}
}

// Only conventionally named files are opened; scanning every .json in a tree
// would read whole repositories to find nothing.
func TestOnlyConventionalFilenamesAreRead(t *testing.T) {
	for name, shouldMatch := range map[string]bool{
		"sbom.json":        true,
		"bom.json":         true,
		"myapp.cdx.json":   true,
		"myapp.spdx.json":  true,
		"cyclonedx.json":   true,
		"package.json":     false,
		"tsconfig.json":    false,
		"data.json":        false,
		"requirements.txt": false,
	} {
		if got := isSBOMFilename(name); got != shouldMatch {
			t.Errorf("isSBOMFilename(%q) = %v, want %v", name, got, shouldMatch)
		}
	}
}

func TestSBOMEngineRejectsImageTargets(t *testing.T) {
	// An SBOM is a file on disk; an image target would mean something else.
	if NewSBOMEngine(nil).SupportsImages() {
		t.Error("the SBOM engine claims image support it does not have")
	}
	if _, err := NewSBOMEngine(nil).Scan(
		context.Background(), Target{ImageReference: "alpine:3"}); err == nil {
		t.Error("expected an error for an image target")
	}
}

func TestSBOMEngineRequiresKnowledgeBase(t *testing.T) {
	// Without it every component would look like a crypto library.
	if err := (&SBOMEngine{}).Available(context.Background()); err == nil {
		t.Error("expected the engine to refuse to run without a knowledge base")
	}
}

// A tree with no SBOM is a valid result, not an error.
func TestNoSBOMPresentYieldsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "# no sbom here\n")

	e := NewSBOMEngine(loadKB(t))
	result, err := e.Scan(context.Background(), Target{Path: dir})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) != 0 || len(result.Gaps) != 0 {
		t.Errorf("expected nothing, got %d findings and %d gaps",
			len(result.Findings), len(result.Gaps))
	}
}
