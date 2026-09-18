package engine

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// Recorded Syft output. Testing the adapter against a fixture pins the shape
// Trinetra expects, so an upstream schema change is caught here rather than in
// production, and the test runs without invoking the tool.
const recordedSyftOutput = `{
  "artifacts": [
    {
      "id": "1",
      "name": "openssl",
      "version": "1.1.1w-0+deb11u1",
      "type": "deb",
      "purl": "pkg:deb/debian/openssl@1.1.1w",
      "locations": [{"path": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "layerID": "sha256:abc"}]
    },
    {
      "id": "2",
      "name": "cryptography",
      "version": "41.0.7",
      "type": "python",
      "purl": "pkg:pypi/cryptography@41.0.7",
      "locations": [{"path": "/usr/lib/python3/dist-packages/cryptography", "layerID": "sha256:def"}]
    },
    {
      "id": "3",
      "name": "libjpeg-turbo",
      "version": "2.1.5",
      "type": "deb",
      "purl": "pkg:deb/debian/libjpeg-turbo@2.1.5",
      "locations": [{"path": "/usr/lib/libjpeg.so", "layerID": "sha256:abc"}]
    },
    {
      "id": "4",
      "name": "pycrypto",
      "version": "2.6.1",
      "type": "python",
      "purl": "pkg:pypi/pycrypto@2.6.1",
      "locations": [{"path": "/usr/lib/python3/dist-packages/Crypto", "layerID": "sha256:def"}]
    }
  ],
  "source": {"type": "image", "name": "example:latest"},
  "descriptor": {"name": "syft", "version": "1.51.0"}
}`

func adaptRecordedSyft(t *testing.T) Result {
	t.Helper()
	doc, err := parseSyftOutput([]byte(recordedSyftOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return (&SyftEngine{Knowledge: loadKB(t)}).adapt(doc)
}

func TestSyftFiltersToCryptoLibraries(t *testing.T) {
	result := adaptRecordedSyft(t)

	// openssl, cryptography and pycrypto are crypto libraries; libjpeg is not.
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 crypto libraries, got %d: %+v",
			len(result.Findings), result.Findings)
	}
	for _, finding := range result.Findings {
		if strings.Contains(strings.ToLower(finding.Name), "jpeg") {
			t.Error("a non-crypto package was reported as a crypto library")
		}
	}
}

// A non-crypto package is not a coverage hole in a cryptographic inventory, so
// it must not be reported as a gap -- that would bury the real gaps.
func TestSyftDoesNotReportUnknownPackagesAsGaps(t *testing.T) {
	if gaps := adaptRecordedSyft(t).Gaps; len(gaps) != 0 {
		t.Errorf("expected no gaps, got %+v", gaps)
	}
}

// The discipline Syft makes easiest to violate: a package name is not an
// algorithm.
func TestSyftLibraryFindingsCarryNoAlgorithm(t *testing.T) {
	for _, finding := range adaptRecordedSyft(t).Findings {
		if finding.AssetType != cbom.AssetLibrary {
			t.Errorf("%s is not a library artefact", finding.Name)
		}
		if finding.Algorithm != "" {
			t.Errorf("library %q carries algorithm %q", finding.Name, finding.Algorithm)
		}
		if finding.KeySizeBits != nil {
			t.Errorf("library %q carries a key size", finding.Name)
		}
	}
}

func TestSyftRecordsVersionAndPurl(t *testing.T) {
	for _, finding := range adaptRecordedSyft(t).Findings {
		if finding.Name == "OpenSSL" {
			if !strings.Contains(finding.Snippet, "1.1.1w") {
				t.Errorf("version missing from evidence: %q", finding.Snippet)
			}
			if !strings.Contains(finding.Snippet, "pkg:deb/debian/openssl") {
				t.Errorf("purl missing from evidence: %q", finding.Snippet)
			}
			return
		}
	}
	t.Error("OpenSSL finding not produced")
}

// "Not recorded" is not "unsupported" (P3).
func TestSyftEvidenceDistinguishesUnknownPQCFromUnsupported(t *testing.T) {
	findings := adaptRecordedSyft(t).Findings

	byName := map[string]cbom.Finding{}
	for _, finding := range findings {
		byName[finding.Name] = finding
	}

	openssl, ok := byName["OpenSSL"]
	if !ok {
		t.Fatalf("OpenSSL missing; got %v", keysOf(byName))
	}
	// 1.1.1w is known to predate PQC support, so the evidence must say so.
	if !strings.Contains(openssl.Snippet, "predates PQC support") {
		t.Errorf("OpenSSL 1.1.1w evidence = %q", openssl.Snippet)
	}

	pyca, ok := byName["cryptography (pyca/cryptography)"]
	if !ok {
		t.Fatalf("pyca/cryptography missing; got %v", keysOf(byName))
	}
	// No pqc_since entry: the honest phrasing is "not recorded".
	if !strings.Contains(pyca.Snippet, "not recorded") {
		t.Errorf("a library with no PQC entry must say 'not recorded': %q", pyca.Snippet)
	}
}

func TestSyftFlagsDeprecatedPackages(t *testing.T) {
	for _, finding := range adaptRecordedSyft(t).Findings {
		if strings.Contains(finding.Snippet, "pycrypto;") ||
			strings.Contains(finding.Snippet, "package pycrypto") {
			if !strings.Contains(finding.Snippet, "unmaintained") {
				t.Errorf("pycrypto was not flagged as unmaintained: %q", finding.Snippet)
			}
			return
		}
	}
	t.Error("pycrypto finding not produced")
}

func TestSyftRecordsLayerAttribution(t *testing.T) {
	for _, finding := range adaptRecordedSyft(t).Findings {
		if finding.Location.Symbol == "" {
			t.Errorf("%s has no layer attribution", finding.Name)
		}
	}
}

// Evidence must never carry a host or absolute path.
func TestSyftPathsAreRelative(t *testing.T) {
	for _, finding := range adaptRecordedSyft(t).Findings {
		if strings.HasPrefix(finding.Location.Path, "/") {
			t.Errorf("absolute path in evidence: %q", finding.Location.Path)
		}
	}
}

// The adapter is the trust boundary: malformed output is a scanner error.
func TestParseSyftOutputRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"", "  ", "not json", "{unclosed"} {
		if _, err := parseSyftOutput([]byte(raw)); err == nil {
			t.Errorf("expected an error for %q", raw)
		}
	}
}

func TestSyftRequiresKnowledgeBase(t *testing.T) {
	// Without the knowledge base every package would look like a crypto
	// library, so the engine must refuse to run rather than flood the inventory.
	engine := &SyftEngine{Binary: "syft"}
	if err := engine.Available(context.Background()); err == nil {
		t.Error("expected the engine to refuse to run without a knowledge base")
	}
}

func TestSyftToolMetadataIsComplete(t *testing.T) {
	tool := (&SyftEngine{Version: "1.51.0"}).Tool()
	if tool.Name != "syft" || tool.Version != "1.51.0" || tool.Licence != "Apache-2.0" {
		t.Errorf("incomplete tool metadata: %+v", tool)
	}
}

// End to end against the real binary when it is installed.
func TestSyftRealScanFindsCryptoLibraries(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft is not installed")
	}

	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "cryptography==41.0.7\npycryptodome==3.19.0\nrequests==2.31.0\n")

	engine := NewSyftEngine(loadKB(t))
	if err := engine.Available(context.Background()); err != nil {
		t.Skipf("syft unavailable: %v", err)
	}

	result, err := engine.Scan(context.Background(), Target{Path: dir})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	names := map[string]bool{}
	for _, finding := range result.Findings {
		names[finding.Name] = true
		if finding.Algorithm != "" {
			t.Errorf("library %q carries an algorithm", finding.Name)
		}
	}

	if !names["cryptography (pyca/cryptography)"] || !names["PyCryptodome"] {
		t.Errorf("expected both crypto libraries, got %v", names)
	}
	// requests is not a crypto library and must be filtered out.
	for name := range names {
		if strings.Contains(strings.ToLower(name), "requests") {
			t.Error("a non-crypto package reached the inventory")
		}
	}
}

func keysOf(m map[string]cbom.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A library name must identify the PACKAGE, not just the product. An image can
// ship several packages from one project, and two findings both called
// "OpenSSL" leave a reader unable to tell which is installed.
func TestLibraryNameQualifiesThePackage(t *testing.T) {
	cases := []struct{ pkg, display, want string }{
		{"libcrypto3", "OpenSSL", "libcrypto3 (OpenSSL)"},
		{"libssl3", "OpenSSL", "libssl3 (OpenSSL)"},
		{"libk5crypto3", "Kerberos (MIT krb5)", "libk5crypto3 (Kerberos (MIT krb5))"},
		// No pointless repetition when the two already agree.
		{"PyCryptodome", "PyCryptodome", "PyCryptodome"},
		{"pycryptodome", "PyCryptodome", "PyCryptodome"},
		{"", "OpenSSL", "OpenSSL"},
	}

	for _, tc := range cases {
		if got := libraryName(tc.pkg, tc.display); got != tc.want {
			t.Errorf("libraryName(%q,%q) = %q, want %q", tc.pkg, tc.display, got, tc.want)
		}
	}
}

// Syft reports host-native separators on a directory scan, so a Windows
// developer machine yields "\opt\app\go.mod". Evidence must read identically
// wherever it was produced.
func TestSyftNormalisesWindowsPaths(t *testing.T) {
	const windowsOutput = `{
      "artifacts": [{
        "id": "1", "name": "openssl", "version": "3.5.0", "type": "deb",
        "purl": "pkg:deb/openssl@3.5.0",
        "locations": [{"path": "\\opt\\app\\go.mod", "layerID": "sha256:a"}]
      }]
    }`

	doc, err := parseSyftOutput([]byte(windowsOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result := (&SyftEngine{Knowledge: loadKB(t)}).adapt(doc)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	path := result.Findings[0].Location.Path
	if strings.Contains(path, `\`) {
		t.Errorf("path retains backslashes: %q", path)
	}
	if path != "opt/app/go.mod" {
		t.Errorf("path = %q, want opt/app/go.mod", path)
	}
}
