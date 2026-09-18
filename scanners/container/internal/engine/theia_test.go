package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// Recorded cbomkit-theia output. Testing the adapter against a fixture verifies
// the trust boundary on a machine where theia is not installed, and pins the
// shape Trinetra expects so an upstream change is caught here.
const recordedTheiaOutput = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "payments.example.org",
      "cryptoProperties": {
        "assetType": "certificate",
        "certificateProperties": {
          "subjectName": "CN=payments.example.org",
          "issuerName": "CN=Example CA",
          "notValidBefore": "2026-01-01T00:00:00Z",
          "notValidAfter": "2027-01-01T00:00:00Z",
          "signatureAlgorithmRef": "sha256WithRSAEncryption",
          "subjectPublicKeyRef": "RSA-2048",
          "certificateFormat": "X.509"
        }
      },
      "evidence": {"occurrences": [{"location": "/etc/ssl/certs/server.crt", "line": 1}]}
    },
    {
      "type": "cryptographic-asset",
      "name": "server-private-key",
      "cryptoProperties": {
        "assetType": "related-crypto-material",
        "relatedCryptoMaterialProperties": {
          "type": "private-key",
          "size": 2048,
          "format": "PEM",
          "state": "active",
          "securedBy": {"mechanism": "none"}
        }
      },
      "evidence": {"occurrences": [{"location": "/etc/ssl/private/server.key", "line": 1}]}
    },
    {
      "type": "cryptographic-asset",
      "name": "TLS",
      "cryptoProperties": {
        "assetType": "protocol",
        "protocolProperties": {
          "type": "tls",
          "version": "1.2",
          "cipherSuites": [
            {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
            {"name": "TLS_RSA_WITH_AES_256_CBC_SHA"}
          ]
        }
      },
      "evidence": {"occurrences": [{"location": "/etc/ssl/openssl.cnf", "line": 12}]}
    },
    {
      "type": "cryptographic-asset",
      "name": "AES-128-CBC",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "parameterSetIdentifier": "128",
          "mode": "cbc",
          "cryptoFunctions": ["encrypt", "decrypt"]
        }
      },
      "evidence": {"occurrences": [{"location": "/opt/app/config.json", "line": 4}]}
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.11"
    },
    {
      "type": "cryptographic-asset",
      "name": "orphan",
      "cryptoProperties": {"assetType": "algorithm"},
      "evidence": {"occurrences": []}
    }
  ]
}`

func adaptRecordedTheia(t *testing.T) Result {
	t.Helper()
	doc, err := parseTheiaOutput([]byte(recordedTheiaOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return AdaptTheiaDocument(doc)
}

func theiaByName(t *testing.T) map[string]cbom.Finding {
	t.Helper()
	byName := map[string]cbom.Finding{}
	for _, finding := range adaptRecordedTheia(t).Findings {
		byName[finding.Name] = finding
	}
	return byName
}

func TestTheiaAdaptsAllAssetTypes(t *testing.T) {
	result := adaptRecordedTheia(t)

	// Four locatable crypto assets; the plain library component is skipped and
	// the location-less one becomes a gap.
	if len(result.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %+v", len(result.Findings), result.Findings)
	}

	types := map[cbom.AssetType]int{}
	for _, finding := range result.Findings {
		types[finding.AssetType]++
	}
	for assetType, want := range map[cbom.AssetType]int{
		cbom.AssetCertificate: 1,
		cbom.AssetKey:         1,
		cbom.AssetProtocol:    1,
		cbom.AssetAlgorithm:   1,
	} {
		if types[assetType] != want {
			t.Errorf("%s count = %d, want %d", assetType, types[assetType], want)
		}
	}
}

// Signature and public-key algorithms carry different risk and must both
// survive rather than being collapsed into one field.
func TestTheiaCertificateKeepsBothAlgorithms(t *testing.T) {
	certificate := theiaByName(t)["payments.example.org"]

	if !strings.Contains(certificate.Snippet, "signature sha256WithRSAEncryption") {
		t.Errorf("signature algorithm missing: %q", certificate.Snippet)
	}
	if !strings.Contains(certificate.Snippet, "public_key RSA-2048") {
		t.Errorf("public-key algorithm missing: %q", certificate.Snippet)
	}
	if !strings.Contains(certificate.Snippet, "issuer CN=Example CA") {
		t.Errorf("issuer missing: %q", certificate.Snippet)
	}
}

// theia uses gitleaks, which finds real secrets. Trinetra records that key
// material exists and never what it is.
func TestTheiaKeysAreRedacted(t *testing.T) {
	key := theiaByName(t)["server-private-key"]

	if key.AssetType != cbom.AssetKey {
		t.Fatalf("asset type = %q, want key", key.AssetType)
	}
	if !key.Redacted {
		t.Error("a private-key finding was not marked redacted")
	}
	if !strings.Contains(key.Snippet, "withheld") {
		t.Errorf("evidence does not state that contents were withheld: %q", key.Snippet)
	}
	// The parameters are still reported; those are not secret.
	if size, ok := key.KeySize(); !ok || size != 2048 {
		t.Errorf("key size = %d (%v), want 2048", size, ok)
	}
}

// Configuration is declared crypto, never observed crypto.
func TestTheiaProtocolIsMarkedDeclared(t *testing.T) {
	protocol := theiaByName(t)["TLS"]

	if protocol.ParameterSet != "1.2" {
		t.Errorf("version = %q, want 1.2", protocol.ParameterSet)
	}
	if !strings.Contains(protocol.Snippet, "declared") {
		t.Errorf("evidence does not mark this as declared: %q", protocol.Snippet)
	}
	if !strings.Contains(protocol.Snippet, "TLS_RSA_WITH_AES_256_CBC_SHA") {
		t.Errorf("cipher suites missing: %q", protocol.Snippet)
	}
}

func TestTheiaAlgorithmResolvesR19Fields(t *testing.T) {
	algorithm := theiaByName(t)["AES-128-CBC"]

	if size, ok := algorithm.KeySize(); !ok || size != 128 {
		t.Errorf("key size = %d (%v), want 128", size, ok)
	}
	if algorithm.Mode != "cbc" {
		t.Errorf("mode = %q, want cbc", algorithm.Mode)
	}
	if algorithm.Primitive != cbom.PrimitiveBlockCipher {
		t.Errorf("primitive = %q, want block_cipher", algorithm.Primitive)
	}
	if len(algorithm.Purposes) != 2 {
		t.Errorf("purposes = %v, want two", algorithm.Purposes)
	}
}

func TestTheiaSkipsNonCryptographicAssets(t *testing.T) {
	for _, finding := range adaptRecordedTheia(t).Findings {
		if finding.Name == "openssl" && finding.AssetType != cbom.AssetLibrary {
			t.Error("a plain library component was adapted as a crypto asset")
		}
	}
}

// An unsourced finding cannot be verified by a human.
func TestTheiaReportsUnlocatableFindingsAsGaps(t *testing.T) {
	result := adaptRecordedTheia(t)

	var found bool
	for _, gap := range result.Gaps {
		if gap.Kind == "unlocatable_finding" {
			found = true
		}
	}
	if !found {
		t.Errorf("a finding with no location produced no gap: %+v", result.Gaps)
	}
}

func TestTheiaPathsAreRelative(t *testing.T) {
	for _, finding := range adaptRecordedTheia(t).Findings {
		if strings.HasPrefix(finding.Location.Path, "/") {
			t.Errorf("absolute path in evidence: %q", finding.Location.Path)
		}
	}
}

// A certificate subject is not an algorithm name.
func TestTheiaDoesNotInventAlgorithmsFromSubjects(t *testing.T) {
	if got := theiaAlgorithmName("", "CN=payments.example.org"); got != "" {
		t.Errorf("a subject DN yielded algorithm %q", got)
	}
}

func TestParseTheiaOutputRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"", "not json", "{unclosed"} {
		if _, err := parseTheiaOutput([]byte(raw)); err == nil {
			t.Errorf("expected an error for %q", raw)
		}
	}
}

// An engine that is not configured is skipped with a reason, never silently.
func TestTheiaUnavailableWhenNotConfigured(t *testing.T) {
	if err := (&TheiaEngine{}).Available(context.Background()); err == nil {
		t.Error("expected an unavailable error with no binary configured")
	}
}

func TestTheiaSupportsImages(t *testing.T) {
	// theia is the engine that makes image scanning real; if this ever returns
	// false, image targets silently lose certificate and key detection.
	if !(&TheiaEngine{}).SupportsImages() {
		t.Error("theia must declare image support")
	}
}

func TestTheiaToolMetadataIsComplete(t *testing.T) {
	tool := (&TheiaEngine{Version: "1.2.3"}).Tool()
	if tool.Name != "cbomkit-theia" || tool.Version != "1.2.3" || tool.Licence != "Apache-2.0" {
		t.Errorf("incomplete tool metadata: %+v", tool)
	}
}
