package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

func scanDir(t *testing.T, e Engine, dir string) Result {
	t.Helper()
	result, err := e.Scan(context.Background(), Target{Path: dir})
	if err != nil {
		t.Fatalf("%s scan: %v", e.Name(), err)
	}
	return result
}

func findByType(findings []cbom.Finding, assetType cbom.AssetType) []cbom.Finding {
	var matched []cbom.Finding
	for _, f := range findings {
		if f.AssetType == assetType {
			matched = append(matched, f)
		}
	}
	return matched
}

func TestPKIFindsCertificatesAndKeys(t *testing.T) {
	dir := t.TempDir()
	writeRSACertificate(t, dir, 2048)
	writeECCertificate(t, dir)
	writePublicKey(t, dir)

	result := scanDir(t, NewPKIEngine(), dir)

	certificates := findByType(result.Findings, cbom.AssetCertificate)
	if len(certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certificates))
	}

	keys := findByType(result.Findings, cbom.AssetKey)
	if len(keys) != 2 { // one private, one public
		t.Fatalf("expected 2 key artefacts, got %d", len(keys))
	}
}

// R19 for certificates: the key size and algorithm must survive.
func TestPKIResolvesCertificateParameters(t *testing.T) {
	dir := t.TempDir()
	writeRSACertificate(t, dir, 2048)

	result := scanDir(t, NewPKIEngine(), dir)
	certificates := findByType(result.Findings, cbom.AssetCertificate)

	if len(certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certificates))
	}
	certificate := certificates[0]

	if certificate.Algorithm != "rsa" {
		t.Errorf("algorithm = %q, want rsa", certificate.Algorithm)
	}
	size, ok := certificate.KeySize()
	if !ok || size != 2048 {
		t.Errorf("key size = %d (%v), want 2048", size, ok)
	}
	if certificate.Name != "payments.example.org" {
		t.Errorf("name = %q, want the certificate subject", certificate.Name)
	}
}

// Signature algorithm and public-key algorithm carry different risk, so both
// must reach the evidence rather than being collapsed into one field.
func TestPKIRecordsBothCertificateAlgorithms(t *testing.T) {
	dir := t.TempDir()
	writeRSACertificate(t, dir, 2048)

	result := scanDir(t, NewPKIEngine(), dir)
	snippet := findByType(result.Findings, cbom.AssetCertificate)[0].Snippet

	if !strings.Contains(snippet, "signature ") {
		t.Errorf("evidence omits the signature algorithm: %q", snippet)
	}
	if !strings.Contains(snippet, "public_key ") {
		t.Errorf("evidence omits the public-key algorithm: %q", snippet)
	}
}

func TestPKIRecordsCertificateValidityAndSelfSigning(t *testing.T) {
	dir := t.TempDir()
	writeECCertificate(t, dir)

	result := scanDir(t, NewPKIEngine(), dir)
	snippet := findByType(result.Findings, cbom.AssetCertificate)[0].Snippet

	for _, want := range []string{"not_before 2026-01-01", "not_after 2031-01-01", "CA", "self-signed"} {
		if !strings.Contains(snippet, want) {
			t.Errorf("evidence omits %q: %s", want, snippet)
		}
	}
}

func TestPKIResolvesECCurve(t *testing.T) {
	dir := t.TempDir()
	writeECCertificate(t, dir)

	certificate := findByType(scanDir(t, NewPKIEngine(), dir).Findings, cbom.AssetCertificate)[0]

	if certificate.Algorithm != "ecdsa" {
		t.Errorf("algorithm = %q, want ecdsa", certificate.Algorithm)
	}
	if certificate.Curve != "P-256" {
		t.Errorf("curve = %q, want P-256", certificate.Curve)
	}
}

// Trinetra stores no secret material. This is the single most important
// property of this engine.
func TestPKINeverStoresPrivateKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeRSACertificate(t, dir, 2048)

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	// The base64 body of the PEM, which is what must never appear in output.
	body := strings.Join(strings.Split(string(keyBytes), "\n")[1:3], "")

	result := scanDir(t, NewPKIEngine(), dir)

	for _, finding := range result.Findings {
		if strings.Contains(finding.Snippet, body) {
			t.Fatalf("finding %q leaked private key material", finding.Name)
		}
		for _, fragment := range []string{"PRIVATE KEY-----", "MIIE", "MIIC"} {
			if strings.Contains(finding.Snippet, fragment) {
				t.Errorf("finding %q snippet contains key-shaped data: %q",
					finding.Name, finding.Snippet)
			}
		}
	}
}

func TestPKIMarksPrivateKeysRedacted(t *testing.T) {
	dir := t.TempDir()
	writeRSACertificate(t, dir, 2048)

	var privateKeys int
	for _, finding := range scanDir(t, NewPKIEngine(), dir).Findings {
		if finding.RuleID == "pki:private-key" {
			privateKeys++
			if !finding.Redacted {
				t.Error("a private-key finding was not marked redacted")
			}
			// The parameters are still reported: knowing an RSA-2048 key exists
			// is the whole point, and that is not secret.
			if size, ok := finding.KeySize(); !ok || size != 2048 {
				t.Errorf("private key size = %d (%v), want 2048", size, ok)
			}
		}
	}
	if privateKeys != 1 {
		t.Fatalf("expected 1 private key finding, got %d", privateKeys)
	}
}

// A password-protected keystore is real key material Trinetra cannot open.
// Reporting the gap is honest; silently skipping it makes the image look clean.
func TestPKIReportsUnopenableKeystoreAsGap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keystore.jks", "\xfe\xed\xfe\xed binary keystore contents")

	result := scanDir(t, NewPKIEngine(), dir)

	var found bool
	for _, gap := range result.Gaps {
		if strings.Contains(gap.Reason, "keystore") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unopenable keystore produced no coverage gap: %+v", result.Gaps)
	}
}

func TestPKIReportsOversizedFilesAsGaps(t *testing.T) {
	dir := t.TempDir()
	engine := NewPKIEngine()
	engine.MaxFileBytes = 64

	writeFile(t, dir, "huge.pem", strings.Repeat("x", 4096))

	result := scanDir(t, engine, dir)

	if len(result.Gaps) != 1 || result.Gaps[0].Kind != "too_large" {
		t.Errorf("expected a too_large gap, got %+v", result.Gaps)
	}
}

// Evidence must never carry a host path.
func TestPKIEvidencePathsAreRelative(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "etc", "ssl")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeRSACertificate(t, certDir, 2048)

	for _, finding := range scanDir(t, NewPKIEngine(), dir).Findings {
		path := finding.Location.Path
		if filepath.IsAbs(path) || strings.Contains(path, dir) {
			t.Errorf("finding path is not relative to the target root: %q", path)
		}
		if !strings.HasPrefix(path, "etc/ssl/") {
			t.Errorf("path = %q, want a path under etc/ssl/", path)
		}
	}
}

// A directory with no crypto is a valid result, not an error.
func TestPKIOnCleanDirectoryYieldsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "# No cryptography here\n")
	writeFile(t, dir, "notes.txt", "We considered TLS but this is plain text.\n")

	result := scanDir(t, NewPKIEngine(), dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

// A .pem file that is not actually PEM must not produce a finding.
func TestPKIIgnoresMalformedPEM(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "broken.pem", "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n")

	result := scanDir(t, NewPKIEngine(), dir)

	if len(result.Findings) != 0 {
		t.Errorf("malformed PEM produced %d findings", len(result.Findings))
	}
}

// A CSR is a request, not a deployed credential.
func TestPKIIgnoresCertificateRequests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "request.csr",
		"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")

	if len(scanDir(t, NewPKIEngine(), dir).Findings) != 0 {
		t.Error("a certificate request was reported as an artefact")
	}
}

func TestPKIRejectsImageTargets(t *testing.T) {
	// This engine reads a filesystem; an image target must be refused so the
	// registry reports it as a gap rather than an empty result.
	if NewPKIEngine().SupportsImages() {
		t.Error("PKI engine claims image support it does not have")
	}
	if _, err := NewPKIEngine().Scan(context.Background(), Target{ImageReference: "alpine:3"}); err == nil {
		t.Error("expected an error for an image target")
	}
}
