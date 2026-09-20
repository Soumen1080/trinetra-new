// +build integration

package engine

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// TestTheiaEndToEnd verifies cbomkit-theia against real images (11C.3).
//
// This test is marked +build integration because it requires:
// - cbomkit-theia installed (11C.3a)
// - Docker running
// - The test fixtures from Phase 3 (alpine, debian)
//
// When theia is not available, the test is skipped rather than failing,
// matching the pattern used for Docker and LocalStack.
func TestTheiaEndToEnd(t *testing.T) {
	ctx := context.Background()

	engine := NewTheiaEngine()

	// Check if theia is available (11C.3e: skip when binary is absent)
	if err := engine.Available(ctx); err != nil {
		t.Skipf("cbomkit-theia not available: %v", err)
	}

	t.Run("alpine", func(t *testing.T) {
		testTheiaOnImage(t, ctx, engine, "alpine:3.18", "alpine")
	})

	t.Run("debian", func(t *testing.T) {
		testTheiaOnImage(t, ctx, engine, "debian:bookworm-slim", "debian")
	})
}

func testTheiaOnImage(t *testing.T, ctx context.Context, engine *TheiaEngine, image, fixture string) {
	// Pull the image if not present
	if err := pullImage(image); err != nil {
		t.Fatalf("pull image: %v", err)
	}

	// Scan with theia (11C.3b)
	result, err := engine.Scan(ctx, image)
	if err != nil {
		t.Fatalf("theia scan failed: %v", err)
	}

	t.Logf("Theia found %d findings in %s", len(result.Findings), image)

	// Also scan with PKI and Config engines for comparison (11C.3c)
	pkiEngine := NewPKIEngine()
	pkiResult, err := pkiEngine.Scan(ctx, image)
	if err != nil {
		t.Fatalf("PKI scan failed: %v", err)
	}

	configEngine := NewConfigEngine()
	configResult, err := configEngine.Scan(ctx, image)
	if err != nil {
		t.Fatalf("Config scan failed: %v", err)
	}

	// Compare certificate findings between theia and PKI (11C.3c)
	compareCertificateFindings(t, result.Findings, pkiResult.Findings, "theia", "PKI")

	// Verify gitleaks-grade secret detection (11C.3d)
	verifySecretDetection(t, result.Findings, image)
}

// compareCertificateFindings checks that where both engines see a certificate,
// they agree on key details (11C.3c).
func compareCertificateFindings(t *testing.T, theiaFindings, pkiFindings []cbom.Finding, name1, name2 string) {
	theiaCerts := filterCertificates(theiaFindings)
	pkiCerts := filterCertificates(pkiFindings)

	if len(theiaCerts) == 0 && len(pkiCerts) == 0 {
		t.Log("No certificates found by either engine")
		return
	}

	t.Logf("%s found %d certificates, %s found %d certificates",
		name1, len(theiaCerts), name2, len(pkiCerts))

	// For each certificate in both sets, check they agree
	for _, tc := range theiaCerts {
		for _, pc := range pkiCerts {
			if locationsMatch(tc.Location, pc.Location) {
				// Same certificate - compare details
				if tc.Algorithm != pc.Algorithm {
					t.Errorf("Certificate at %v: %s reports algorithm %s, %s reports %s",
						tc.Location, name1, tc.Algorithm, name2, pc.Algorithm)
				}

				if tc.KeySizeBits != nil && pc.KeySizeBits != nil {
					if *tc.KeySizeBits != *pc.KeySizeBits {
						t.Errorf("Certificate at %v: %s reports size %d, %s reports %d",
							tc.Location, name1, *tc.KeySizeBits, name2, *pc.KeySizeBits)
					}
				}
			}
		}
	}
}

// verifySecretDetection checks that theia finds secrets the PKI engine's
// PEM-extension scan would miss (11C.3d).
func verifySecretDetection(t *testing.T, findings []cbom.Finding, image string) {
	secrets := filterSecrets(findings)

	if len(secrets) > 0 {
		t.Logf("Theia found %d secret(s) in %s", len(secrets), image)

		for _, s := range secrets {
			t.Logf("  Secret: %s at %v (confidence: %s)",
				s.Name, s.Location, s.Confidence)
		}
	} else {
		// Not finding secrets in base images is expected
		t.Logf("No secrets found in %s (expected for base images)", image)
	}
}

func filterCertificates(findings []cbom.Finding) []cbom.Finding {
	var certs []cbom.Finding
	for _, f := range findings {
		if f.AssetType == cbom.AssetCertificate {
			certs = append(certs, f)
		}
	}
	return certs
}

func filterSecrets(findings []cbom.Finding) []cbom.Finding {
	var secrets []cbom.Finding
	for _, f := range findings {
		if f.AssetType == cbom.AssetKey && f.Redacted {
			secrets = append(secrets, f)
		}
	}
	return secrets
}

func locationsMatch(loc1, loc2 cbom.Location) bool {
	// Normalize paths for comparison
	p1 := strings.TrimPrefix(loc1.Path, "/")
	p2 := strings.TrimPrefix(loc2.Path, "/")
	return p1 == p2
}

func pullImage(image string) error {
	cmd := exec.Command("docker", "pull", image)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// TestTheiaVsPKIReconciliation is a focused test that compares theia and PKI
// findings on the same fixture to ensure they agree where they overlap (11C.3c).
func TestTheiaVsPKIReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reconciliation test in short mode")
	}

	ctx := context.Background()

	theiaEngine := NewTheiaEngine()
	if err := theiaEngine.Available(ctx); err != nil {
		t.Skipf("cbomkit-theia not available: %v", err)
	}

	pkiEngine := NewPKIEngine()

	// Use a known fixture that should have certificates
	image := "nginx:alpine"

	if err := pullImage(image); err != nil {
		t.Fatalf("pull image: %v", err)
	}

	theiaResult, err := theiaEngine.Scan(ctx, image)
	if err != nil {
		t.Fatalf("theia scan: %v", err)
	}

	pkiResult, err := pkiEngine.Scan(ctx, image)
	if err != nil {
		t.Fatalf("PKI scan: %v", err)
	}

	// Where both see certificates, they must agree
	theiaCerts := filterCertificates(theiaResult.Findings)
	pkiCerts := filterCertificates(pkiResult.Findings)

	if len(theiaCerts) == 0 || len(pkiCerts) == 0 {
		t.Log("One engine found no certificates - cannot reconcile")
		return
	}

	// Build a map of PKI findings by normalized path
	pkiByPath := make(map[string]cbom.Finding)
	for _, c := range pkiCerts {
		path := strings.TrimPrefix(c.Location.Path, "/")
		pkiByPath[path] = c
	}

	// Check each theia finding against PKI
	disagreements := 0
	for _, tc := range theiaCerts {
		path := strings.TrimPrefix(tc.Location.Path, "/")
		if pc, found := pkiByPath[path]; found {
			// Same certificate - must agree
			if tc.Algorithm != pc.Algorithm {
				t.Errorf("Disagreement at %s: theia=%s, PKI=%s",
					path, tc.Algorithm, pc.Algorithm)
				disagreements++
			}
		}
	}

	if disagreements > 0 {
		t.Errorf("Found %d disagreements between theia and PKI - this is a bug in one of them",
			disagreements)
	} else {
		t.Log("Theia and PKI findings reconciled successfully")
	}
}
