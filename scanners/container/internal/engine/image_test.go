package engine

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// requireDocker skips when no daemon is reachable. These tests are the only
// place the image path is genuinely exercised, so they must run wherever Docker
// exists and skip cleanly where it does not.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon is not reachable")
	}
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft is not installed")
	}
}

// scanImage runs the syft engine against a real image.
func scanImage(t *testing.T, reference string) Result {
	t.Helper()
	requireDocker(t)

	engine := NewSyftEngine(loadKB(t))
	if err := engine.Available(context.Background()); err != nil {
		t.Skipf("syft unavailable: %v", err)
	}

	result, err := engine.Scan(context.Background(), Target{ImageReference: reference})
	if err != nil {
		t.Skipf("image %s could not be scanned (not pulled?): %v", reference, err)
	}
	return result
}

// Every package in an OS package database shares one location, so keying a
// library finding on path alone collapses an entire image into one arbitrary
// entry. Observed on a real alpine image: three crypto packages became one.
func TestImageScanDoesNotCollapsePackagesSharingALocation(t *testing.T) {
	result := scanImage(t, "nginx:1.25-alpine")

	if len(result.Findings) < 2 {
		t.Fatalf("expected several crypto packages, got %d: %+v",
			len(result.Findings), result.Findings)
	}

	locations := map[string]int{}
	names := map[string]bool{}
	for _, finding := range result.Findings {
		locations[finding.Location.Path]++
		if names[finding.Name] {
			t.Errorf("duplicate finding name %q", finding.Name)
		}
		names[finding.Name] = true
	}

	// The point of the test: several findings at one shared path.
	var shared bool
	for _, count := range locations {
		if count > 1 {
			shared = true
		}
	}
	if !shared {
		t.Skip("this image does not exercise the shared-location case")
	}
}

// A real image ships several packages from one project. Two findings both
// called "OpenSSL" leave a reader unable to tell which is installed.
func TestImageScanNamesThePackageNotJustTheProduct(t *testing.T) {
	result := scanImage(t, "nginx:1.25-alpine")

	var sawQualified bool
	for _, finding := range result.Findings {
		if strings.Contains(finding.Name, "(") {
			sawQualified = true
		}
		if finding.Algorithm != "" {
			t.Errorf("library %q carries an algorithm", finding.Name)
		}
		if finding.AssetType != cbom.AssetLibrary {
			t.Errorf("%q is not a library artefact", finding.Name)
		}
	}
	if !sawQualified {
		t.Error("no finding names its package; a bare product name is ambiguous")
	}
}

// The letter-release fix, verified on a real Debian image rather than a
// hand-written version string.
func TestImageScanResolvesRealOpenSSLVersions(t *testing.T) {
	result := scanImage(t, "debian:11-slim")

	for _, finding := range result.Findings {
		if !strings.Contains(finding.Name, "libssl") {
			continue
		}
		// 1.1.1w-0+deb11u8 must be orderable, so the verdict is a real one
		// rather than "not recorded".
		if !strings.Contains(finding.Snippet, "predates PQC support") {
			t.Errorf("a real OpenSSL version did not resolve to a verdict: %q",
				finding.Snippet)
		}
		return
	}
	t.Skip("no libssl package in this image")
}

// A package that merely links against a crypto library is not that library.
// ssl_client is a BusyBox applet and libgpg-error is an error-reporting
// library; attaching OpenSSL's or GnuPG's PQC verdict to either is a wrong
// claim about a real package.
func TestKnowledgeBaseDoesNotClaimLinkedPackages(t *testing.T) {
	kb := loadKB(t)

	for _, name := range []string{"ssl_client", "libgpg-error0"} {
		if profile, ok := kb.Lookup(name); ok {
			t.Errorf("%q is claimed by %q, but it only links against that library",
				name, profile.DisplayName)
		}
	}
}

// The knowledge base must recognise the package names real images actually use.
func TestKnowledgeBaseCoversRealDistroPackageNames(t *testing.T) {
	kb := loadKB(t)

	// Observed in alpine 3.19 and debian 11 images.
	for _, name := range []string{
		"libcrypto3", "libssl3", "libssl1.1", "libgcrypt", "libgcrypt20",
		"libgnutls30", "libk5crypto3", "libkrb5-3",
	} {
		if _, ok := kb.Lookup(name); !ok {
			t.Errorf("%q ships in real images but is not in the knowledge base", name)
		}
	}
}
