package engine

import (
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

func TestConfigFindsDeclaredTLSVersions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nginx.conf", nginxConfig)

	result := scanDir(t, NewConfigEngine(), dir)
	protocols := findByType(result.Findings, cbom.AssetProtocol)

	if len(protocols) == 0 {
		t.Fatal("no protocol findings from an nginx config declaring TLS")
	}

	versions := map[string]bool{}
	for _, protocol := range protocols {
		if protocol.ParameterSet != "" {
			versions[protocol.ParameterSet] = true
		}
	}
	for _, want := range []string{"1.2", "1.3"} {
		if !versions[want] {
			t.Errorf("TLS %s was declared but not detected; got %v", want, versions)
		}
	}
}

// A commented directive is documentation, not configuration -- the config-file
// equivalent of matching a bare identifier in source.
func TestConfigIgnoresCommentedDirectives(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nginx.conf", nginxConfig)

	for _, finding := range scanDir(t, NewConfigEngine(), dir).Findings {
		if finding.ParameterSet == "1.0" || finding.ParameterSet == "1.1" {
			t.Errorf("a commented-out TLS version produced a finding: %+v", finding)
		}
	}
}

func TestConfigOnCleanFileYieldsNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nginx.conf", cleanConfig)

	result := scanDir(t, NewConfigEngine(), dir)

	if len(result.Findings) != 0 {
		t.Errorf("a plain HTTP config produced %d findings: %+v",
			len(result.Findings), result.Findings)
	}
}

// TLS 1.0 is a finding in its own right, so a legacy floor must be visible.
func TestConfigDetectsLegacyTLSFloor(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openssl.cnf", legacyConfig)

	var found bool
	for _, finding := range scanDir(t, NewConfigEngine(), dir).Findings {
		if finding.ParameterSet == "1.0" {
			found = true
		}
	}
	if !found {
		t.Error("MinProtocol = TLSv1.0 was not detected")
	}
}

func TestConfigDetectsCipherSuites(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nginx.conf", nginxConfig)

	var suites int
	for _, finding := range scanDir(t, NewConfigEngine(), dir).Findings {
		if strings.Contains(finding.Snippet, "cipher suite") {
			suites++
		}
	}
	if suites == 0 {
		t.Error("declared cipher suites were not detected")
	}
}

func TestConfigDetectsSSHAlgorithms(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sshd_config", sshdConfig)

	findings := scanDir(t, NewConfigEngine(), dir).Findings
	if len(findings) == 0 {
		t.Fatal("no findings from an sshd_config declaring algorithms")
	}

	var kex bool
	for _, finding := range findings {
		if finding.Algorithm != "ssh" {
			t.Errorf("algorithm = %q, want ssh", finding.Algorithm)
		}
		if strings.Contains(finding.Snippet, "KexAlgorithms") {
			kex = true
		}
	}
	if !kex {
		t.Error("KexAlgorithms was not detected")
	}
}

// Declared crypto is not observed crypto. The distinction must survive to the
// evidence, because a load balancer can accept protocols the config forbids.
func TestConfigFindingsAreMarkedDeclared(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nginx.conf", nginxConfig)

	for _, finding := range scanDir(t, NewConfigEngine(), dir).Findings {
		if !strings.Contains(finding.Snippet, "declared") {
			t.Errorf("finding does not state that it is declared, not observed: %q",
				finding.Snippet)
		}
		if finding.DetectionMethod != cbom.DetectConfigParse {
			t.Errorf("detection method = %q, want config_parse", finding.DetectionMethod)
		}
		// Medium, never high: another config can shadow this one.
		if finding.Confidence != cbom.ConfidenceMedium {
			t.Errorf("confidence = %q, want medium", finding.Confidence)
		}
	}
}

func TestNormaliseTLSVersion(t *testing.T) {
	cases := []struct {
		full     string
		captured string
		want     string
	}{
		{"TLSv1.2", "1.2", "1.2"},
		{"TLSv1.3", "1.3", "1.3"},
		{"TLSv1", "1", "1.0"},
		{"SSLv3", "3", "SSLv3"},
		{"SSLv2", "2", "SSLv2"},
		// A bare number that is not a protocol version must not become one.
		{"TLSv9.9", "9.9", ""},
		{"TLS 42", "42", ""},
	}

	for _, tc := range cases {
		t.Run(tc.full, func(t *testing.T) {
			if got := normaliseTLSVersion(tc.full, tc.captured); got != tc.want {
				t.Errorf("normaliseTLSVersion(%q,%q) = %q, want %q",
					tc.full, tc.captured, got, tc.want)
			}
		})
	}
}

func TestConfigIgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	// Contains TLS text but is not a configuration file Trinetra reads.
	writeFile(t, dir, "notes.txt", "ssl_protocols TLSv1.0;\n")

	if len(scanDir(t, NewConfigEngine(), dir).Findings) != 0 {
		t.Error("a non-config file was parsed as configuration")
	}
}
