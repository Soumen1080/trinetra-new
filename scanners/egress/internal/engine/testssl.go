package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// TestSSLEngine wraps testssl.sh for live TLS protocol observation.
//
// Everything this engine finds has `is_observed=true` by construction, which
// distinguishes it from the config engine's declared findings. The difference
// matters: a load balancer can accept TLS 1.0 even when the backend forbids it.
type TestSSLEngine struct {
	binary string
}

// NewTestSSLEngine creates a testssl.sh engine.
func NewTestSSLEngine() *TestSSLEngine {
	binary := os.Getenv("TRINETRA_TESTSSL_BINARY")
	if binary == "" {
		binary = "testssl.sh"
	}
	return &TestSSLEngine{binary: binary}
}

func (e *TestSSLEngine) Name() string { return "testssl.sh" }

func (e *TestSSLEngine) Tool() cbom.Tool {
	// Version detection from testssl.sh --version
	return cbom.Tool{
		Vendor:  "testssl.sh",
		Name:    "testssl",
		Version: detectTestSSLVersion(e.binary),
	}
}

func (e *TestSSLEngine) Available(ctx context.Context) error {
	path, err := exec.LookPath(e.binary)
	if err != nil {
		return fmt.Errorf("testssl.sh not found (set TRINETRA_TESTSSL_BINARY): %w", err)
	}
	e.binary = path
	return nil
}

func (e *TestSSLEngine) Scan(ctx context.Context, endpoint string) (Result, error) {
	// testssl.sh --jsonfile output.json host:port
	tmpDir, err := os.MkdirTemp("", "testssl-*")
	if err != nil {
		return Result{}, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "output.json")

	cmd := exec.CommandContext(ctx, e.binary,
		"--jsonfile", outFile,
		"--quiet",
		"--warnings", "off",
		endpoint)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// testssl.sh exits non-zero for some findings; check if output exists
		if _, statErr := os.Stat(outFile); statErr != nil {
			return Result{}, fmt.Errorf("testssl.sh failed: %w: %s", err, output)
		}
	}

	// Parse the JSON output
	data, err := os.ReadFile(outFile)
	if err != nil {
		return Result{}, fmt.Errorf("read output: %w", err)
	}

	var testsslOutput []TestSSLRecord
	if err := json.Unmarshal(data, &testsslOutput); err != nil {
		return Result{}, fmt.Errorf("parse json: %w", err)
	}

	findings := e.parseFindings(testsslOutput, endpoint)

	return Result{
		Findings: findings,
		Gaps:     nil,
	}, nil
}

// TestSSLRecord represents one testssl.sh JSON finding
type TestSSLRecord struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve,omitempty"`
}

func (e *TestSSLEngine) parseFindings(records []TestSSLRecord, endpoint string) []cbom.Finding {
	var findings []cbom.Finding

	protocolMap := make(map[string]bool)
	cipherMap := make(map[string]bool)
	var certKeyType string
	var certKeySize int

	for _, rec := range records {
		switch {
		case strings.Contains(rec.ID, "TLS1") || strings.Contains(rec.ID, "SSLv"):
			// Protocol version
			protocol := extractProtocol(rec.ID, rec.Finding)
			if protocol != "" && !protocolMap[protocol] {
				protocolMap[protocol] = true
				findings = append(findings, cbom.Finding{
					AssetType:  cbom.AssetProtocol,
					Name:       "TLS",
					Algorithm:  protocol,
					Location:   endpoint,
					Snippet:    fmt.Sprintf("observed: %s", rec.Finding),
					Note:       "Live TLS handshake observation",
					Confidence: cbom.ConfidenceHigh,
					IsObserved: true,
				})
			}

		case strings.Contains(rec.ID, "cipher"):
			// Cipher suite
			cipher := extractCipher(rec.Finding)
			if cipher != "" && !cipherMap[cipher] {
				cipherMap[cipher] = true
				findings = append(findings, cbom.Finding{
					AssetType:  cbom.AssetProtocol,
					Name:       "TLS-Cipher",
					Algorithm:  cipher,
					Location:   endpoint,
					Snippet:    fmt.Sprintf("observed: %s", rec.Finding),
					Note:       "Negotiated cipher suite",
					Confidence: cbom.ConfidenceHigh,
					IsObserved: true,
				})
			}

		case strings.Contains(rec.ID, "cert") && strings.Contains(rec.ID, "key"):
			// Certificate key type
			kt, ks := extractKeyInfo(rec.Finding)
			if kt != "" {
				certKeyType = kt
				certKeySize = ks
			}
		}
	}

	// Add certificate key finding if detected
	if certKeyType != "" {
		findings = append(findings, cbom.Finding{
			AssetType:  cbom.AssetCertificate,
			Primitive:  cbom.PrimitiveAsymmetric,
			Name:       "Server Certificate",
			Algorithm:  certKeyType,
			KeySize:    cbom.IntPtr(certKeySize),
			Location:   endpoint,
			Snippet:    fmt.Sprintf("observed certificate key: %s-%d", certKeyType, certKeySize),
			Note:       "Live certificate observation",
			Confidence: cbom.ConfidenceHigh,
			IsObserved: true,
		})
	}

	// Detect hybrid PQC KEX
	for _, rec := range records {
		if strings.Contains(strings.ToLower(rec.Finding), "x25519mlkem768") ||
			strings.Contains(strings.ToLower(rec.Finding), "mlkem") {
			findings = append(findings, cbom.Finding{
				AssetType:  cbom.AssetProtocol,
				Primitive:  cbom.PrimitiveKEM,
				Name:       "TLS-KEX",
				Algorithm:  "X25519MLKEM768",
				Location:   endpoint,
				Snippet:    fmt.Sprintf("observed: %s", rec.Finding),
				Note:       "Hybrid post-quantum key exchange detected",
				Confidence: cbom.ConfidenceHigh,
				IsObserved: true,
			})
			break
		}
	}

	return findings
}

func extractProtocol(id, finding string) string {
	// Extract protocol version from testssl.sh output
	if strings.Contains(id, "TLSv1_3") || strings.Contains(finding, "TLS 1.3") {
		return "TLSv1.3"
	}
	if strings.Contains(id, "TLSv1_2") || strings.Contains(finding, "TLS 1.2") {
		return "TLSv1.2"
	}
	if strings.Contains(id, "TLSv1_1") || strings.Contains(finding, "TLS 1.1") {
		return "TLSv1.1"
	}
	if strings.Contains(id, "TLSv1") || strings.Contains(finding, "TLS 1.0") {
		return "TLSv1.0"
	}
	if strings.Contains(id, "SSLv3") || strings.Contains(finding, "SSL 3") {
		return "SSLv3"
	}
	return ""
}

func extractCipher(finding string) string {
	// Extract cipher suite name from finding
	// testssl.sh typically reports cipher suites in the format:
	// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	fields := strings.Fields(finding)
	for _, f := range fields {
		if strings.HasPrefix(f, "TLS_") || strings.HasPrefix(f, "ECDHE") {
			return strings.TrimSuffix(f, ",")
		}
	}
	return ""
}

func extractKeyInfo(finding string) (string, int) {
	// Extract key type and size from certificate findings
	// Example: "RSA 2048 bits", "ECDSA P-256"
	finding = strings.ToUpper(finding)

	if strings.Contains(finding, "RSA") {
		if strings.Contains(finding, "2048") {
			return "RSA", 2048
		}
		if strings.Contains(finding, "4096") {
			return "RSA", 4096
		}
		if strings.Contains(finding, "3072") {
			return "RSA", 3072
		}
		return "RSA", 0
	}

	if strings.Contains(finding, "ECDSA") || strings.Contains(finding, "EC") {
		if strings.Contains(finding, "256") || strings.Contains(finding, "P-256") {
			return "ECDSA", 256
		}
		if strings.Contains(finding, "384") || strings.Contains(finding, "P-384") {
			return "ECDSA", 384
		}
		return "ECDSA", 0
	}

	if strings.Contains(finding, "ED25519") {
		return "Ed25519", 256
	}

	return "", 0
}

func detectTestSSLVersion(binary string) string {
	cmd := exec.Command(binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	// Parse version from output
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "testssl.sh") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return "unknown"
}
