package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/trinetra/cbom-go/cbom"
)

// OSVEngine wraps OSV-Scanner for CVE detection in dependencies.
//
// This provides *present-tense* risk (what is vulnerable today) alongside
// Trinetra's future quantum risk verdict. The two are kept clearly separated
// so they are never confused.
//
// Per §7.1, OSV is an evidence source, not a verdict source. A CVE is reported
// as a finding with confidence based on how certain the match is.
type OSVEngine struct {
	binary string
}

// NewOSVEngine creates an OSV-Scanner engine.
func NewOSVEngine() *OSVEngine {
	binary := os.Getenv("TRINETRA_OSV_BINARY")
	if binary == "" {
		binary = "osv-scanner"
	}
	return &OSVEngine{binary: binary}
}

func (e *OSVEngine) Name() string { return "OSV-Scanner" }

func (e *OSVEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Google",
		Name:    "osv-scanner",
		Version: detectOSVVersion(e.binary),
	}
}

func (e *OSVEngine) Available(ctx context.Context) error {
	path, err := exec.LookPath(e.binary)
	if err != nil {
		return fmt.Errorf("osv-scanner not found (set TRINETRA_OSV_BINARY): %w", err)
	}
	e.binary = path
	return nil
}

func (e *OSVEngine) Languages() []string {
	return []string{"Go", "Python", "Node.js", "Rust", "Java", "Ruby", "PHP"}
}

func (e *OSVEngine) Scan(ctx context.Context, root string) (Result, error) {
	// Create temp file for JSON output
	tmpFile, err := os.CreateTemp("", "osv-*.json")
	if err != nil {
		return Result{}, fmt.Errorf("temp file: %w", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Run osv-scanner with JSON output
	// osv-scanner --format=json --output=file.json /path/to/scan
	cmd := exec.CommandContext(ctx, e.binary,
		"--format=json",
		"--output="+tmpFile.Name(),
		"--recursive",
		root)

	output, err := cmd.CombinedOutput()
	// OSV-Scanner exits non-zero when vulnerabilities are found, which is expected
	if err != nil && !isOSVExpectedError(output) {
		return Result{}, fmt.Errorf("osv-scanner failed: %w: %s", err, output)
	}

	// Parse the JSON output
	findings, gaps, filesScanned := e.parseOSVOutput(tmpFile.Name(), root)

	return Result{
		Findings:     findings,
		Gaps:         gaps,
		FilesScanned: filesScanned,
	}, nil
}

type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source  string            `json:"source"`
	Package osvPackage        `json:"package"`
	Vulns   []osvVulnerability `json:"vulnerabilities"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity string   `json:"severity,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
}

func (e *OSVEngine) parseOSVOutput(outputFile, root string) ([]cbom.Finding, []Gap, int) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No output = no vulnerabilities found
			return nil, nil, 0
		}
		return nil, []Gap{{
			Kind:   "osv_parse_failed",
			Reason: fmt.Sprintf("Failed to read OSV output: %v", err),
			Count:  1,
		}}, 0
	}

	var output osvOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, []Gap{{
			Kind:   "osv_parse_failed",
			Reason: fmt.Sprintf("Failed to parse OSV JSON: %v", err),
			Count:  1,
		}}, 0
	}

	var findings []cbom.Finding
	filesScanned := 0
	uniqueSources := make(map[string]bool)

	for _, result := range output.Results {
		// Count unique files scanned
		if !uniqueSources[result.Source] {
			uniqueSources[result.Source] = true
			filesScanned++
		}

		// Create a finding for each vulnerability
		for _, vuln := range result.Vulns {
			findings = append(findings, e.convertOSVFinding(result, vuln, root))
		}
	}

	return findings, nil, filesScanned
}

func (e *OSVEngine) convertOSVFinding(result osvResult, vuln osvVulnerability, root string) cbom.Finding {
	// Make the source path relative to root
	relPath := result.Source
	if rel, err := filepath.Rel(root, result.Source); err == nil {
		relPath = rel
	}

	// Build a descriptive note
	note := fmt.Sprintf("CVE in %s@%s: %s", result.Package.Name, result.Package.Version, vuln.Summary)
	if vuln.Severity != "" {
		note += fmt.Sprintf(" (severity: %s)", vuln.Severity)
	}

	// CVE findings are a special type - they're not crypto findings per se,
	// but dependency vulnerabilities. We'll use a custom asset type or note field.
	return cbom.Finding{
		AssetType: cbom.AssetLibrary, // The vulnerable component is a library
		Name:      result.Package.Name,
		Location:  relPath,
		Snippet:   vuln.ID, // Store CVE ID in snippet
		Note:      note,
		Confidence: cbom.ConfidenceHigh, // OSV data is authoritative
		// We don't set Algorithm here because this is a CVE, not a crypto usage
		// The CVE ID is stored in Snippet for later filtering/display
	}
}

func isOSVExpectedError(output []byte) bool {
	// OSV-Scanner exits 1 when vulnerabilities are found
	// This is expected and not an error condition for us
	outStr := string(output)
	return len(output) > 0 && (
		// Common expected messages
		containsAny(outStr, "vulnerabilities found", "Scanned", "packages"))
}

func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if len(s) > 0 && len(substr) > 0 {
			// Basic substring check
			if len(s) >= len(substr) {
				for i := 0; i <= len(s)-len(substr); i++ {
					match := true
					for j := 0; j < len(substr); j++ {
						if s[i+j] != substr[j] {
							match = false
							break
						}
					}
					if match {
						return true
					}
				}
			}
		}
	}
	return false
}

func detectOSVVersion(binary string) string {
	cmd := exec.Command(binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	// OSV-Scanner version output: "osv-scanner version: v1.x.x"
	outStr := string(out)
	if idx := stringIndex(outStr, "version:"); idx >= 0 {
		version := outStr[idx+8:]
		if endIdx := stringIndex(version, "\n"); endIdx >= 0 {
			version = version[:endIdx]
		}
		return trim(version)
	}
	return "unknown"
}

func stringIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
