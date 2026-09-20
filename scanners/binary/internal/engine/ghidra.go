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

// GhidraEngine wraps Ghidra for crypto constant and API call detection in
// stripped binaries.
//
// It detects:
// - AES S-boxes (256-byte tables with specific patterns)
// - SHA-256 initialization vectors (specific 32-byte constants)
// - MD5 magic constants
// - DES S-boxes
// - Crypto API calls (even in stripped binaries via pattern matching)
type GhidraEngine struct {
	binary     string
	scriptPath string
}

// NewGhidraEngine creates a Ghidra analysis engine.
func NewGhidraEngine() *GhidraEngine {
	binary := os.Getenv("TRINETRA_GHIDRA_BINARY")
	if binary == "" {
		binary = "analyzeHeadless"
	}
	scriptPath := os.Getenv("TRINETRA_GHIDRA_SCRIPT_PATH")
	if scriptPath == "" {
		scriptPath = "/opt/trinetra/ghidra-scripts"
	}
	return &GhidraEngine{
		binary:     binary,
		scriptPath: scriptPath,
	}
}

func (e *GhidraEngine) Name() string { return "Ghidra" }

func (e *GhidraEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "NSA",
		Name:    "Ghidra",
		Version: detectGhidraVersion(e.binary),
	}
}

func (e *GhidraEngine) Available(ctx context.Context) error {
	path, err := exec.LookPath(e.binary)
	if err != nil {
		return fmt.Errorf("Ghidra not found (set TRINETRA_GHIDRA_BINARY): %w", err)
	}
	e.binary = path

	// Check if our crypto detection script exists
	scriptFile := filepath.Join(e.scriptPath, "CryptoDetector.java")
	if _, err := os.Stat(scriptFile); err != nil {
		return fmt.Errorf("Ghidra crypto detection script not found at %s: %w", scriptFile, err)
	}

	return nil
}

func (e *GhidraEngine) Languages() []string {
	return []string{"binary", "ELF", "PE", "Mach-O"}
}

func (e *GhidraEngine) Scan(ctx context.Context, root string) (Result, error) {
	var result Result

	// Find all binary files in the root
	binaries, err := findBinaries(root)
	if err != nil {
		return result, fmt.Errorf("find binaries: %w", err)
	}

	if len(binaries) == 0 {
		result.Gaps = append(result.Gaps, Gap{
			Kind:   "no_binaries",
			Reason: "No binary files found in target",
			Count:  1,
		})
		return result, nil
	}

	// Create temp directory for Ghidra project
	tmpDir, err := os.MkdirTemp("", "ghidra-*")
	if err != nil {
		return result, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	projectName := "trinetra-scan"
	outputFile := filepath.Join(tmpDir, "findings.json")

	// Analyze each binary
	for _, binary := range binaries {
		findings, gaps := e.analyzeBinary(ctx, binary, projectName, tmpDir, outputFile)
		result.Findings = append(result.Findings, findings...)
		result.Gaps = append(result.Gaps, gaps...)
		result.FilesScanned++
	}

	return result, nil
}

func (e *GhidraEngine) analyzeBinary(ctx context.Context, binaryPath, projectName, projectDir, outputFile string) ([]cbom.Finding, []Gap) {
	// analyzeHeadless <project_dir> <project_name> -import <binary> -postScript CryptoDetector.java <output_file>
	cmd := exec.CommandContext(ctx, e.binary,
		projectDir, projectName,
		"-import", binaryPath,
		"-scriptPath", e.scriptPath,
		"-postScript", "CryptoDetector.java", outputFile,
		"-deleteProject", // Clean up after analysis
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, []Gap{{
			Path:   binaryPath,
			Kind:   "ghidra_failed",
			Reason: fmt.Sprintf("Ghidra analysis failed: %v: %s", err, output),
			Count:  1,
		}}
	}

	// Parse the findings from the output JSON
	findings, err := e.parseGhidraOutput(outputFile, binaryPath)
	if err != nil {
		return nil, []Gap{{
			Path:   binaryPath,
			Kind:   "parse_failed",
			Reason: fmt.Sprintf("Failed to parse Ghidra output: %v", err),
			Count:  1,
		}}
	}

	return findings, nil
}

type ghidraFinding struct {
	Type      string `json:"type"`      // "constant", "api_call", "library"
	Algorithm string `json:"algorithm"` // "AES", "SHA256", "RSA", etc.
	Address   string `json:"address"`   // Memory address where found
	Value     string `json:"value"`     // Hex representation or function name
	KeySize   int    `json:"key_size,omitempty"`
	Note      string `json:"note,omitempty"`
}

func (e *GhidraEngine) parseGhidraOutput(outputFile, binaryPath string) ([]cbom.Finding, error) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No findings is valid
			return nil, nil
		}
		return nil, err
	}

	var ghidraFindings []ghidraFinding
	if err := json.Unmarshal(data, &ghidraFindings); err != nil {
		return nil, err
	}

	var findings []cbom.Finding
	for _, gf := range ghidraFindings {
		finding := e.convertGhidraFinding(gf, binaryPath)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

func (e *GhidraEngine) convertGhidraFinding(gf ghidraFinding, binaryPath string) *cbom.Finding {
	location := fmt.Sprintf("%s@%s", filepath.Base(binaryPath), gf.Address)

	switch gf.Type {
	case "constant":
		return &cbom.Finding{
			AssetType:  cbom.AssetImplementation,
			Primitive:  determinePrimitive(gf.Algorithm),
			Name:       fmt.Sprintf("%s constant", gf.Algorithm),
			Algorithm:  gf.Algorithm,
			KeySize:    intPtrIfNonZero(gf.KeySize),
			Location:   location,
			Snippet:    truncateHex(gf.Value),
			Note:       fmt.Sprintf("Ghidra detected %s: %s", gf.Type, gf.Note),
			Confidence: cbom.ConfidenceMedium, // Constants are indicators, not proof
		}

	case "api_call":
		return &cbom.Finding{
			AssetType:  cbom.AssetCall,
			Primitive:  determinePrimitive(gf.Algorithm),
			Name:       gf.Value, // Function name
			Algorithm:  gf.Algorithm,
			KeySize:    intPtrIfNonZero(gf.KeySize),
			Location:   location,
			Snippet:    fmt.Sprintf("call to %s", gf.Value),
			Note:       fmt.Sprintf("Crypto API call detected: %s", gf.Note),
			Confidence: cbom.ConfidenceHigh,
		}

	case "library":
		// Linked crypto library
		return &cbom.Finding{
			AssetType:  cbom.AssetLibrary,
			Name:       gf.Value, // Library name
			Location:   binaryPath,
			Snippet:    fmt.Sprintf("linked: %s", gf.Value),
			Note:       "Crypto library dependency",
			Confidence: cbom.ConfidenceHigh,
			// Libraries never carry an algorithm (invariant)
		}

	default:
		return nil
	}
}

func determinePrimitive(algorithm string) cbom.Primitive {
	algo := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(algo, "AES"), strings.Contains(algo, "DES"), strings.Contains(algo, "CHACHA"):
		return cbom.PrimitiveBlockCipher
	case strings.Contains(algo, "SHA"), strings.Contains(algo, "MD5"), strings.Contains(algo, "BLAKE"):
		return cbom.PrimitiveHash
	case strings.Contains(algo, "RSA"), strings.Contains(algo, "ECDSA"), strings.Contains(algo, "ED25519"):
		return cbom.PrimitiveAsymmetric
	case strings.Contains(algo, "HMAC"):
		return cbom.PrimitiveMAC
	default:
		return cbom.Primitive("") // Unknown
	}
}

func intPtrIfNonZero(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

func truncateHex(hex string) string {
	if len(hex) > 64 {
		return hex[:64] + "..."
	}
	return hex
}

func findBinaries(root string) ([]string, error) {
	var binaries []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Check if file is a binary (ELF, PE, Mach-O, or executable)
		if isBinary(path, info) {
			binaries = append(binaries, path)
		}

		return nil
	})

	return binaries, err
}

func isBinary(path string, info os.FileInfo) bool {
	// Check file extension and executable bit
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".elf":
		return true
	case "": // No extension - check if executable
		return info.Mode()&0111 != 0
	}

	// Check magic bytes for binary formats
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return false
	}

	// ELF: 0x7F 'E' 'L' 'F'
	if magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return true
	}

	// PE: 'M' 'Z'
	if magic[0] == 'M' && magic[1] == 'Z' {
		return true
	}

	// Mach-O: 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE
	if (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && (magic[3] == 0xCE || magic[3] == 0xCF)) ||
		(magic[0] == 0xCE && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
		(magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) {
		return true
	}

	return false
}

func detectGhidraVersion(binary string) string {
	cmd := exec.Command(binary, "-help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}

	// Parse version from help output
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version") || strings.Contains(line, "version") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if (strings.Contains(f, "Version") || strings.Contains(f, "version")) && i+1 < len(fields) {
					return fields[i+1]
				}
			}
		}
	}
	return "unknown"
}
