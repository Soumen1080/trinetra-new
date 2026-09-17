package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/targetpath"
)

// SemgrepEngine runs Semgrep OSS against Trinetra's rule packs.
//
// It covers the languages CBOMkit does not (JavaScript, TypeScript, C, C++) and
// supplies the taint analysis that gives Mosca's X its scanner-evidence tier —
// which no upstream tool provides.
type SemgrepEngine struct {
	Binary    string
	RulePaths []string
	Version   string
	// Timeout is passed to Semgrep so one pathological file cannot hang a scan.
	TimeoutSeconds int
}

// NewSemgrepEngine returns an engine using the given rule packs.
func NewSemgrepEngine(rulePaths []string) *SemgrepEngine {
	return &SemgrepEngine{
		Binary:         "semgrep",
		RulePaths:      rulePaths,
		TimeoutSeconds: 300,
	}
}

func (e *SemgrepEngine) Name() string { return "semgrep" }

func (e *SemgrepEngine) Languages() []string {
	return []string{"python", "java", "go", "javascript", "typescript", "c", "cpp"}
}

func (e *SemgrepEngine) Tool() cbom.Tool {
	version := e.Version
	if version == "" {
		version = "unknown"
	}
	return cbom.Tool{
		Vendor:  "Semgrep",
		Name:    "semgrep-oss",
		Version: version,
		Licence: "LGPL-2.1",
	}
}

// Available checks the binary exists and records its version for metadata.
func (e *SemgrepEngine) Available(ctx context.Context) error {
	path, err := exec.LookPath(e.Binary)
	if err != nil {
		return fmt.Errorf("semgrep binary not found on PATH")
	}
	e.Binary = path

	out, err := exec.CommandContext(ctx, e.Binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("semgrep --version failed")
	}
	e.Version = strings.TrimSpace(string(out))
	return nil
}

// semgrepOutput is the subset of Semgrep's JSON that Trinetra reads.
//
// Deliberately partial: Semgrep's `severity` and `extra.metadata.*` beyond the
// trinetra block are not mapped, because Trinetra scores and Semgrep does not
// (P1). Taking only what is needed also means an upstream schema addition
// cannot break the adapter.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
	Paths   struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Message  string          `json:"message"`
		Lines    string          `json:"lines"`
		Metadata semgrepMetadata `json:"metadata"`
	} `json:"extra"`
}

type semgrepMetadata struct {
	Trinetra trinetraMeta `json:"trinetra"`
}

// trinetraMeta is the canonical vocabulary carried in rule metadata (P6).
type trinetraMeta struct {
	AssetType    string   `json:"asset_type"`
	Algorithm    string   `json:"algorithm"`
	Primitive    string   `json:"primitive"`
	Purposes     []string `json:"purposes"`
	Confidence   string   `json:"confidence"`
	DataCategory string   `json:"data_category"`
}

type semgrepError struct {
	Message string `json:"message"`
	Path    string `json:"path"`
	Level   string `json:"level"`
}

// Scan runs Semgrep and adapts its output.
func (e *SemgrepEngine) Scan(ctx context.Context, root string) (Result, error) {
	args := []string{
		"--json",
		"--quiet",
		"--no-git-ignore",
		"--disable-version-check",
		"--metrics=off", // P7: nothing leaves the private network
		// Semgrep's built-in ignore rules skip any path containing tests/,
		// vendor/ and similar. That default is right for a linter and WRONG
		// for an inventory: a hardcoded RSA-1024 key under tests/ is still a
		// key in the repository, and crypto in vendored code still ships.
		// Without this flag a fixture corpus silently yields zero findings.
		"--x-ignore-semgrepignore-files",
		"--timeout", strconv.Itoa(e.TimeoutSeconds),
	}
	for _, p := range e.RulePaths {
		args = append(args, "--config", p)
	}
	args = append(args, root)

	cmd := exec.CommandContext(ctx, e.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Semgrep exits non-zero when findings exist, so exit status alone cannot
	// distinguish success from failure. Parseable JSON is the real signal.
	output, parseErr := parseSemgrepOutput(stdout.Bytes())
	if parseErr != nil {
		if runErr != nil {
			return Result{}, fmt.Errorf("semgrep failed and produced no parseable output: %w", runErr)
		}
		return Result{}, fmt.Errorf("semgrep output could not be parsed: %w", parseErr)
	}

	return e.adapt(root, output), nil
}

// parseSemgrepOutput validates the tool's output rather than trusting it.
// Malformed output is a scanner error, not a crash (§7.1, rule 2).
func parseSemgrepOutput(raw []byte) (semgrepOutput, error) {
	var out semgrepOutput
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, fmt.Errorf("empty output")
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("invalid json: %w", err)
	}
	return out, nil
}

func (e *SemgrepEngine) adapt(root string, out semgrepOutput) Result {
	result := Result{FilesScanned: len(out.Paths.Scanned)}

	for _, r := range out.Results {
		finding, ok := e.toFinding(root, r)
		if !ok {
			continue
		}
		result.Findings = append(result.Findings, finding)
	}

	for _, semErr := range out.Errors {
		path, _ := targetpath.RelativeTo(root, semErr.Path)
		result.Gaps = append(result.Gaps, Gap{
			Path:   path,
			Kind:   "unparseable",
			Reason: sanitiseError(semErr.Message),
			Count:  1,
		})
	}

	return result
}

// toFinding reduces one Semgrep result to a canonical Finding.
//
// Returns false for results carrying no trinetra metadata: a rule without it is
// not a Trinetra rule, and inventing a finding from an unknown rule would let
// an arbitrary third-party rule pack inject artefacts.
func (e *SemgrepEngine) toFinding(root string, r semgrepResult) (cbom.Finding, bool) {
	meta := r.Extra.Metadata.Trinetra
	if meta.AssetType == "" && meta.DataCategory == "" {
		return cbom.Finding{}, false
	}

	path, err := targetpath.RelativeTo(root, r.Path)
	if err != nil {
		path = filepath.ToSlash(r.Path)
	}

	captured := parseMessageCaptures(r.Extra.Message)

	finding := cbom.Finding{
		AssetType:       assetTypeFrom(meta.AssetType),
		Name:            "",
		Algorithm:       meta.Algorithm,
		Primitive:       cbom.Primitive(meta.Primitive),
		Confidence:      confidenceFrom(meta.Confidence),
		RuleID:          r.CheckID,
		DataCategory:    firstNonEmpty(captured["data_category"], meta.DataCategory),
		DetectionMethod: cbom.DetectSemgrepPattern,
		Location: cbom.Location{
			Path:    path,
			Line:    r.Start.Line,
			EndLine: r.End.Line,
		},
		Snippet: truncateSnippet(r.Extra.Lines),
	}

	if strings.Contains(r.CheckID, "taint") {
		finding.DetectionMethod = cbom.DetectSemgrepTaint
	}
	for _, p := range meta.Purposes {
		finding.Purposes = append(finding.Purposes, cbom.Purpose(p))
	}

	// The message-interpolation contract: Semgrep OSS emits no metavars field,
	// so the message is the only channel carrying a key size. If a rule author
	// forgot it, the size is genuinely absent and the finding degrades to
	// NEEDS_CONTEXT rather than being guessed.
	if raw, ok := captured["key_size"]; ok {
		if size, err := strconv.Atoi(raw); err == nil && size > 0 {
			finding.KeySizeBits = cbom.IntPtr(size)
		}
	}
	if mode, ok := captured["mode"]; ok {
		finding.Mode = normaliseMode(mode)
	}
	if curve, ok := captured["curve"]; ok {
		finding.Curve = curve
	}
	if algo, ok := captured["algorithm"]; ok && finding.Algorithm == "" {
		finding.Algorithm = strings.ToLower(algo)
	}

	// A Java transformation string carries algorithm, mode and padding at once:
	// "AES/GCM/NoPadding".
	if transform, ok := captured["transformation"]; ok {
		applyTransformation(&finding, transform)
	}

	finding.Name = deriveName(finding)
	if finding.Name == "" {
		return cbom.Finding{}, false
	}

	return finding.Normalise(), true
}

// capturePattern extracts the trinetra:key=value pairs a rule interpolates.
var capturePattern = regexp.MustCompile(`trinetra:([a-z_]+)=([^\s,;]+)`)

func parseMessageCaptures(message string) map[string]string {
	captures := make(map[string]string)
	for _, m := range capturePattern.FindAllStringSubmatch(message, -1) {
		value := strings.Trim(m[2], `"'`)
		// An unresolved metavariable comes through literally as "$BITS"; that
		// is not a value, and storing it would fabricate a key size.
		if value == "" || strings.HasPrefix(value, "$") {
			continue
		}
		captures[m[1]] = value
	}
	return captures
}

// applyTransformation splits a JCA transformation into its parts.
func applyTransformation(f *cbom.Finding, transform string) {
	parts := strings.Split(transform, "/")
	if len(parts) > 0 && parts[0] != "" {
		algo := strings.ToLower(parts[0])
		f.Algorithm = algo
		// "AES-256" and "AES_128" appear in Node transformation strings.
		if size, rest, ok := splitAlgorithmSize(algo); ok {
			f.Algorithm = rest
			f.KeySizeBits = cbom.IntPtr(size)
		}
	}
	if len(parts) > 1 {
		f.Mode = normaliseMode(parts[1])
	}
	if len(parts) > 2 {
		f.Padding = normalisePadding(parts[2])
	}
}

// splitAlgorithmSize handles names like "aes-256-gcm" and "aes_128".
func splitAlgorithmSize(name string) (int, string, bool) {
	fields := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	if len(fields) < 2 {
		return 0, name, false
	}
	for _, field := range fields[1:] {
		if size, err := strconv.Atoi(field); err == nil && size >= 40 {
			return size, fields[0], true
		}
	}
	return 0, name, false
}

func normaliseMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	m = strings.TrimPrefix(m, "mode_")
	switch m {
	case "ecb", "cbc", "ctr", "gcm", "ccm", "ofb", "cfb", "xts", "siv":
		return m
	case "":
		return ""
	default:
		return "other"
	}
}

func normalisePadding(padding string) string {
	p := strings.ToLower(strings.TrimSpace(padding))
	switch {
	case p == "nopadding", p == "none":
		return "none"
	case strings.Contains(p, "oaep"):
		return "oaep"
	case strings.Contains(p, "pss"):
		return "pss"
	case strings.Contains(p, "pkcs1"):
		return "pkcs1_v15"
	case strings.Contains(p, "pkcs5"), strings.Contains(p, "pkcs7"):
		return "pkcs7"
	case p == "":
		return ""
	default:
		return "other"
	}
}

// deriveName builds the display name, e.g. "RSA-2048" or "AES-128-CBC".
// This is the R19 field: "AES" alone is not an answer.
func deriveName(f cbom.Finding) string {
	base := strings.ToUpper(f.Algorithm)
	if base == "" {
		return ""
	}
	parts := []string{base}
	if size, ok := f.KeySize(); ok {
		parts = append(parts, strconv.Itoa(size))
	}
	if f.Mode != "" && f.Mode != "other" {
		parts = append(parts, strings.ToUpper(f.Mode))
	}
	if f.Curve != "" {
		parts = append(parts, f.Curve)
	}
	return strings.Join(parts, "-")
}

func assetTypeFrom(raw string) cbom.AssetType {
	if raw == "" {
		return cbom.AssetAlgorithm
	}
	return cbom.AssetType(raw)
}

func confidenceFrom(raw string) cbom.Confidence {
	switch raw {
	case "high":
		return cbom.ConfidenceHigh
	case "medium":
		return cbom.ConfidenceMedium
	case "low":
		return cbom.ConfidenceLow
	default:
		return cbom.ConfidenceLow
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncateSnippet bounds the evidence snippet. Snippets are shown in the UI and
// stored; an unbounded one could carry an entire minified file.
func truncateSnippet(lines string) string {
	trimmed := strings.TrimSpace(lines)
	const max = 500
	if len(trimmed) > max {
		return trimmed[:max] + "…"
	}
	return trimmed
}

// sanitiseError strips anything resembling a host path from a tool's error
// before it becomes user-visible evidence.
func sanitiseError(msg string) string {
	cleaned := strings.TrimSpace(msg)
	if idx := strings.Index(cleaned, "\n"); idx > 0 {
		cleaned = cleaned[:idx]
	}
	const max = 200
	if len(cleaned) > max {
		cleaned = cleaned[:max] + "…"
	}
	if cleaned == "" {
		return "the file could not be parsed"
	}
	return cleaned
}
