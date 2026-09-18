package engine

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// ConfigEngine reads declared TLS configuration (R4, partial).
//
// **Everything this engine finds is `is_observed=false` by construction.** A
// config file states what a service intends to negotiate; only a live handshake
// (Phase 11A) states what it actually does. The two routinely differ — a load
// balancer in front of a correctly configured service can still accept TLS 1.0 —
// so conflating them would report a fix that was never deployed.
type ConfigEngine struct {
	MaxFileBytes int64
	MaxFiles     int
}

// NewConfigEngine returns an engine with sensible bounds.
func NewConfigEngine() *ConfigEngine {
	return &ConfigEngine{MaxFileBytes: 2 << 20, MaxFiles: 50_000}
}

func (e *ConfigEngine) Name() string { return "config" }

func (e *ConfigEngine) SupportsImages() bool { return false }

func (e *ConfigEngine) Detects() []string {
	return []string{"declared TLS versions", "cipher suites", "openssl configuration"}
}

func (e *ConfigEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "config-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

func (e *ConfigEngine) Available(context.Context) error { return nil }

// configFiles are the filenames worth opening.
var configFiles = map[string]bool{
	"openssl.cnf": true, "openssl.conf": true,
	"nginx.conf": true, "ssl.conf": true, "ssl-params.conf": true,
	"httpd.conf": true, "apache2.conf": true,
	"sshd_config": true, "ssh_config": true,
	"java.security":   true,
	"application.yml": true, "application.yaml": true, "application.properties": true,
	"server.xml": true, "web.config": true,
}

var (
	// Matches a declared TLS/SSL protocol version in any of the common config
	// dialects: TLSv1.2, TLS 1.2, ssl_protocols TLSv1.3, MinProtocol=TLSv1.2.
	tlsVersionPattern = regexp.MustCompile(`(?i)\b(?:TLSv?|SSLv?)\s*([0-9]+(?:\.[0-9]+)?)\b`)

	// Matches an OpenSSL/IANA cipher suite name.
	cipherSuitePattern = regexp.MustCompile(
		`\b(TLS_[A-Z0-9_]+|(?:ECDHE|DHE|RSA|ECDH|PSK)-[A-Z0-9-]+)\b`)

	// Matches an SSH key-exchange or host-key algorithm declaration.
	sshAlgorithmPattern = regexp.MustCompile(
		`(?i)^\s*(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs)\s+(.+)$`)
)

// Scan walks the target for configuration files.
func (e *ConfigEngine) Scan(ctx context.Context, target Target) (Result, error) {
	if target.Path == "" {
		return Result{}, fmt.Errorf("config engine requires a filesystem path")
	}

	var result Result
	seen := 0

	err := filepath.WalkDir(target.Path, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || entry.IsDir() {
			return nil
		}

		seen++
		if seen > e.MaxFiles {
			return filepath.SkipAll
		}

		name := strings.ToLower(entry.Name())
		if !configFiles[name] {
			return nil
		}

		info, statErr := entry.Info()
		if statErr != nil || info.Size() > e.MaxFileBytes {
			return nil
		}

		result.FilesScanned++
		findings := e.inspectConfig(target.Path, path)
		result.Findings = append(result.Findings, findings...)
		return nil
	})

	if err != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

func (e *ConfigEngine) inspectConfig(root, path string) []cbom.Finding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	location := relativeOrBase(root, path)
	isSSH := strings.Contains(strings.ToLower(filepath.Base(path)), "ssh")

	var findings []cbom.Finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()

		// A commented directive is documentation, not configuration. Treating
		// it as a finding is the config-file equivalent of matching a bare
		// identifier in source.
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		findings = append(findings, e.matchLine(trimmed, location, line, isSSH)...)
	}

	return findings
}

func (e *ConfigEngine) matchLine(text, location string, line int, isSSH bool) []cbom.Finding {
	var findings []cbom.Finding

	if isSSH {
		if match := sshAlgorithmPattern.FindStringSubmatch(text); match != nil {
			findings = append(findings, protocolFinding(
				"SSH", "", location, line,
				fmt.Sprintf("declared %s: %s", match[1], strings.TrimSpace(match[2])),
			))
			return findings
		}
	}

	for _, match := range tlsVersionPattern.FindAllStringSubmatch(text, -1) {
		version := normaliseTLSVersion(match[0], match[1])
		if version == "" {
			continue
		}
		findings = append(findings, protocolFinding(
			"TLS", version, location, line,
			"declared in configuration: "+truncate(text, 160),
		))
	}

	for _, match := range cipherSuitePattern.FindAllStringSubmatch(text, -1) {
		findings = append(findings, protocolFinding(
			"TLS", "", location, line,
			"declared cipher suite "+match[1],
		))
	}

	return findings
}

// protocolFinding builds a declared-protocol artefact.
//
// The snippet always says "declared", so the distinction from observed crypto
// survives into the UI even before Phase 11A exists to contrast with it.
func protocolFinding(protocol, version, location string, line int, note string) cbom.Finding {
	name := protocol
	if version != "" {
		name = protocol + " " + version
	}

	return cbom.Finding{
		AssetType:       cbom.AssetProtocol,
		Name:            name,
		Algorithm:       strings.ToLower(protocol),
		ParameterSet:    version,
		DetectionMethod: cbom.DetectConfigParse,
		// Medium, not high: a config file can be shadowed by another, and the
		// deployed listener may negotiate something else entirely.
		Confidence: cbom.ConfidenceMedium,
		RuleID:     "config:" + strings.ToLower(protocol),
		Location:   cbom.Location{Path: location, Line: line},
		Snippet:    note,
	}.Normalise()
}

// normaliseTLSVersion turns "TLSv1.2", "SSLv3" and "TLS 1.3" into "1.2" etc.
// Returns empty for anything that is not a real protocol version, so a random
// number in a config line does not become a protocol finding.
func normaliseTLSVersion(full, captured string) string {
	switch captured {
	case "1", "1.0", "1.1", "1.2", "1.3", "2", "3":
		// SSLv2 and SSLv3 keep their major number; TLS 1.x keeps the minor.
		if strings.HasPrefix(strings.ToUpper(full), "SSL") {
			return "SSLv" + captured
		}
		if captured == "1" {
			return "1.0"
		}
		if captured == "2" || captured == "3" {
			return ""
		}
		return captured
	default:
		return ""
	}
}

func truncate(text string, max int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "…"
}
