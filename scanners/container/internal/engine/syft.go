package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// SyftEngine produces the library inventory (R16, R5).
//
// It takes Syft's **native JSON**, never its CycloneDX output: Syft's CycloneDX
// describes software components, Trinetra's describes cryptographic assets, and
// mixing the two would give the document two writers with two shapes. One
// writer, one shape, one schema.
//
// What Trinetra takes from Syft is the package inventory. What it deliberately
// does not take is any vulnerability claim -- that is OSV's job (Phase 11B), and
// neither is a crypto verdict.
type SyftEngine struct {
	Binary    string
	Version   string
	Knowledge *KnowledgeBase
}

// NewSyftEngine returns an engine filtering Syft's output through kb.
func NewSyftEngine(kb *KnowledgeBase) *SyftEngine {
	return &SyftEngine{Binary: "syft", Knowledge: kb}
}

func (e *SyftEngine) Name() string { return "syft" }

func (e *SyftEngine) SupportsImages() bool { return true }

func (e *SyftEngine) Detects() []string {
	return []string{"crypto libraries", "os packages", "language dependencies"}
}

func (e *SyftEngine) Tool() cbom.Tool {
	version := e.Version
	if version == "" {
		version = "unknown"
	}
	return cbom.Tool{
		Vendor:  "Anchore",
		Name:    "syft",
		Version: version,
		Licence: "Apache-2.0",
	}
}

// Available checks the binary and records its version for metadata.tools.
func (e *SyftEngine) Available(ctx context.Context) error {
	if e.Knowledge == nil {
		return fmt.Errorf("crypto-library knowledge base is not loaded")
	}

	path, err := exec.LookPath(e.Binary)
	if err != nil {
		return fmt.Errorf("syft binary not found on PATH")
	}
	e.Binary = path

	out, err := exec.CommandContext(ctx, e.Binary, "version", "-o", "json").Output()
	if err != nil {
		// Version reporting is best-effort; a scan is still possible without it.
		e.Version = "unknown"
		return nil
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &payload); err == nil && payload.Version != "" {
		e.Version = payload.Version
	} else {
		e.Version = "unknown"
	}
	return nil
}

// syftDocument is the subset of Syft's native JSON that Trinetra reads.
//
// Deliberately partial. Syft's schema is large and evolving; taking only the
// fields needed means an upstream addition cannot break the adapter, and it
// makes explicit that vulnerability and relationship data are not consumed.
type syftDocument struct {
	Artifacts []syftArtifact `json:"artifacts"`
	Source    struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"source"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type syftArtifact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	FoundBy   string    `json:"foundBy"`
	PURL      string    `json:"purl"`
	Licenses  []any     `json:"licenses"`
	Locations []syftLoc `json:"locations"`
}

type syftLoc struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID"`
}

// Scan runs Syft and adapts its output.
func (e *SyftEngine) Scan(ctx context.Context, target Target) (Result, error) {
	args := []string{
		"scan",
		target.Descriptor(),
		"-o", "syft-json",
		"--quiet",
	}

	cmd := exec.CommandContext(ctx, e.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// The adapter is the trust boundary: report a scanner error rather than
		// leaking the tool's stderr, which can contain registry credentials in
		// an auth failure message.
		return Result{}, fmt.Errorf("syft invocation failed")
	}

	doc, err := parseSyftOutput(stdout.Bytes())
	if err != nil {
		return Result{}, fmt.Errorf("syft output could not be parsed: %w", err)
	}

	return e.adapt(doc), nil
}

// parseSyftOutput validates the tool's output rather than trusting it.
func parseSyftOutput(raw []byte) (syftDocument, error) {
	var doc syftDocument
	if len(bytes.TrimSpace(raw)) == 0 {
		return doc, fmt.Errorf("empty output")
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("invalid json: %w", err)
	}
	return doc, nil
}

// adapt turns Syft artifacts into library findings.
//
// Exported behaviour worth stating: packages absent from the knowledge base are
// skipped silently and are NOT counted as gaps. A JPEG decoder in an image is
// not a coverage hole in a cryptographic inventory, and reporting it as one
// would bury the real gaps.
func (e *SyftEngine) adapt(doc syftDocument) Result {
	var result Result
	result.FilesScanned = len(doc.Artifacts)

	for _, artifact := range doc.Artifacts {
		profile, known := e.Knowledge.Lookup(artifact.Name)
		if !known {
			continue
		}

		location := "unknown"
		layer := ""
		if len(artifact.Locations) > 0 {
			// Syft reports host-native separators when scanning a directory, so
			// a Windows developer machine yields "\opt\app\go.mod". Evidence
			// paths must be forward-slashed everywhere: the same finding has to
			// read identically whether it was produced in a Linux container or
			// on a developer's laptop.
			location = filepath.ToSlash(artifact.Locations[0].Path)
			location = strings.TrimPrefix(location, "/")
			layer = artifact.Locations[0].LayerID
		}

		finding := cbom.Finding{
			AssetType: cbom.AssetLibrary,
			Name:      profile.DisplayName,
			// Algorithm stays empty. Normalise() enforces it too, but stating
			// it here documents the reason: a package name is not an algorithm.
			DetectionMethod: cbom.DetectDependency,
			Confidence:      cbom.ConfidenceHigh,
			RuleID:          "syft:" + artifact.Type,
			Location: cbom.Location{
				Path:   location,
				Symbol: layer,
			},
			Snippet: describeLibrary(artifact, profile),
		}

		result.Findings = append(result.Findings, finding.Normalise())
	}

	return result
}

// describeLibrary builds the evidence note shown beside the finding.
//
// Carries the facts a reader needs to judge it -- package, version, purl, PQC
// status -- and says "not recorded" rather than "unsupported" where the
// knowledge base has no entry (P3).
func describeLibrary(artifact syftArtifact, profile *LibraryProfile) string {
	parts := []string{fmt.Sprintf("package %s", artifact.Name)}

	if artifact.Version != "" {
		parts = append(parts, "version "+artifact.Version)
	}
	if artifact.PURL != "" {
		parts = append(parts, artifact.PURL)
	}

	if supported, known := profile.SupportsPQC(artifact.Version); known {
		if supported {
			parts = append(parts, fmt.Sprintf("PQC-capable since %s", profile.PQCSince))
		} else {
			parts = append(parts, fmt.Sprintf("predates PQC support (%s)", profile.PQCSince))
		}
	} else {
		parts = append(parts, "PQC support not recorded for this version")
	}

	if profile.IsDeprecated(artifact.Name) && profile.DeprecationNote != "" {
		parts = append(parts, profile.DeprecationNote)
	}

	return strings.Join(parts, "; ")
}
