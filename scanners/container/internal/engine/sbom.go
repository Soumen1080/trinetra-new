package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// SBOMEngine ingests SBOMs produced by other tools (11C.2).
//
// An organisation that already produces SBOMs should not have to rescan, and
// for an estate Trinetra cannot reach directly this is the only coverage
// available at all.
//
// **An ingested SBOM is someone else's evidence.** Trinetra did not observe
// these components; another tool asserted them. Three consequences, all
// enforced below rather than left to convention:
//
//   - Confidence is MEDIUM at best. A finding's confidence must reflect who
//     actually looked, and it was not us.
//   - The producing tool is recorded, so a reader can judge the source.
//   - The detection method is sbom_ingest, never a method implying Trinetra
//     parsed the artefact itself.
type SBOMEngine struct {
	Knowledge *KnowledgeBase
	// MaxFileBytes bounds what is read. An SBOM for a large monorepo is big but
	// not unbounded, and a runaway file must not stall a scan.
	MaxFileBytes int64
}

// NewSBOMEngine returns an engine filtering ingested components through kb.
func NewSBOMEngine(kb *KnowledgeBase) *SBOMEngine {
	return &SBOMEngine{Knowledge: kb, MaxFileBytes: 64 << 20}
}

func (e *SBOMEngine) Name() string { return "sbom-ingest" }

// SupportsImages is false: an SBOM is a file on disk. Ingesting one for an
// image target would mean reading an SBOM the image happens to contain, which
// is a different and much less useful thing.
func (e *SBOMEngine) SupportsImages() bool { return false }

func (e *SBOMEngine) Detects() []string {
	return []string{"components asserted by third-party CycloneDX and SPDX SBOMs"}
}

func (e *SBOMEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "sbom-ingest",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

func (e *SBOMEngine) Available(context.Context) error {
	if e.Knowledge == nil {
		return fmt.Errorf("crypto-library knowledge base is not loaded")
	}
	return nil
}

// sbomFilenames are the conventional names. Scanning every .json in a tree for
// an SBOM shape would read whole repositories to find nothing.
var sbomFilenames = map[string]bool{
	"sbom.json": true, "sbom.cdx.json": true, "sbom.spdx.json": true,
	"bom.json": true, "bom.cdx.json": true,
	"cyclonedx.json": true, "cyclonedx-sbom.json": true,
	"spdx.json": true, "manifest.spdx.json": true,
}

func isSBOMFilename(name string) bool {
	lower := strings.ToLower(name)
	if sbomFilenames[lower] {
		return true
	}
	// Also accept the conventional suffixes, which build tools emit with a
	// project prefix: myapp.cdx.json, myapp.spdx.json.
	return strings.HasSuffix(lower, ".cdx.json") || strings.HasSuffix(lower, ".spdx.json")
}

// Scan walks the target for SBOM files and ingests each one.
func (e *SBOMEngine) Scan(ctx context.Context, target Target) (Result, error) {
	if target.Path == "" {
		return Result{}, fmt.Errorf("sbom engine requires a filesystem path")
	}

	var result Result

	err := filepath.WalkDir(target.Path, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || entry.IsDir() {
			return nil
		}
		if !isSBOMFilename(entry.Name()) {
			return nil
		}

		info, statErr := entry.Info()
		if statErr != nil {
			return nil
		}
		if info.Size() > e.MaxFileBytes {
			result.Gaps = append(result.Gaps, Gap{
				Path:   relativeOrBase(target.Path, path),
				Kind:   "too_large",
				Reason: fmt.Sprintf("SBOM exceeds the %d byte ingest limit", e.MaxFileBytes),
				Count:  1,
			})
			return nil
		}

		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		location := relativeOrBase(target.Path, path)
		findings, gaps := e.ingest(raw, location)
		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		result.Gaps = append(result.Gaps, gaps...)
		return nil
	})

	if err != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

// ingest detects the format and dispatches. An unrecognised document is a
// visible gap, not a silent skip: a file named sbom.json that Trinetra could
// not read is a hole the user should know about.
func (e *SBOMEngine) ingest(raw []byte, location string) ([]cbom.Finding, []Gap) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, []Gap{{
			Path:   location,
			Kind:   "unparseable",
			Reason: "the file is named like an SBOM but is not valid json",
			Count:  1,
		}}
	}

	switch {
	case probe.BOMFormat == "CycloneDX":
		return e.ingestCycloneDX(raw, location)
	case probe.SPDXVersion != "" || probe.SPDXID != "":
		return e.ingestSPDX(raw, location)
	default:
		return nil, []Gap{{
			Path:   location,
			Kind:   "unparseable",
			Reason: "the file is named like an SBOM but is neither CycloneDX nor SPDX",
			Count:  1,
		}}
	}
}

// externalCycloneDX is the subset Trinetra reads from a third-party document.
//
// Deliberately partial and version-tolerant: 1.4 through 1.6 share the fields
// used here, so one shape covers all three rather than three parsers drifting.
type externalCycloneDX struct {
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Tools json.RawMessage `json:"tools"`
	} `json:"metadata"`
	Components []externalCycloneDXComponent `json:"components"`
}

type externalCycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Group   string `json:"group"`
}

func (e *SBOMEngine) ingestCycloneDX(raw []byte, location string) ([]cbom.Finding, []Gap) {
	var doc externalCycloneDX
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, []Gap{{
			Path:   location,
			Kind:   "unparseable",
			Reason: "CycloneDX document could not be parsed",
			Count:  1,
		}}
	}

	if !supportedCycloneDXVersion(doc.SpecVersion) {
		return nil, []Gap{{
			Path: location,
			Kind: "unsupported_format",
			Reason: fmt.Sprintf(
				"CycloneDX %s is outside the supported 1.4-1.6 range; its components were not ingested",
				doc.SpecVersion),
			Count: 1,
		}}
	}

	producer := cycloneDXProducer(doc.Metadata.Tools)

	var findings []cbom.Finding
	for _, component := range doc.Components {
		finding, ok := e.componentToFinding(
			component.Name, component.Version, component.PURL, location, producer)
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// externalSPDX is the subset Trinetra reads from an SPDX 2.3 document.
type externalSPDX struct {
	SPDXVersion  string `json:"spdxVersion"`
	CreationInfo struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func (e *SBOMEngine) ingestSPDX(raw []byte, location string) ([]cbom.Finding, []Gap) {
	var doc externalSPDX
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, []Gap{{
			Path:   location,
			Kind:   "unparseable",
			Reason: "SPDX document could not be parsed",
			Count:  1,
		}}
	}

	if !supportedSPDXVersion(doc.SPDXVersion) {
		return nil, []Gap{{
			Path: location,
			Kind: "unsupported_format",
			Reason: fmt.Sprintf(
				"%s is outside the supported SPDX-2.x range; its packages were not ingested",
				doc.SPDXVersion),
			Count: 1,
		}}
	}

	producer := spdxProducer(doc.CreationInfo.Creators)

	var findings []cbom.Finding
	for _, pkg := range doc.Packages {
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purl = ref.ReferenceLocator
				break
			}
		}
		finding, ok := e.componentToFinding(
			pkg.Name, pkg.VersionInfo, purl, location, producer)
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// componentToFinding filters one component through the knowledge base.
//
// Components absent from it are skipped silently and are NOT gaps: an SBOM
// lists every dependency, and a JPEG decoder is not a hole in a cryptographic
// inventory. Reporting it as one would bury the real gaps.
func (e *SBOMEngine) componentToFinding(
	name, version, purl, location, producer string,
) (cbom.Finding, bool) {
	profile, known := e.Knowledge.Lookup(name)
	if !known {
		return cbom.Finding{}, false
	}

	finding := cbom.Finding{
		AssetType: cbom.AssetLibrary,
		Name:      libraryName(name, profile.DisplayName),
		// Algorithm stays empty, as for every library finding: a package name
		// is dependency evidence, not an algorithm.
		DetectionMethod: cbom.DetectSBOMIngest,
		// MEDIUM, never high. Trinetra did not observe this component; another
		// tool asserted it, and a finding's confidence must reflect who
		// actually looked.
		Confidence: cbom.ConfidenceMedium,
		RuleID:     "sbom:" + producer,
		Location:   cbom.Location{Path: location, Symbol: purl},
		Snippet:    describeIngestedComponent(name, version, purl, producer, profile),
	}

	return finding.Normalise(), true
}

// describeIngestedComponent builds the evidence note.
//
// It leads with the fact that this is second-hand, because that is what a
// reader most needs to know before acting on it.
func describeIngestedComponent(
	name, version, purl, producer string, profile *LibraryProfile,
) string {
	parts := []string{
		fmt.Sprintf("asserted by an external SBOM (%s), not observed by Trinetra", producer),
		"package " + name,
	}

	if version != "" {
		parts = append(parts, "version "+version)
	}
	if purl != "" {
		parts = append(parts, purl)
	}

	if supported, recorded := profile.SupportsPQC(version); recorded {
		if supported {
			parts = append(parts, fmt.Sprintf("PQC-capable since %s", profile.PQCSince))
		} else {
			parts = append(parts, fmt.Sprintf("predates PQC support (%s)", profile.PQCSince))
		}
	} else {
		parts = append(parts, "PQC support not recorded for this version")
	}

	if profile.IsDeprecated(name) && profile.DeprecationNote != "" {
		parts = append(parts, profile.DeprecationNote)
	}

	return strings.Join(parts, "; ")
}

// supportedCycloneDXVersion accepts 1.4 through 1.6.
//
// Older documents are rejected rather than parsed optimistically: 1.3 and
// earlier lack fields this adapter assumes, and a silently partial ingest is
// worse than a stated refusal.
func supportedCycloneDXVersion(version string) bool {
	switch strings.TrimSpace(version) {
	case "1.4", "1.5", "1.6":
		return true
	default:
		return false
	}
}

// supportedSPDXVersion accepts the SPDX 2.x line.
func supportedSPDXVersion(version string) bool {
	trimmed := strings.TrimSpace(version)
	return strings.HasPrefix(trimmed, "SPDX-2.")
}

// cycloneDXProducer names the tool that wrote the document.
//
// CycloneDX changed the shape of metadata.tools between 1.4 (an array) and 1.5
// (an object with components), so both are handled. An unnamed producer is
// reported as "unknown" rather than omitted: a reader must be able to see that
// the source is unidentified.
func cycloneDXProducer(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "unknown"
	}

	// 1.5+ object form.
	var object struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &object); err == nil && len(object.Components) > 0 {
		return formatProducer(object.Components[0].Name, object.Components[0].Version)
	}

	// 1.4 array form.
	var array []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &array); err == nil && len(array) > 0 {
		return formatProducer(array[0].Name, array[0].Version)
	}

	return "unknown"
}

// spdxProducer reads the SPDX creators list, preferring a Tool entry.
func spdxProducer(creators []string) string {
	for _, creator := range creators {
		if rest, found := strings.CutPrefix(creator, "Tool:"); found {
			if trimmed := strings.TrimSpace(rest); trimmed != "" {
				return trimmed
			}
		}
	}
	return "unknown"
}

func formatProducer(name, version string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unknown"
	}
	if version = strings.TrimSpace(version); version != "" {
		return name + "@" + version
	}
	return name
}
