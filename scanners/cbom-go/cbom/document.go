package cbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SpecVersion is the CycloneDX version this builder emits.
const SpecVersion = "1.6"

// Document is a CycloneDX 1.6 CBOM.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string           `json:"timestamp"`
	Tools     []Tool           `json:"tools"`
	Component *TargetComponent `json:"component,omitempty"`
}

// Tool records what produced the document. A CBOM that cannot say which version
// of which tool produced it is not an audit artefact, so Licence is required
// here rather than optional.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Licence string `json:"licence,omitempty"`
}

type TargetComponent struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Component struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref"`
	Name             string            `json:"name"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	OID                 string               `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Curve                  string   `json:"curve,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	Padding                string   `json:"padding,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
}

// isEmpty reports whether nothing at all was observed about the algorithm.
// Written out rather than compared against a zero value because the struct
// contains a slice and is therefore not comparable.
func (a *AlgorithmProperties) isEmpty() bool {
	return a.Primitive == "" &&
		a.ParameterSetIdentifier == "" &&
		a.Curve == "" &&
		a.Mode == "" &&
		a.Padding == "" &&
		len(a.CryptoFunctions) == 0
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

type Occurrence struct {
	Location          string `json:"location"`
	Line              int    `json:"line,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BuildOptions carries the per-scan values that would otherwise make output
// non-deterministic.
type BuildOptions struct {
	ScanID     string
	TargetName string
	// Timestamp is supplied by the caller rather than read from the clock, so
	// the same input produces the same document. Determinism is what makes
	// golden-CBOM diffs meaningful.
	Timestamp string
	Tools     []Tool
}

// Build turns findings into a CycloneDX document.
//
// The result is deterministic: findings are sorted by a stable key and bom-refs
// are content-derived, so identical input yields a byte-identical document.
// A document with zero components is a valid result — a repository genuinely
// free of cryptography — not an error.
func Build(findings []Finding, opts BuildOptions) Document {
	normalised := make([]Finding, 0, len(findings))
	for _, f := range findings {
		normalised = append(normalised, f.Normalise())
	}
	deduped := dedupe(normalised)
	sortFindings(deduped)

	components := make([]Component, 0, len(deduped))
	for _, f := range deduped {
		components = append(components, toComponent(f))
	}

	return Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serialNumberFor(opts.ScanID),
		Version:      1,
		Metadata: Metadata{
			Timestamp: opts.Timestamp,
			Tools:     opts.Tools,
			Component: &TargetComponent{Type: "application", Name: opts.TargetName},
		},
		Components: components,
	}
}

// serialNumberFor derives a stable URN from the scan id, so re-running a scan
// with the same id produces the same document rather than a fresh random UUID.
func serialNumberFor(scanID string) string {
	sum := sha256.Sum256([]byte("trinetra-cbom:" + scanID))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// findingKey is the identity used for both dedup and sort ordering.
//
// Deliberately excludes key size, mode and rule id. Those are the fields
// engines disagree about: one engine resolves a key size and another does not,
// and keying on them would make the two records distinct and defeat the merge
// that exists precisely to combine them. Identity is *which asset, where*.
func findingKey(f Finding) string {
	// Libraries are identified by NAME rather than algorithm, because a library
	// finding never carries one. Every package in an OS package database shares
	// one location (lib/apk/db/installed, var/lib/dpkg/status), so keying a
	// library on path alone collapses an entire image's inventory into a single
	// arbitrary entry -- observed on a real alpine image, where three crypto
	// packages became one finding under the wrong name.
	discriminator := strings.ToLower(f.Algorithm)
	if f.IsLibrary() {
		discriminator = strings.ToLower(f.Name)
	}

	return f.Location.Path + "\x00" +
		strconv.Itoa(f.Location.Line) + "\x00" +
		string(f.AssetType) + "\x00" +
		discriminator
}

// dedupe merges findings that describe the same asset at the same place.
//
// Two engines finding one asset is corroboration, not duplication. The merge
// prefers the record that actually observed a key size: a finding with the size
// strictly dominates one without, because absent means unobserved (P3).
func dedupe(findings []Finding) []Finding {
	index := make(map[string]int, len(findings))
	out := make([]Finding, 0, len(findings))

	for _, f := range findings {
		key := findingKey(f)
		if at, seen := index[key]; seen {
			out[at] = mergeFindings(out[at], f)
			continue
		}
		index[key] = len(out)
		out = append(out, f)
	}
	return out
}

func mergeFindings(a, b Finding) Finding {
	if _, ok := a.KeySize(); !ok {
		if _, bHas := b.KeySize(); bHas {
			a.KeySizeBits = b.KeySizeBits
		}
	}
	if a.Mode == "" {
		a.Mode = b.Mode
	}
	if a.Padding == "" {
		a.Padding = b.Padding
	}
	if a.Curve == "" {
		a.Curve = b.Curve
	}
	if a.DataCategory == "" {
		a.DataCategory = b.DataCategory
	}
	if a.Algorithm == "" {
		a.Algorithm = b.Algorithm
	}
	if a.ParameterSet == "" {
		a.ParameterSet = b.ParameterSet
	}
	if a.Snippet == "" {
		a.Snippet = b.Snippet
	}
	// Prefer the more specific name. Identity no longer includes the name, so a
	// merge must not let "RSA" win over "RSA-2048" — the R19 detail is the whole
	// point of the finding.
	if len(b.Name) > len(a.Name) {
		a.Name = b.Name
	}
	// Keep the stronger confidence: the best single piece of evidence is the
	// fairest summary of what is known about an asset.
	if confidenceRank(b.Confidence) < confidenceRank(a.Confidence) {
		a.Confidence = b.Confidence
	}
	// Prefer a resolved detection over a pattern match, so the merged record
	// reports how the surviving evidence was actually obtained.
	if a.DetectionMethod == DetectSemgrepPattern && b.DetectionMethod == DetectCBOMkit {
		a.DetectionMethod = b.DetectionMethod
		a.RuleID = b.RuleID
	}
	return a.Normalise()
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 0
	case ConfidenceMedium:
		return 1
	default:
		return 2
	}
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return findingKey(findings[i]) < findingKey(findings[j])
	})
}

func toComponent(f Finding) Component {
	crypto := &CryptoProperties{
		AssetType: AssetTypeToWire(f.AssetType),
		OID:       f.OID,
	}

	// Library findings carry no algorithmProperties at all: there is no
	// algorithm to describe, and an empty block would invite one to be added.
	if !f.IsLibrary() {
		algo := &AlgorithmProperties{
			Curve:                  f.Curve,
			Mode:                   f.Mode,
			Padding:                f.Padding,
			ParameterSetIdentifier: f.ParameterSet,
		}
		if f.Primitive != "" {
			algo.Primitive = PrimitiveToWire(f.Primitive)
		}
		if size, ok := f.KeySize(); ok && algo.ParameterSetIdentifier == "" {
			algo.ParameterSetIdentifier = strconv.Itoa(size)
		}
		for _, p := range f.Purposes {
			algo.CryptoFunctions = append(algo.CryptoFunctions, PurposeToWire(p))
		}
		// Omit the block entirely when nothing was observed, rather than
		// emitting an empty object that implies a lookup which never happened.
		if !algo.isEmpty() {
			crypto.AlgorithmProperties = algo
		}
	}

	component := Component{
		Type:             "cryptographic-asset",
		BOMRef:           bomRef(f),
		Name:             f.Name,
		CryptoProperties: crypto,
		Evidence: &Evidence{
			Occurrences: []Occurrence{{
				Location:          f.Location.Path,
				Line:              f.Location.Line,
				AdditionalContext: f.Snippet,
			}},
		},
		Properties: buildProperties(f),
	}
	return component
}

// buildProperties emits Trinetra's namespaced extensions.
//
// Namespacing matters: a consumer that does not know Trinetra ignores these
// safely and the document stays schema-valid.
func buildProperties(f Finding) []Property {
	var props []Property

	if size, ok := f.KeySize(); ok {
		props = append(props, Property{TrinetraKeySizeProperty, strconv.Itoa(size)})
	}
	if f.DataCategory != "" {
		props = append(props, Property{TrinetraDataCategoryProperty, f.DataCategory})
	}
	if AssetTypeNeedsHint(f.AssetType) {
		props = append(props, Property{TrinetraAssetTypeProperty, string(f.AssetType)})
	}
	props = append(props,
		Property{"trinetra:detection-method", string(f.DetectionMethod)},
		Property{"trinetra:confidence", string(f.Confidence)},
	)
	if f.RuleID != "" {
		props = append(props, Property{"trinetra:rule-id", f.RuleID})
	}
	if f.Algorithm != "" {
		props = append(props, Property{"trinetra:algorithm", f.Algorithm})
	}

	// Engine-specific attributes. Anything not already namespaced is dropped
	// rather than emitted: a bare property name would not be safely ignorable
	// by a consumer that does not know Trinetra, and Validate rejects it.
	for name, value := range f.Extra {
		if value == "" || !strings.HasPrefix(name, "trinetra:") {
			continue
		}
		props = append(props, Property{name, value})
	}

	sort.SliceStable(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return props
}

// bomRef is content-derived so it is stable across runs. A counter or a random
// id would change on every scan and make document diffs useless.
func bomRef(f Finding) string {
	sum := sha256.Sum256([]byte(findingKey(f)))
	return "trinetra:" + hex.EncodeToString(sum[:])[:32]
}

// Marshal renders the document deterministically.
func Marshal(doc Document) ([]byte, error) {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cbom: %w", err)
	}
	return append(out, '\n'), nil
}
