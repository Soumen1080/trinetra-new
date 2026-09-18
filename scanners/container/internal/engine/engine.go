package engine

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

// Target is what a container scan was asked to inspect.
//
// The same engine set runs over an image or a directory, because the difference
// is how bytes are obtained, not what counts as a cryptographic asset.
type Target struct {
	// Path is a resolved local directory, empty for a pure image scan.
	Path string
	// ImageReference is a registry reference, empty for a directory scan.
	ImageReference string
}

// IsImage reports whether this target requires registry egress.
func (t Target) IsImage() bool { return t.ImageReference != "" }

// Descriptor returns what Syft or theia should be pointed at.
func (t Target) Descriptor() string {
	if t.IsImage() {
		return t.ImageReference
	}
	return "dir:" + t.Path
}

// Engine is one detection backend for deployment artefacts.
//
// Same contract as the source scanner's: §7.1 governs every engine here too --
// every upstream tool is a source of evidence, never a source of verdicts.
type Engine interface {
	Name() string
	Tool() cbom.Tool

	// Available reports whether the engine can run here. An engine whose
	// binary is missing is skipped and reported as a coverage gap, never
	// silently ignored: a missing engine means a smaller inventory.
	Available(ctx context.Context) error

	// SupportsImages reports whether this engine can inspect a registry image.
	// Engines that only read a local filesystem are skipped for image targets
	// rather than failing the scan.
	SupportsImages() bool

	// Detects describes what this engine contributes, for coverage reporting.
	Detects() []string

	Scan(ctx context.Context, target Target) (Result, error)
}

// Result is one engine's output.
type Result struct {
	Findings []cbom.Finding
	// Gaps are things this engine could not inspect. Surfaced in the UI, not
	// only the report: an image reported clean because three layers failed to
	// extract is more dangerous than an honest error.
	Gaps         []Gap
	FilesScanned int
}

// Gap is something an engine could not inspect.
type Gap struct {
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Registry holds the engines a scan will run.
type Registry struct {
	engines []Engine
}

// NewRegistry builds a registry from engines.
func NewRegistry(engines ...Engine) *Registry {
	return &Registry{engines: engines}
}

// Engines returns the registered engines.
func (r *Registry) Engines() []Engine { return r.engines }

// RunAll runs every applicable engine and merges the results.
//
// An engine that is unavailable, or that cannot handle this target kind, becomes
// a coverage gap rather than a failure: a partial inventory that says what it
// missed is more useful than a refusal, provided the "says what it missed" half
// is never skipped.
func (r *Registry) RunAll(ctx context.Context, target Target) (Result, []cbom.Tool, error) {
	var (
		merged Result
		tools  []cbom.Tool
		ran    int
	)

	for _, e := range r.engines {
		if target.IsImage() && !e.SupportsImages() {
			merged.Gaps = append(merged.Gaps, Gap{
				Kind: "engine_not_applicable",
				Reason: fmt.Sprintf(
					"%s cannot inspect a registry image, so %v were not detected in this target",
					e.Name(), e.Detects()),
				Count: 1,
			})
			continue
		}

		if err := e.Available(ctx); err != nil {
			merged.Gaps = append(merged.Gaps, Gap{
				Kind: "engine_unavailable",
				Reason: fmt.Sprintf("%s is not available, so %v were not detected: %v",
					e.Name(), e.Detects(), err),
				Count: 1,
			})
			continue
		}

		res, err := e.Scan(ctx, target)
		if err != nil {
			// One engine failing must not discard what the others found.
			merged.Gaps = append(merged.Gaps, Gap{
				Kind:   "engine_failed",
				Reason: fmt.Sprintf("%s failed: %v", e.Name(), err),
				Count:  1,
			})
			continue
		}

		ran++
		tools = append(tools, e.Tool())
		merged.Findings = append(merged.Findings, res.Findings...)
		merged.Gaps = append(merged.Gaps, res.Gaps...)
		merged.FilesScanned += res.FilesScanned
	}

	if ran == 0 {
		return merged, tools, fmt.Errorf("no detection engine was available for this target")
	}
	return merged, tools, nil
}
