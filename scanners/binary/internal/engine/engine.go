// Package engine defines the detection-engine boundary for the binary scanner.
//
// Binary analysis is slow and has a different resource profile than source
// scanning, so it runs on its own queue (§7.4). Each engine remains an evidence
// source, never a verdict source (§7.1).
package engine

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

const ScannerVersion = "2026.1.0"

// Engine is one detection backend for binary analysis.
type Engine interface {
	// Name identifies the engine in logs and coverage reporting.
	Name() string

	// Tool describes the engine for metadata.tools.
	Tool() cbom.Tool

	// Available reports whether the engine can run here.
	Available(ctx context.Context) error

	// Languages lists what this engine covers (if applicable).
	Languages() []string

	// Scan runs the engine over root and returns findings plus any gaps.
	Scan(ctx context.Context, root string) (Result, error)
}

// Result is one engine's output.
type Result struct {
	Findings     []cbom.Finding
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

// Add registers another engine.
func (r *Registry) Add(e Engine) { r.engines = append(r.engines, e) }

// Engines returns the registered engines.
func (r *Registry) Engines() []Engine { return r.engines }

// RunAll runs every available engine and merges the results.
func (r *Registry) RunAll(ctx context.Context, root string) (Result, []cbom.Tool, error) {
	var (
		merged Result
		tools  []cbom.Tool
		ran    int
	)

	for _, e := range r.engines {
		if err := e.Available(ctx); err != nil {
			merged.Gaps = append(merged.Gaps, Gap{
				Kind: "engine_unavailable",
				Reason: fmt.Sprintf(
					"%s is not available, so %v were not scanned: %v",
					e.Name(), e.Languages(), err),
				Count: 1,
			})
			continue
		}

		res, err := e.Scan(ctx, root)
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
		return merged, tools, fmt.Errorf("no detection engine was available")
	}
	return merged, tools, nil
}
