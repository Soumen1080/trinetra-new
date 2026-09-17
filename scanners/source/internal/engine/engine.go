// Package engine defines the detection-engine boundary for the source scanner.
//
// Trinetra does not write its own detector. It runs maintained upstream engines
// behind a thin adapter, and §7.1 governs every one of them:
//
//	Every upstream tool is a source of evidence, never a source of verdicts.
//
// Three practical consequences, all enforced here rather than left to habit:
//
//  1. Wrap, never fork. Each engine is a subprocess behind an adapter. When the
//     tool changes, the adapter changes and nothing else does.
//  2. The adapter is the trust boundary. Engine output is parsed and validated,
//     never trusted. Malformed output is a scanner error, not a crash.
//  3. A tool's vocabulary never leaks inward. Semgrep says "results", CBOMkit
//     says "components"; both become cbom.Finding in canonical snake_case (P6).
package engine

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

// Engine is one detection backend.
//
// Engines are composed rather than chosen: the scanner runs every available
// engine and merges their findings, because a CBOMkit hit and a Semgrep taint
// path about the same call site are complementary evidence, not duplicates.
type Engine interface {
	// Name identifies the engine in logs and coverage reporting.
	Name() string

	// Tool describes the engine for metadata.tools. A CBOM that cannot say
	// which version of which tool produced it is not an audit artefact.
	Tool() cbom.Tool

	// Available reports whether the engine can run here. An engine whose
	// binary is missing is skipped and reported as a coverage gap — never
	// silently ignored, because a missing engine means a smaller inventory and
	// the user must be able to see that.
	Available(ctx context.Context) error

	// Languages lists what this engine actually covers. Used to compute honest
	// coverage, not to advertise.
	Languages() []string

	// Scan runs the engine over root and returns findings plus any gaps.
	Scan(ctx context.Context, root string) (Result, error)
}

// Result is one engine's output.
type Result struct {
	Findings []cbom.Finding
	// Gaps are files or areas this engine could not inspect. They are surfaced
	// in the UI, not just the report: a repository reported clean because three
	// files failed to parse is more dangerous than an honest error.
	Gaps []Gap
	// FilesScanned is best-effort, used for coverage statistics.
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
//
// An unavailable engine does not fail the scan; it becomes a coverage gap. A
// scan that produces a partial inventory and says so is more useful than one
// that refuses to run — but the "and says so" half is not optional.
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
