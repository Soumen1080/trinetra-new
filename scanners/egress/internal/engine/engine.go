// Package engine defines the detection-engine boundary for the egress scanner.
//
// This scanner differs from the others: it connects to live endpoints rather
// than reading files. Every finding it produces has `is_observed=true`,
// distinguishing observed protocol negotiation from declared configuration.
package engine

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

const ScannerVersion = "2026.1.0"

// Engine is one detection backend for live endpoint scanning.
type Engine interface {
	// Name identifies the engine in logs and coverage reporting.
	Name() string

	// Tool describes the engine for metadata.tools.
	Tool() cbom.Tool

	// Available reports whether the engine can run here.
	Available(ctx context.Context) error

	// Scan connects to the specified endpoint and returns findings plus any gaps.
	// The endpoint format is engine-specific (host:port for TLS, etc.)
	Scan(ctx context.Context, endpoint string) (Result, error)
}

// Result is one engine's output.
type Result struct {
	Findings []cbom.Finding
	Gaps     []Gap
}

// Gap is something an engine could not inspect.
type Gap struct {
	Endpoint string `json:"endpoint,omitempty"`
	Kind     string `json:"kind"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
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

// RunAll runs every available engine against the endpoint and merges results.
func (r *Registry) RunAll(ctx context.Context, endpoint string) (Result, []cbom.Tool, error) {
	var (
		merged Result
		tools  []cbom.Tool
		ran    int
	)

	for _, e := range r.engines {
		if err := e.Available(ctx); err != nil {
			merged.Gaps = append(merged.Gaps, Gap{
				Kind: "engine_unavailable",
				Reason: fmt.Sprintf("%s is not available: %v", e.Name(), err),
				Count:  1,
			})
			continue
		}

		res, err := e.Scan(ctx, endpoint)
		if err != nil {
			// One engine failing must not discard what the others found.
			merged.Gaps = append(merged.Gaps, Gap{
				Kind:     "engine_failed",
				Endpoint: endpoint,
				Reason:   fmt.Sprintf("%s failed: %v", e.Name(), err),
				Count:    1,
			})
			continue
		}

		ran++
		tools = append(tools, e.Tool())
		merged.Findings = append(merged.Findings, res.Findings...)
		merged.Gaps = append(merged.Gaps, res.Gaps...)
	}

	if ran == 0 {
		return merged, tools, fmt.Errorf("no detection engine was available")
	}
	return merged, tools, nil
}
