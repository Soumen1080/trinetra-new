// Package engine holds the cloud/HSM scanner's detection engines.
//
// This scanner answers "what key-bearing infrastructure exists, and what is it
// made of" — the question neither source nor container scanning can reach,
// because a KMS key and an HSM slot leave no trace in a repository or an image.
//
// One rule governs everything here and is stronger than anywhere else in
// Trinetra: **metadata only, never key material.** A cloud KMS or an HSM exists
// precisely so that key material never leaves it, and a scanner that extracted
// a key would defeat the control it is inventorying. Every adapter reads
// descriptive attributes and stops.
package engine

import (
	"context"
	"fmt"

	"github.com/trinetra/cbom-go/cbom"
)

// Target is what a cloud/HSM scan was asked to inspect.
//
// Unlike the source and container scanners, there is no filesystem path here:
// the target is an account, a region or a token, and the "location" recorded in
// evidence is a resource identifier rather than a file.
type Target struct {
	// Provider selects the cloud adapter: "aws", "azure", "gcp".
	Provider string
	// Region scopes the query. Empty means the adapter's default.
	Region string
	// Endpoint overrides the service URL. Used for a private-cloud deployment
	// and for testing against a local emulator; empty means the real service.
	Endpoint string
	// ModulePath is a PKCS#11 provider library for HSM enumeration.
	ModulePath string
}

// Engine is one detection backend for key-bearing infrastructure.
type Engine interface {
	Name() string
	Tool() cbom.Tool

	// Available reports whether the engine can run here. A missing credential
	// or an absent PKCS#11 module is a coverage gap, never a silent skip: an
	// unscanned KMS account is a hole in the inventory the user must see.
	Available(ctx context.Context, target Target) error

	// Detects describes what this engine contributes, for coverage reporting.
	Detects() []string

	Scan(ctx context.Context, target Target) (Result, error)
}

// Result is one engine's output.
type Result struct {
	Findings []cbom.Finding
	Gaps     []Gap
	// ObjectsInspected counts keys, slots or resources examined, for coverage.
	ObjectsInspected int
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

// RunAll runs every available engine and merges the results.
//
// An unavailable engine becomes a coverage gap rather than a failure. That
// matters more here than elsewhere: a missing AWS credential is the single most
// likely reason a cloud inventory comes back thin, and reporting it as "no keys
// found" would tell the user they have nothing to migrate.
func (r *Registry) RunAll(ctx context.Context, target Target) (Result, []cbom.Tool, error) {
	var (
		merged Result
		tools  []cbom.Tool
		ran    int
	)

	for _, e := range r.engines {
		if err := e.Available(ctx, target); err != nil {
			merged.Gaps = append(merged.Gaps, Gap{
				Kind: "engine_unavailable",
				Reason: fmt.Sprintf("%s is not available, so %v were not inventoried: %v",
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
		merged.ObjectsInspected += res.ObjectsInspected
	}

	if ran == 0 {
		return merged, tools, fmt.Errorf("no detection engine was available for this target")
	}
	return merged, tools, nil
}
