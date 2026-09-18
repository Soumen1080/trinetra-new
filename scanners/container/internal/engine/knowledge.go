// Package engine holds the container scanner's detection engines.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// KnowledgeBase decides which packages are cryptographic implementations.
//
// Syft produces a package list for everything in an image. Trinetra filters it
// against this curated set, because emitting every package as a crypto artefact
// would bury the real inventory in noise.
//
// Nothing here names an algorithm, by design: a library finding is dependency
// evidence, and "OpenSSL is installed" proves an implementation exists, not that
// any particular algorithm is used.
type KnowledgeBase struct {
	Version     string           `json:"version"`
	Description string           `json:"description"`
	Libraries   []LibraryProfile `json:"libraries"`

	// index maps a lowercased package name to its profile, built once on load.
	index map[string]*LibraryProfile
}

// LibraryProfile is one known crypto library.
type LibraryProfile struct {
	Names       []string `json:"names"`
	Ecosystems  []string `json:"ecosystems"`
	DisplayName string   `json:"display_name"`

	// PQCSince is the first version known to ship NIST PQC primitives.
	// Empty means the knowledge base has no entry -- NOT that the library
	// lacks support. Absent means unobserved (P3).
	PQCSince string `json:"pqc_since"`
	PQCNote  string `json:"pqc_note"`

	FIPSCapable bool `json:"fips_capable"`

	DeprecatedNames []string `json:"deprecated_names"`
	DeprecationNote string   `json:"deprecation_note"`
	Citation        string   `json:"citation"`
}

// LoadKnowledgeBase reads and validates a knowledge base from disk.
//
// Validation happens at load rather than at use: a malformed profile must fail
// when the service starts, not silently mis-classify packages hours into a scan.
func LoadKnowledgeBase(path string) (*KnowledgeBase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read knowledge base: %w", err)
	}

	var kb KnowledgeBase
	if err := json.Unmarshal(raw, &kb); err != nil {
		return nil, fmt.Errorf("parse knowledge base: %w", err)
	}
	if err := kb.validate(); err != nil {
		return nil, err
	}

	kb.buildIndex()
	return &kb, nil
}

func (kb *KnowledgeBase) validate() error {
	var problems []string

	if kb.Version == "" {
		problems = append(problems, "version is required so a finding can cite the profile that classified it")
	}
	if len(kb.Libraries) == 0 {
		problems = append(problems, "at least one library profile is required")
	}

	seen := make(map[string]string)
	for i, lib := range kb.Libraries {
		if len(lib.Names) == 0 {
			problems = append(problems, fmt.Sprintf("libraries[%d] has no names", i))
		}
		if lib.DisplayName == "" {
			problems = append(problems, fmt.Sprintf("libraries[%d] has no display_name", i))
		}
		if lib.Citation == "" {
			// Every judgement Trinetra makes must be traceable to a source.
			problems = append(problems,
				fmt.Sprintf("libraries[%d] (%s) has no citation", i, lib.DisplayName))
		}
		for _, name := range lib.Names {
			key := strings.ToLower(name)
			if other, dup := seen[key]; dup {
				problems = append(problems, fmt.Sprintf(
					"package name %q claimed by both %q and %q", name, other, lib.DisplayName))
			}
			seen[key] = lib.DisplayName
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid knowledge base: %s", strings.Join(problems, "; "))
	}
	return nil
}

func (kb *KnowledgeBase) buildIndex() {
	kb.index = make(map[string]*LibraryProfile, len(kb.Libraries)*3)
	for i := range kb.Libraries {
		profile := &kb.Libraries[i]
		for _, name := range profile.Names {
			kb.index[strings.ToLower(name)] = profile
		}
	}
}

// Lookup returns the profile for a package name, if it is a known crypto
// library. The boolean is false for ordinary packages, which are skipped.
func (kb *KnowledgeBase) Lookup(name string) (*LibraryProfile, bool) {
	if kb.index == nil {
		return nil, false
	}
	profile, ok := kb.index[strings.ToLower(strings.TrimSpace(name))]
	return profile, ok
}

// SupportsPQC reports whether a version is known to ship PQC primitives.
//
// Returns (false, false) when the knowledge base has no PQCSince entry: "we do
// not know" is not "it does not support PQC", and collapsing the two would let
// the recommendation engine assert a fact nobody established.
func (p *LibraryProfile) SupportsPQC(version string) (supported bool, known bool) {
	if p.PQCSince == "" || version == "" {
		return false, false
	}
	cmp, ok := compareVersions(version, p.PQCSince)
	if !ok {
		return false, false
	}
	return cmp >= 0, true
}

// IsDeprecated reports whether this package name is a known-unmaintained one.
func (p *LibraryProfile) IsDeprecated(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, deprecated := range p.DeprecatedNames {
		if strings.ToLower(deprecated) == lower {
			return true
		}
	}
	return false
}

// compareVersions compares dotted numeric versions.
//
// Deliberately conservative: it reports failure rather than guessing on
// anything it cannot parse cleanly, so an exotic version string produces "not
// known" instead of a wrong PQC claim. Leading "v" and a trailing suffix such
// as "-r0" or "+deb12u1" are tolerated because distro packages always carry one.
func compareVersions(a, b string) (int, bool) {
	aParts, ok := parseVersion(a)
	if !ok {
		return 0, false
	}
	bParts, ok := parseVersion(b)
	if !ok {
		return 0, false
	}

	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		var av, bv int
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func parseVersion(version string) ([]int, bool) {
	cleaned := strings.TrimPrefix(strings.TrimSpace(version), "v")
	// Drop any packaging suffix: 3.0.11-1ubuntu2 -> 3.0.11
	for _, sep := range []string{"-", "+", "~", ":"} {
		if idx := strings.Index(cleaned, sep); idx > 0 {
			cleaned = cleaned[:idx]
		}
	}
	if cleaned == "" {
		return nil, false
	}

	fields := strings.Split(cleaned, ".")
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		// OpenSSL's letter releases put the suffix on the last component:
		// 1.1.1w, 3.0.2a. Strip a trailing alphabetic run so the numeric
		// ordering still works -- 1.1.1w and 1.1.1 compare equal, which is
		// correct for a PQC-capability question where letter releases are
		// patch-level and never add primitives.
		numeric := strings.TrimRightFunc(field, func(r rune) bool {
			return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		})
		if numeric == "" {
			// A component with no digits at all is not orderable.
			return nil, false
		}

		value, err := strconv.Atoi(numeric)
		if err != nil {
			// A non-numeric component means this is not a version we can
			// order reliably.
			return nil, false
		}
		parts = append(parts, value)
	}
	return parts, true
}

// defaultKnowledgeBase caches the process-wide knowledge base so a scan does not
// re-read and re-validate it per package.
var (
	defaultKB     *KnowledgeBase
	defaultKBOnce sync.Once
	defaultKBErr  error
)

// DefaultKnowledgeBase loads the knowledge base at path once per process.
func DefaultKnowledgeBase(path string) (*KnowledgeBase, error) {
	defaultKBOnce.Do(func() {
		defaultKB, defaultKBErr = LoadKnowledgeBase(path)
	})
	return defaultKB, defaultKBErr
}
