package cbom

import (
	"errors"
	"fmt"
	"strings"
)

// Validation happens twice by design: here in Go before the file is written,
// and again in Python on ingest. Defence in depth — a schema drift on either
// side is caught at the boundary rather than three layers deep.

// ValidationError lists everything wrong with a document, rather than failing on
// the first problem, so a rule author sees all of it in one run.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("cbom validation failed: %s", strings.Join(e.Problems, "; "))
}

var validAssetTypes = map[string]bool{
	"algorithm":               true,
	"certificate":             true,
	"protocol":                true,
	"library":                 true,
	"related-crypto-material": true,
}

// Validate checks a document against the frozen contract.
//
// A document with zero components is explicitly valid: a repository genuinely
// free of cryptography is a real result, and rejecting it would report a clean
// codebase as an error.
func Validate(doc Document) error {
	var problems []string

	if doc.BOMFormat != "CycloneDX" {
		problems = append(problems, fmt.Sprintf("bomFormat must be CycloneDX, got %q", doc.BOMFormat))
	}
	if doc.SpecVersion != SpecVersion {
		problems = append(problems, fmt.Sprintf("specVersion must be %s, got %q", SpecVersion, doc.SpecVersion))
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		problems = append(problems, "serialNumber must be a urn:uuid")
	}
	if doc.Metadata.Timestamp == "" {
		problems = append(problems, "metadata.timestamp is required")
	}
	if len(doc.Metadata.Tools) == 0 {
		// Not pedantry: a CBOM that cannot say what produced it cannot be
		// audited, and a finding's credibility depends on the rule version.
		problems = append(problems, "metadata.tools must record at least one tool")
	}
	for i, tool := range doc.Metadata.Tools {
		if tool.Name == "" || tool.Version == "" {
			problems = append(problems, fmt.Sprintf("metadata.tools[%d] needs name and version", i))
		}
	}

	seenRefs := make(map[string]bool, len(doc.Components))
	for i, c := range doc.Components {
		prefix := fmt.Sprintf("components[%d]", i)

		if c.Type != "cryptographic-asset" {
			problems = append(problems, fmt.Sprintf("%s.type must be cryptographic-asset", prefix))
		}
		if c.Name == "" {
			problems = append(problems, prefix+".name is required")
		}
		if c.BOMRef == "" {
			problems = append(problems, prefix+".bom-ref is required")
		} else if seenRefs[c.BOMRef] {
			problems = append(problems, fmt.Sprintf("%s.bom-ref %q is duplicated", prefix, c.BOMRef))
		}
		seenRefs[c.BOMRef] = true

		if c.CryptoProperties == nil {
			problems = append(problems, prefix+".cryptoProperties is required")
			continue
		}
		if !validAssetTypes[c.CryptoProperties.AssetType] {
			problems = append(problems, fmt.Sprintf("%s.cryptoProperties.assetType %q is not a CycloneDX 1.6 value",
				prefix, c.CryptoProperties.AssetType))
		}

		// The rule that keeps the risk engine honest, checked at the wire
		// boundary too: OpenSSL being installed proves an implementation
		// exists, not that any algorithm is used.
		if c.CryptoProperties.AssetType == "library" && c.CryptoProperties.AlgorithmProperties != nil {
			problems = append(problems, prefix+": library components must not carry algorithmProperties")
		}

		if c.Evidence == nil || len(c.Evidence.Occurrences) == 0 {
			problems = append(problems, prefix+": every finding must cite at least one occurrence")
		} else {
			for j, occ := range c.Evidence.Occurrences {
				if occ.Location == "" {
					problems = append(problems, fmt.Sprintf("%s.evidence.occurrences[%d].location is required", prefix, j))
				}
				if strings.HasPrefix(occ.Location, "/") || strings.Contains(occ.Location, ":\\") {
					problems = append(problems, fmt.Sprintf(
						"%s.evidence.occurrences[%d].location must be relative to the target root, got %q",
						prefix, j, occ.Location))
				}
			}
		}

		for _, p := range c.Properties {
			if !strings.HasPrefix(p.Name, "trinetra:") {
				problems = append(problems, fmt.Sprintf(
					"%s: property %q must use the trinetra: namespace so unknown consumers ignore it safely",
					prefix, p.Name))
			}
		}
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// ErrNotValidated guards the write path.
var ErrNotValidated = errors.New("document failed validation and was not written")
