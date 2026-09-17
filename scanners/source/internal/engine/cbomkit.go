package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// CBOMkitEngine adapts PQCA CBOMkit (Apache-2.0, Linux Foundation).
//
// CBOMkit is the maintained detection engine for Java, Python and Go, and it
// resolves key size, mode and padding — the R19 fields. Adopting it is why
// Trinetra does not write 43 detection rules of its own.
//
// It is distributed as a Java library (cbomkit-lib) and as a full-stack server,
// neither of which is a CLI. This adapter therefore invokes a CLI entry point
// (cbomkit-action, or a thin wrapper jar) and is SKIPPED WHEN UNAVAILABLE
// rather than failing the scan: an environment without a JRE still gets a
// Semgrep-only inventory, and the missing coverage is reported as a gap.
//
// § 7.1: what Trinetra takes is the inventory. What it explicitly discards is
// CBOMkit's compliance verdict — Trinetra scores, CBOMkit does not (P1).
type CBOMkitEngine struct {
	// Binary is the CLI entry point. Empty disables the engine.
	Binary string
	// ExtraArgs are passed before the target path.
	ExtraArgs []string
	Version   string
}

// NewCBOMkitEngine reads configuration from the environment so deployment can
// enable the engine without a rebuild.
func NewCBOMkitEngine() *CBOMkitEngine {
	return &CBOMkitEngine{
		Binary:  os.Getenv("TRINETRA_CBOMKIT_BINARY"),
		Version: os.Getenv("TRINETRA_CBOMKIT_VERSION"),
	}
}

func (e *CBOMkitEngine) Name() string { return "cbomkit" }

// Languages are the languages CBOMkit actually covers. This list is deliberately
// honest: C# is in development upstream and JS/TS/C/C++ are not covered at all,
// which is why the Semgrep engine carries those.
func (e *CBOMkitEngine) Languages() []string {
	return []string{"java", "python", "go"}
}

func (e *CBOMkitEngine) Tool() cbom.Tool {
	version := e.Version
	if version == "" {
		version = "unknown"
	}
	return cbom.Tool{
		Vendor:  "PQCA",
		Name:    "cbomkit",
		Version: version,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run, so the reason reaches the user
// as a coverage gap instead of being silently swallowed.
func (e *CBOMkitEngine) Available(ctx context.Context) error {
	if strings.TrimSpace(e.Binary) == "" {
		return fmt.Errorf("TRINETRA_CBOMKIT_BINARY is not configured")
	}
	path, err := exec.LookPath(e.Binary)
	if err != nil {
		return fmt.Errorf("cbomkit entry point %q not found", filepath.Base(e.Binary))
	}
	e.Binary = path
	return nil
}

// Scan runs CBOMkit and adapts its CycloneDX output.
func (e *CBOMkitEngine) Scan(ctx context.Context, root string) (Result, error) {
	args := append([]string{}, e.ExtraArgs...)
	args = append(args, root)

	out, err := exec.CommandContext(ctx, e.Binary, args...).Output()
	if err != nil {
		return Result{}, fmt.Errorf("cbomkit invocation failed")
	}

	doc, err := parseCBOMkitOutput(out)
	if err != nil {
		// The adapter is the trust boundary: malformed output is a scanner
		// error, never a crash.
		return Result{}, fmt.Errorf("cbomkit output could not be parsed: %w", err)
	}

	return AdaptCBOMkitDocument(doc), nil
}

// cbomkitDocument is the subset of CycloneDX that Trinetra reads back.
type cbomkitDocument struct {
	Components []cbomkitComponent `json:"components"`
}

type cbomkitComponent struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	CryptoProperties struct {
		AssetType           string `json:"assetType"`
		OID                 string `json:"oid"`
		AlgorithmProperties struct {
			Primitive              string   `json:"primitive"`
			ParameterSetIdentifier string   `json:"parameterSetIdentifier"`
			Curve                  string   `json:"curve"`
			Mode                   string   `json:"mode"`
			Padding                string   `json:"padding"`
			CryptoFunctions        []string `json:"cryptoFunctions"`
		} `json:"algorithmProperties"`
	} `json:"cryptoProperties"`
	Evidence struct {
		Occurrences []struct {
			Location string `json:"location"`
			Line     int    `json:"line"`
		} `json:"occurrences"`
	} `json:"evidence"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

func parseCBOMkitOutput(raw []byte) (cbomkitDocument, error) {
	var doc cbomkitDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("invalid json: %w", err)
	}
	return doc, nil
}

// AdaptCBOMkitDocument converts CBOMkit components into canonical findings.
//
// Exported so the adapter can be tested against recorded CBOMkit output without
// the engine installed — which is how this adapter is verified on a machine
// with no JRE.
func AdaptCBOMkitDocument(doc cbomkitDocument) Result {
	var result Result

	for _, c := range doc.Components {
		// Non-cryptographic-asset components are legitimately present in a
		// CBOM and are skipped, not rejected.
		if c.Type != "cryptographic-asset" {
			continue
		}

		finding := cbom.Finding{
			AssetType:       cbomkitAssetType(c.CryptoProperties.AssetType, c.Properties),
			Name:            c.Name,
			OID:             c.CryptoProperties.OID,
			Primitive:       cbomkitPrimitive(c.CryptoProperties.AlgorithmProperties.Primitive),
			Mode:            normaliseMode(c.CryptoProperties.AlgorithmProperties.Mode),
			Padding:         normalisePadding(c.CryptoProperties.AlgorithmProperties.Padding),
			Curve:           c.CryptoProperties.AlgorithmProperties.Curve,
			DetectionMethod: cbom.DetectCBOMkit,
			// CBOMkit resolves symbols rather than matching text, so its
			// findings start at high confidence.
			Confidence: cbom.ConfidenceHigh,
			RuleID:     "cbomkit",
		}

		for _, fn := range c.CryptoProperties.AlgorithmProperties.CryptoFunctions {
			finding.Purposes = append(finding.Purposes, cbomkitPurpose(fn))
		}

		param := c.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier
		if size, err := strconv.Atoi(param); err == nil && size > 0 {
			finding.KeySizeBits = cbom.IntPtr(size)
		} else if param != "" {
			finding.ParameterSet = param
		}

		// Trinetra's own namespaced properties survive a round trip through
		// CBOMkit's output if a previous stage added them.
		for _, p := range c.Properties {
			switch p.Name {
			case cbom.TrinetraKeySizeProperty:
				if size, err := strconv.Atoi(p.Value); err == nil && size > 0 {
					finding.KeySizeBits = cbom.IntPtr(size)
				}
			case cbom.TrinetraDataCategoryProperty:
				finding.DataCategory = p.Value
			}
		}

		if len(c.Evidence.Occurrences) > 0 {
			occ := c.Evidence.Occurrences[0]
			finding.Location = cbom.Location{
				Path: filepath.ToSlash(occ.Location),
				Line: occ.Line,
			}
		}

		// A finding with no location cannot be verified by a human, and an
		// unsourced finding is a bug rather than a low-quality artefact.
		if finding.Location.Path == "" {
			result.Gaps = append(result.Gaps, Gap{
				Kind:   "unlocatable_finding",
				Reason: fmt.Sprintf("cbomkit reported %q with no source location", c.Name),
				Count:  1,
			})
			continue
		}

		finding.Algorithm = cbomkitAlgorithmName(c.Name)
		result.Findings = append(result.Findings, finding.Normalise())
	}

	return result
}

func cbomkitAssetType(raw string, props []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}) cbom.AssetType {
	// A Trinetra hint, if present, is authoritative: it disambiguates the
	// canonical types that share the related-crypto-material spelling.
	for _, p := range props {
		if p.Name == cbom.TrinetraAssetTypeProperty && p.Value != "" {
			return cbom.AssetType(p.Value)
		}
	}
	switch raw {
	case "algorithm":
		return cbom.AssetAlgorithm
	case "certificate":
		return cbom.AssetCertificate
	case "protocol":
		return cbom.AssetProtocol
	case "library":
		return cbom.AssetLibrary
	case "related-crypto-material":
		return cbom.AssetRelatedMaterial
	default:
		// Degrade rather than fail: a newer assetType from a third-party CBOM
		// should still ingest.
		return cbom.AssetAlgorithm
	}
}

func cbomkitPrimitive(raw string) cbom.Primitive {
	switch raw {
	case "block-cipher":
		return cbom.PrimitiveBlockCipher
	case "stream-cipher":
		return cbom.PrimitiveStreamCipher
	case "hash":
		return cbom.PrimitiveHash
	case "mac":
		return cbom.PrimitiveMAC
	case "ae":
		return cbom.PrimitiveAEAD
	case "signature":
		return cbom.PrimitiveSignature
	case "pke":
		return cbom.PrimitivePKE
	case "kem":
		return cbom.PrimitiveKEM
	case "key-agree":
		return cbom.PrimitiveKeyAgreement
	case "kdf":
		return cbom.PrimitiveKDF
	case "drbg":
		return cbom.PrimitiveDRBG
	case "":
		return ""
	default:
		return cbom.PrimitiveOther
	}
}

func cbomkitPurpose(raw string) cbom.Purpose {
	switch raw {
	case "encrypt":
		return cbom.PurposeEncryption
	case "decrypt":
		return cbom.PurposeDecryption
	case "sign":
		return cbom.PurposeDigitalSignature
	case "verify":
		return cbom.PurposeVerify
	case "encapsulate":
		return cbom.PurposeKeyEncapsulation
	case "keygen":
		return cbom.PurposeKeyAgreement
	case "derive":
		return cbom.PurposeKeyDerivation
	case "digest":
		return cbom.PurposeHashing
	case "tag":
		return cbom.PurposeAuthentication
	case "generate":
		return cbom.PurposeRandomGeneration
	default:
		return cbom.PurposeOther
	}
}

// cbomkitAlgorithmName strips size and mode from a display name to get the bare
// algorithm, e.g. "AES-128-CBC" -> "aes".
func cbomkitAlgorithmName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	fields := strings.FieldsFunc(lower, func(r rune) bool { return r == '-' || r == '_' || r == '/' })
	if len(fields) == 0 {
		return lower
	}
	return fields[0]
}
