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

// TheiaEngine adapts PQCA cbomkit-theia (Apache-2.0, Linux Foundation).
//
// theia is a Go CLI that scans container images and directories and emits
// CycloneDX 1.6, detecting X.509 certificates, keys (via gitleaks), TLS cipher
// suites from OpenSSL configuration, and Java security configuration.
//
// It is **configuration, not a hard dependency**: the binary is not always
// present, and a deployment without it still gets a complete inventory from the
// Syft, PKI and config engines. When it is present it adds gitleaks-grade
// secret detection and image-layer attribution that those engines do not have.
//
// § 7.1 applies as everywhere else: Trinetra takes theia's inventory and
// discards any verdict it offers.
type TheiaEngine struct {
	// Binary is the CLI entry point. Empty disables the engine.
	Binary  string
	Version string
}

// NewTheiaEngine reads configuration from the environment, so a deployment can
// enable the engine without a rebuild.
func NewTheiaEngine() *TheiaEngine {
	return &TheiaEngine{
		Binary:  os.Getenv("TRINETRA_THEIA_BINARY"),
		Version: os.Getenv("TRINETRA_THEIA_VERSION"),
	}
}

func (e *TheiaEngine) Name() string { return "cbomkit-theia" }

// SupportsImages is true: this is the engine that makes image scanning real.
func (e *TheiaEngine) SupportsImages() bool { return true }

func (e *TheiaEngine) Detects() []string {
	return []string{
		"x509 certificates in image layers",
		"keys and secrets (gitleaks)",
		"openssl and java security configuration",
	}
}

func (e *TheiaEngine) Tool() cbom.Tool {
	version := e.Version
	if version == "" {
		version = "unknown"
	}
	return cbom.Tool{
		Vendor:  "PQCA",
		Name:    "cbomkit-theia",
		Version: version,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run, so the reason reaches the user
// as a coverage gap instead of being swallowed.
func (e *TheiaEngine) Available(context.Context) error {
	if strings.TrimSpace(e.Binary) == "" {
		return fmt.Errorf("TRINETRA_THEIA_BINARY is not configured")
	}
	path, err := exec.LookPath(e.Binary)
	if err != nil {
		return fmt.Errorf("cbomkit-theia binary %q not found", filepath.Base(e.Binary))
	}
	e.Binary = path
	return nil
}

// Scan runs theia and adapts its CycloneDX output.
func (e *TheiaEngine) Scan(ctx context.Context, target Target) (Result, error) {
	subcommand := "dir"
	argument := target.Path
	if target.IsImage() {
		subcommand = "image"
		argument = target.ImageReference
	}

	out, err := exec.CommandContext(ctx, e.Binary, subcommand, argument).Output()
	if err != nil {
		// Never surface the tool's stderr: an auth failure message from a
		// registry pull can contain credentials.
		return Result{}, fmt.Errorf("cbomkit-theia invocation failed")
	}

	doc, err := parseTheiaOutput(out)
	if err != nil {
		return Result{}, fmt.Errorf("cbomkit-theia output could not be parsed: %w", err)
	}

	return AdaptTheiaDocument(doc), nil
}

// theiaDocument is the subset of CycloneDX that Trinetra reads back.
type theiaDocument struct {
	Components []theiaComponent `json:"components"`
}

type theiaComponent struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	PURL             string `json:"purl"`
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
		CertificateProperties struct {
			SubjectName           string `json:"subjectName"`
			IssuerName            string `json:"issuerName"`
			NotValidBefore        string `json:"notValidBefore"`
			NotValidAfter         string `json:"notValidAfter"`
			SignatureAlgorithmRef string `json:"signatureAlgorithmRef"`
			SubjectPublicKeyRef   string `json:"subjectPublicKeyRef"`
			CertificateFormat     string `json:"certificateFormat"`
		} `json:"certificateProperties"`
		RelatedCryptoMaterialProperties struct {
			Type      string `json:"type"`
			Size      int    `json:"size"`
			Format    string `json:"format"`
			State     string `json:"state"`
			SecuredBy struct {
				Mechanism string `json:"mechanism"`
			} `json:"securedBy"`
		} `json:"relatedCryptoMaterialProperties"`
		ProtocolProperties struct {
			Type         string `json:"type"`
			Version      string `json:"version"`
			CipherSuites []struct {
				Name string `json:"name"`
			} `json:"cipherSuites"`
		} `json:"protocolProperties"`
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

func parseTheiaOutput(raw []byte) (theiaDocument, error) {
	var doc theiaDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("invalid json: %w", err)
	}
	return doc, nil
}

// AdaptTheiaDocument converts theia components into canonical findings.
//
// Exported so the adapter can be tested against recorded theia output without
// the binary installed — which is how it is verified here.
func AdaptTheiaDocument(doc theiaDocument) Result {
	var result Result

	for _, component := range doc.Components {
		// Non-cryptographic-asset components are legitimately present and are
		// skipped, not rejected.
		if component.Type != "cryptographic-asset" {
			continue
		}

		assetType := theiaAssetType(component)

		finding := cbom.Finding{
			AssetType:       assetType,
			Name:            component.Name,
			OID:             component.CryptoProperties.OID,
			DetectionMethod: cbom.DetectCertificate,
			Confidence:      cbom.ConfidenceHigh,
			RuleID:          "cbomkit-theia",
		}

		switch assetType {
		case cbom.AssetCertificate:
			applyTheiaCertificate(&finding, component)
		case cbom.AssetKey:
			applyTheiaKey(&finding, component)
		case cbom.AssetProtocol:
			applyTheiaProtocol(&finding, component)
		default:
			applyTheiaAlgorithm(&finding, component)
		}

		// Trinetra's own namespaced properties survive a round trip.
		for _, property := range component.Properties {
			switch property.Name {
			case cbom.TrinetraKeySizeProperty:
				if size, err := strconv.Atoi(property.Value); err == nil && size > 0 {
					finding.KeySizeBits = cbom.IntPtr(size)
				}
			case cbom.TrinetraDataCategoryProperty:
				finding.DataCategory = property.Value
			}
		}

		if len(component.Evidence.Occurrences) > 0 {
			occurrence := component.Evidence.Occurrences[0]
			finding.Location = cbom.Location{
				Path: strings.TrimPrefix(filepath.ToSlash(occurrence.Location), "/"),
				Line: occurrence.Line,
			}
		}

		// An unsourced finding cannot be verified by a human, so it becomes a
		// visible gap rather than an unverifiable artefact.
		if finding.Location.Path == "" {
			result.Gaps = append(result.Gaps, Gap{
				Kind:   "unlocatable_finding",
				Reason: fmt.Sprintf("cbomkit-theia reported %q with no location", component.Name),
				Count:  1,
			})
			continue
		}

		result.Findings = append(result.Findings, finding.Normalise())
	}

	return result
}

func theiaAssetType(component theiaComponent) cbom.AssetType {
	// A Trinetra hint is authoritative where present: it disambiguates the
	// canonical types that share the related-crypto-material wire spelling.
	for _, property := range component.Properties {
		if property.Name == cbom.TrinetraAssetTypeProperty && property.Value != "" {
			return cbom.AssetType(property.Value)
		}
	}

	switch component.CryptoProperties.AssetType {
	case "certificate":
		return cbom.AssetCertificate
	case "protocol":
		return cbom.AssetProtocol
	case "library":
		return cbom.AssetLibrary
	case "related-crypto-material":
		// theia reports keys through this type; the material subtype tells
		// which kind. Anything key-shaped becomes a key artefact so that key
		// lifecycle fields are available downstream.
		material := strings.ToLower(component.CryptoProperties.RelatedCryptoMaterialProperties.Type)
		if strings.Contains(material, "key") || strings.Contains(material, "secret") {
			return cbom.AssetKey
		}
		return cbom.AssetRelatedMaterial
	case "algorithm":
		return cbom.AssetAlgorithm
	default:
		// Degrade rather than fail: a newer assetType should still ingest.
		return cbom.AssetAlgorithm
	}
}

func applyTheiaCertificate(finding *cbom.Finding, component theiaComponent) {
	properties := component.CryptoProperties.CertificateProperties

	// Signature algorithm and public-key algorithm are kept separate: one is an
	// authenticity risk at CRQC time, the other a retroactive confidentiality
	// risk, and the risk engine must be able to tell them apart.
	notes := []string{}
	if properties.IssuerName != "" {
		notes = append(notes, "issuer "+properties.IssuerName)
	}
	if properties.NotValidBefore != "" {
		notes = append(notes, "not_before "+properties.NotValidBefore)
	}
	if properties.NotValidAfter != "" {
		notes = append(notes, "not_after "+properties.NotValidAfter)
	}
	if properties.SignatureAlgorithmRef != "" {
		notes = append(notes, "signature "+properties.SignatureAlgorithmRef)
	}
	if properties.SubjectPublicKeyRef != "" {
		notes = append(notes, "public_key "+properties.SubjectPublicKeyRef)
	}

	finding.Algorithm = theiaAlgorithmName(properties.SignatureAlgorithmRef, component.Name)
	finding.Snippet = strings.Join(notes, "; ")
	finding.DetectionMethod = cbom.DetectCertificate
}

func applyTheiaKey(finding *cbom.Finding, component theiaComponent) {
	material := component.CryptoProperties.RelatedCryptoMaterialProperties

	if material.Size > 0 {
		finding.KeySizeBits = cbom.IntPtr(material.Size)
	}
	finding.Algorithm = theiaAlgorithmName("", component.Name)

	// theia uses gitleaks, which finds real secrets. Trinetra records that key
	// material exists and never what it is.
	finding.Redacted = true
	notes := []string{"key material detected; contents withheld"}
	if material.Type != "" {
		notes = append(notes, "type "+material.Type)
	}
	if material.State != "" {
		notes = append(notes, "state "+material.State)
	}
	if material.SecuredBy.Mechanism != "" {
		notes = append(notes, "secured_by "+material.SecuredBy.Mechanism)
	}
	finding.Snippet = strings.Join(notes, "; ")
}

func applyTheiaProtocol(finding *cbom.Finding, component theiaComponent) {
	properties := component.CryptoProperties.ProtocolProperties

	finding.Algorithm = strings.ToLower(properties.Type)
	finding.ParameterSet = properties.Version

	notes := []string{"declared in image configuration"}
	if len(properties.CipherSuites) > 0 {
		names := make([]string, 0, len(properties.CipherSuites))
		for _, suite := range properties.CipherSuites {
			names = append(names, suite.Name)
		}
		notes = append(notes, "cipher suites: "+strings.Join(names, ", "))
	}
	finding.Snippet = strings.Join(notes, "; ")
	finding.DetectionMethod = cbom.DetectConfigParse
}

func applyTheiaAlgorithm(finding *cbom.Finding, component theiaComponent) {
	properties := component.CryptoProperties.AlgorithmProperties

	finding.Primitive = theiaPrimitive(properties.Primitive)
	finding.Mode = strings.ToLower(properties.Mode)
	finding.Padding = strings.ToLower(properties.Padding)
	finding.Curve = properties.Curve
	finding.Algorithm = theiaAlgorithmName("", component.Name)

	if size, err := strconv.Atoi(properties.ParameterSetIdentifier); err == nil && size > 0 {
		finding.KeySizeBits = cbom.IntPtr(size)
	} else if properties.ParameterSetIdentifier != "" {
		finding.ParameterSet = properties.ParameterSetIdentifier
	}

	for _, function := range properties.CryptoFunctions {
		finding.Purposes = append(finding.Purposes, theiaPurpose(function))
	}
}

func theiaPrimitive(raw string) cbom.Primitive {
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

func theiaPurpose(raw string) cbom.Purpose {
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

// theiaAlgorithmName extracts a bare algorithm from a reference or display name.
func theiaAlgorithmName(reference, name string) string {
	candidate := strings.TrimSpace(reference)
	if candidate == "" {
		candidate = strings.TrimSpace(name)
	}
	if candidate == "" {
		return ""
	}

	lower := strings.ToLower(candidate)
	// A CN= subject is not an algorithm name; leave it unset rather than
	// inventing one from a hostname.
	if strings.Contains(lower, "=") {
		return ""
	}

	fields := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '-' || r == '_' || r == '/' || r == ' '
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
