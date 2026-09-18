package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// PKCS11Engine inventories hardware security modules (R6).
//
// It reads a **PKCS#11 inventory export** rather than dlopen-ing a vendor
// module. That is a deliberate design choice, not a shortcut:
//
//   - A PKCS#11 provider is a native library that must be loaded into the
//     scanner's process. Loading a vendor .so into a service that also holds
//     cloud credentials is a large and unnecessary attack surface.
//   - HSMs live on isolated networks. In a real defence deployment the scanner
//     cannot reach the module at all; an operator runs `pkcs11-tool -O` or the
//     vendor's own utility on the HSM host and hands over the output.
//   - The export is reviewable. A human can read what was collected before it
//     enters the inventory, which matters for the most sensitive asset class
//     Trinetra touches.
//
// **Metadata only, and more strictly than anywhere else.** An HSM exists so that
// key material cannot be extracted; this engine reads slot, token and key-object
// attributes and nothing else. `CKA_VALUE` is never read even when a token would
// permit it.
type PKCS11Engine struct {
	// ExportPath is the inventory file. Empty disables the engine.
	ExportPath string
}

// NewPKCS11Engine reads configuration from the environment.
func NewPKCS11Engine() *PKCS11Engine {
	return &PKCS11Engine{ExportPath: os.Getenv("TRINETRA_PKCS11_EXPORT")}
}

func (e *PKCS11Engine) Name() string { return "pkcs11" }

func (e *PKCS11Engine) Detects() []string {
	return []string{"hsm tokens", "key objects", "firmware and FIPS certification"}
}

func (e *PKCS11Engine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "pkcs11-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run.
func (e *PKCS11Engine) Available(_ context.Context, target Target) error {
	path := e.exportPath(target)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("no PKCS#11 inventory export configured (TRINETRA_PKCS11_EXPORT)")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("PKCS#11 inventory export is not readable")
	}
	return nil
}

func (e *PKCS11Engine) exportPath(target Target) string {
	if target.ModulePath != "" {
		return target.ModulePath
	}
	return e.ExportPath
}

// PKCS11Export is the inventory an operator hands over.
//
// The shape mirrors what PKCS#11 itself exposes, so an export is a faithful
// transcription rather than an interpretation: slots contain tokens, tokens
// contain key objects.
type PKCS11Export struct {
	// Collector records what produced the export, so a finding can cite it.
	Collector   string       `json:"collector"`
	CollectedAt string       `json:"collected_at"`
	Slots       []PKCS11Slot `json:"slots"`
}

// PKCS11Slot is one slot and the token in it.
type PKCS11Slot struct {
	SlotID          int    `json:"slot_id"`
	Description     string `json:"description"`
	ManufacturerID  string `json:"manufacturer_id"`
	TokenLabel      string `json:"token_label"`
	TokenModel      string `json:"token_model"`
	TokenSerial     string `json:"token_serial"`
	FirmwareVersion string `json:"firmware_version"`
	HardwareVersion string `json:"hardware_version"`
	// FIPSCertificate is the NIST CMVP certificate number, where the operator
	// recorded one. Empty means not recorded, never "not certified" (P3).
	FIPSCertificate string `json:"fips_certificate"`
	FIPSLevel       string `json:"fips_level"`
	// SupportedMechanisms are the CKM_* names the token advertises. This is
	// what decides whether the HSM can do PQC at all.
	SupportedMechanisms []string       `json:"supported_mechanisms"`
	Objects             []PKCS11Object `json:"objects"`
}

// PKCS11Object is one key object. It carries no key material by construction.
type PKCS11Object struct {
	Label       string `json:"label"`
	Class       string `json:"class"`    // CKO_PRIVATE_KEY, CKO_SECRET_KEY, ...
	KeyType     string `json:"key_type"` // CKK_RSA, CKK_EC, CKK_AES, ...
	ModulusBits int    `json:"modulus_bits"`
	ECParams    string `json:"ec_params"`
	ID          string `json:"id"`
	Extractable bool   `json:"extractable"`
	Sensitive   bool   `json:"sensitive"`
}

// pqcMechanisms are the PKCS#11 mechanism names that indicate PQC capability.
//
// Vendors ship these under both standardised and vendor-prefixed names, so the
// match is a substring rather than an exact one.
var pqcMechanisms = []string{
	"ML_KEM", "ML-KEM", "MLKEM", "KYBER",
	"ML_DSA", "ML-DSA", "MLDSA", "DILITHIUM",
	"SLH_DSA", "SLH-DSA", "SPHINCS",
	"FALCON", "FN_DSA", "FN-DSA",
	"LMS", "XMSS",
}

// Scan reads the export and emits hardware-module and key artefacts.
func (e *PKCS11Engine) Scan(_ context.Context, target Target) (Result, error) {
	path := e.exportPath(target)

	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("PKCS#11 export could not be read")
	}

	export, err := parsePKCS11Export(raw)
	if err != nil {
		return Result{}, err
	}

	var result Result
	for _, slot := range export.Slots {
		result.ObjectsInspected++
		result.Findings = append(result.Findings, hardwareModuleFinding(slot))

		for _, object := range slot.Objects {
			finding, ok := hsmKeyFinding(slot, object)
			if !ok {
				continue
			}
			result.ObjectsInspected++
			result.Findings = append(result.Findings, finding)
		}

		// An HSM whose mechanism list was not collected cannot be assessed for
		// PQC capability, and that is the question this engine exists to
		// answer. Say so rather than implying the HSM lacks support.
		if len(slot.SupportedMechanisms) == 0 {
			result.Gaps = append(result.Gaps, Gap{
				Path: slotPath(slot),
				Kind: "partial_metadata",
				Reason: "the token's supported mechanisms were not collected, " +
					"so its PQC capability could not be determined",
				Count: 1,
			})
		}
	}

	return result, nil
}

// parsePKCS11Export validates the export rather than trusting it.
func parsePKCS11Export(raw []byte) (PKCS11Export, error) {
	var export PKCS11Export
	if err := json.Unmarshal(raw, &export); err != nil {
		return export, fmt.Errorf("PKCS#11 export is not valid json: %w", err)
	}

	// An export that names no collector cannot be audited: a reader has no way
	// to know which utility produced it or on which host.
	if strings.TrimSpace(export.Collector) == "" {
		return export, fmt.Errorf("PKCS#11 export does not record which tool collected it")
	}
	return export, nil
}

// hardwareModuleFinding describes the module itself.
func hardwareModuleFinding(slot PKCS11Slot) cbom.Finding {
	name := strings.TrimSpace(slot.TokenLabel)
	if name == "" {
		name = strings.TrimSpace(slot.Description)
	}
	if name == "" {
		name = fmt.Sprintf("PKCS#11 slot %d", slot.SlotID)
	}

	return cbom.Finding{
		AssetType:       cbom.AssetHardwareModule,
		Name:            name,
		DetectionMethod: cbom.DetectPKCS11,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "pkcs11:token",
		Location:        cbom.Location{Path: slotPath(slot), Symbol: slot.TokenSerial},
		Snippet:         describeSlot(slot),
	}.Normalise()
}

// hsmKeyFinding describes one key object.
//
// Public keys are skipped: a public key in an HSM is not a secret and carries no
// migration burden of its own beyond the private key it pairs with, which is
// already reported.
func hsmKeyFinding(slot PKCS11Slot, object PKCS11Object) (cbom.Finding, bool) {
	class := strings.ToUpper(strings.TrimSpace(object.Class))
	if class == "CKO_PUBLIC_KEY" || class == "CKO_CERTIFICATE" || class == "CKO_DATA" {
		return cbom.Finding{}, false
	}

	algorithm, keySize, curve := pkcs11KeyType(object)

	label := strings.TrimSpace(object.Label)
	if label == "" {
		label = strings.TrimSpace(object.ID)
	}
	if label == "" {
		label = "unlabelled key"
	}

	name := label
	if algorithm != "" {
		name = fmt.Sprintf("%s (%s)", label, strings.ToUpper(algorithm))
	}

	finding := cbom.Finding{
		AssetType:       cbom.AssetKey,
		Name:            name,
		Algorithm:       algorithm,
		Curve:           curve,
		DetectionMethod: cbom.DetectPKCS11,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "pkcs11:key",
		Location: cbom.Location{
			Path:   slotPath(slot) + "/" + label,
			Symbol: slot.TokenSerial,
		},
		// The key lives in hardware and its material was never read. The flag
		// tells the UI that this is withheld by design rather than missing.
		Redacted: true,
		Snippet:  describeObject(object),
	}

	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}

	return finding.Normalise(), true
}

// pkcs11KeyType maps a CKK_* key type to canonical algorithm, size and curve.
func pkcs11KeyType(object PKCS11Object) (algorithm string, keySize int, curve string) {
	switch strings.ToUpper(strings.TrimSpace(object.KeyType)) {
	case "CKK_RSA":
		return "rsa", object.ModulusBits, ""
	case "CKK_EC", "CKK_ECDSA":
		return "ecdsa", ecCurveBits(object.ECParams), normaliseECParams(object.ECParams)
	case "CKK_EC_EDWARDS":
		return "ed25519", 255, "Ed25519"
	case "CKK_AES":
		return "aes", object.ModulusBits, ""
	case "CKK_DES3":
		return "3des", 168, ""
	case "CKK_GENERIC_SECRET":
		return "hmac", object.ModulusBits, ""
	case "CKK_DH":
		return "dh", object.ModulusBits, ""
	case "":
		return "", 0, ""
	default:
		// An unrecognised key type is reported without an algorithm rather
		// than guessed at: a vendor-specific type must not be mislabelled.
		return "", object.ModulusBits, ""
	}
}

// ecCurveBits returns the field size for a named curve, or 0 when unknown.
func ecCurveBits(params string) int {
	switch normaliseECParams(params) {
	case "P-256", "secp256k1":
		return 256
	case "P-384":
		return 384
	case "P-521":
		return 521
	default:
		return 0
	}
}

func normaliseECParams(params string) string {
	trimmed := strings.TrimSpace(params)
	switch strings.ToLower(trimmed) {
	case "prime256v1", "secp256r1", "p-256", "nistp256":
		return "P-256"
	case "secp384r1", "p-384", "nistp384":
		return "P-384"
	case "secp521r1", "p-521", "nistp521":
		return "P-521"
	case "secp256k1":
		return "secp256k1"
	default:
		return trimmed
	}
}

// describeSlot builds the module's evidence note.
//
// SupportsPQC is the field that decides whether migration is a code change or a
// hardware purchase, so it leads — and says "not recorded" rather than "no"
// when the mechanism list was not collected.
func describeSlot(slot PKCS11Slot) string {
	parts := []string{fmt.Sprintf("pkcs#11 slot %d", slot.SlotID)}

	if slot.ManufacturerID != "" {
		parts = append(parts, "vendor "+strings.TrimSpace(slot.ManufacturerID))
	}
	if slot.TokenModel != "" {
		parts = append(parts, "model "+strings.TrimSpace(slot.TokenModel))
	}
	if slot.FirmwareVersion != "" {
		parts = append(parts, "firmware "+slot.FirmwareVersion)
	}

	if slot.FIPSCertificate != "" {
		certified := "FIPS certificate " + slot.FIPSCertificate
		if slot.FIPSLevel != "" {
			certified += " (level " + slot.FIPSLevel + ")"
		}
		parts = append(parts, certified)
	} else {
		parts = append(parts, "FIPS certification not recorded")
	}

	switch {
	case len(slot.SupportedMechanisms) == 0:
		parts = append(parts, "PQC capability not recorded: mechanisms not collected")
	case slotSupportsPQC(slot):
		parts = append(parts, "advertises PQC mechanisms: "+
			strings.Join(pqcMechanismsIn(slot), ", "))
	default:
		parts = append(parts, fmt.Sprintf(
			"no PQC mechanisms among the %d advertised; migrating this module is a "+
				"firmware or hardware change, not a code change",
			len(slot.SupportedMechanisms)))
	}

	return strings.Join(parts, "; ")
}

// slotSupportsPQC reports whether the token advertises any PQC mechanism.
func slotSupportsPQC(slot PKCS11Slot) bool {
	return len(pqcMechanismsIn(slot)) > 0
}

func pqcMechanismsIn(slot PKCS11Slot) []string {
	var found []string
	for _, mechanism := range slot.SupportedMechanisms {
		upper := strings.ToUpper(mechanism)
		for _, candidate := range pqcMechanisms {
			if strings.Contains(upper, candidate) {
				found = append(found, mechanism)
				break
			}
		}
	}
	return found
}

// describeObject builds a key object's evidence note.
func describeObject(object PKCS11Object) string {
	parts := []string{"key material held in hardware; contents never read"}

	if object.Class != "" {
		parts = append(parts, "class "+object.Class)
	}
	if object.KeyType != "" {
		parts = append(parts, "type "+object.KeyType)
	}

	// An extractable key in an HSM is a finding in its own right: the module's
	// whole value is that material cannot leave it.
	if object.Extractable {
		parts = append(parts, "EXTRACTABLE: this key can be exported from the module")
	}
	if !object.Sensitive {
		parts = append(parts, "NOT SENSITIVE: the module may disclose this key's value")
	}

	return strings.Join(parts, "; ")
}

func slotPath(slot PKCS11Slot) string {
	return fmt.Sprintf("pkcs11/slot-%d", slot.SlotID)
}
