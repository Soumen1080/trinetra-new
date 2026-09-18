package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// A realistic HSM export: one PQC-capable module and one that is not, which is
// the distinction that decides whether migration is firmware or hardware.
const hsmExport = `{
  "collector": "pkcs11-tool 0.23.0 on hsm-01.internal",
  "collected_at": "2026-03-14T10:30:00Z",
  "slots": [
    {
      "slot_id": 0,
      "description": "Luna PCIe HSM slot 0",
      "manufacturer_id": "Thales",
      "token_label": "payments-hsm",
      "token_model": "Luna K7",
      "token_serial": "1234567890",
      "firmware_version": "7.8.4",
      "fips_certificate": "4708",
      "fips_level": "3",
      "supported_mechanisms": ["CKM_RSA_PKCS", "CKM_ECDSA", "CKM_AES_GCM", "CKM_SHA256"],
      "objects": [
        {"label": "payments-signing", "class": "CKO_PRIVATE_KEY", "key_type": "CKK_RSA",
         "modulus_bits": 2048, "extractable": false, "sensitive": true},
        {"label": "token-signing", "class": "CKO_EC_PARAMS", "key_type": "CKK_EC",
         "ec_params": "prime256v1", "extractable": false, "sensitive": true},
        {"label": "payments-signing-pub", "class": "CKO_PUBLIC_KEY", "key_type": "CKK_RSA",
         "modulus_bits": 2048},
        {"label": "legacy-wrapping", "class": "CKO_SECRET_KEY", "key_type": "CKK_AES",
         "modulus_bits": 256, "extractable": true, "sensitive": false}
      ]
    },
    {
      "slot_id": 1,
      "manufacturer_id": "Utimaco",
      "token_label": "pqc-ready-hsm",
      "token_model": "CryptoServer CP5",
      "firmware_version": "5.4.0",
      "supported_mechanisms": ["CKM_RSA_PKCS", "CKM_ML_DSA", "CKM_ML_KEM"],
      "objects": []
    },
    {
      "slot_id": 2,
      "token_label": "uninventoried-hsm",
      "objects": []
    }
  ]
}`

func writeExport(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hsm-export.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write export: %v", err)
	}
	return path
}

func scanExport(t *testing.T, content string) Result {
	t.Helper()
	engine := &PKCS11Engine{ExportPath: writeExport(t, content)}

	if err := engine.Available(context.Background(), Target{}); err != nil {
		t.Fatalf("engine unavailable: %v", err)
	}
	result, err := engine.Scan(context.Background(), Target{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

func TestPKCS11EmitsHardwareModules(t *testing.T) {
	result := scanExport(t, hsmExport)

	var modules []cbom.Finding
	for _, finding := range result.Findings {
		if finding.AssetType == cbom.AssetHardwareModule {
			modules = append(modules, finding)
		}
	}

	if len(modules) != 3 {
		t.Fatalf("expected a module per slot, got %d", len(modules))
	}
	names := map[string]bool{}
	for _, module := range modules {
		names[module.Name] = true
	}
	if !names["payments-hsm"] || !names["pqc-ready-hsm"] {
		t.Errorf("module names = %v", names)
	}
}

func TestPKCS11RecordsVendorFirmwareAndFIPS(t *testing.T) {
	for _, finding := range scanExport(t, hsmExport).Findings {
		if finding.Name != "payments-hsm" {
			continue
		}
		for _, want := range []string{
			"vendor Thales", "model Luna K7", "firmware 7.8.4",
			"FIPS certificate 4708", "level 3",
		} {
			if !strings.Contains(finding.Snippet, want) {
				t.Errorf("evidence omits %q: %s", want, finding.Snippet)
			}
		}
		return
	}
	t.Fatal("payments-hsm module not produced")
}

// The question this engine exists to answer: can the HSM do PQC at all? An HSM
// that cannot is a hardware purchase, not a code change.
func TestPKCS11ReportsPQCCapability(t *testing.T) {
	findings := scanExport(t, hsmExport).Findings

	byName := map[string]cbom.Finding{}
	for _, finding := range findings {
		byName[finding.Name] = finding
	}

	pqc := byName["pqc-ready-hsm"]
	if !strings.Contains(pqc.Snippet, "advertises PQC mechanisms") {
		t.Errorf("a PQC-capable HSM was not recognised: %s", pqc.Snippet)
	}
	if !strings.Contains(pqc.Snippet, "CKM_ML_DSA") {
		t.Errorf("the PQC mechanism is not named: %s", pqc.Snippet)
	}

	legacy := byName["payments-hsm"]
	if !strings.Contains(legacy.Snippet, "no PQC mechanisms") {
		t.Errorf("a non-PQC HSM was not flagged: %s", legacy.Snippet)
	}
	if !strings.Contains(legacy.Snippet, "firmware or hardware change") {
		t.Errorf("the migration consequence is not stated: %s", legacy.Snippet)
	}
}

// "Not collected" is not "not supported" (P3).
func TestPKCS11UncollectedMechanismsBecomeAGap(t *testing.T) {
	result := scanExport(t, hsmExport)

	var found bool
	for _, gap := range result.Gaps {
		if strings.Contains(gap.Reason, "PQC capability could not be determined") {
			found = true
		}
	}
	if !found {
		t.Errorf("a slot with no mechanism list produced no gap: %+v", result.Gaps)
	}

	for _, finding := range result.Findings {
		if finding.Name == "uninventoried-hsm" {
			if !strings.Contains(finding.Snippet, "not recorded") {
				t.Errorf("uncollected mechanisms must say 'not recorded': %s", finding.Snippet)
			}
		}
	}
}

// FIPS certification absent means not recorded, never "not certified".
func TestPKCS11AbsentFIPSSaysNotRecorded(t *testing.T) {
	for _, finding := range scanExport(t, hsmExport).Findings {
		if finding.Name == "pqc-ready-hsm" {
			if !strings.Contains(finding.Snippet, "FIPS certification not recorded") {
				t.Errorf("absent FIPS data should say 'not recorded': %s", finding.Snippet)
			}
			return
		}
	}
	t.Fatal("pqc-ready-hsm not produced")
}

func TestPKCS11EmitsKeyObjects(t *testing.T) {
	var keys []cbom.Finding
	for _, finding := range scanExport(t, hsmExport).Findings {
		if finding.AssetType == cbom.AssetKey {
			keys = append(keys, finding)
		}
	}

	// Three private/secret keys; the public key is skipped.
	if len(keys) != 3 {
		t.Fatalf("expected 3 key artefacts, got %d", len(keys))
	}
	for _, key := range keys {
		if strings.Contains(key.Name, "-pub") {
			t.Errorf("a public key was inventoried as a key artefact: %q", key.Name)
		}
	}
}

func TestPKCS11ResolvesKeyParameters(t *testing.T) {
	byName := map[string]cbom.Finding{}
	for _, finding := range scanExport(t, hsmExport).Findings {
		byName[finding.Name] = finding
	}

	rsa, ok := byName["payments-signing (RSA)"]
	if !ok {
		t.Fatalf("RSA key not produced; got %v", keysOf(byName))
	}
	if size, has := rsa.KeySize(); !has || size != 2048 {
		t.Errorf("RSA size = %d (%v), want 2048", size, has)
	}

	ec, ok := byName["token-signing (ECDSA)"]
	if !ok {
		t.Fatalf("EC key not produced; got %v", keysOf(byName))
	}
	if ec.Curve != "P-256" {
		t.Errorf("curve = %q, want P-256", ec.Curve)
	}
	if size, has := ec.KeySize(); !has || size != 256 {
		t.Errorf("EC size = %d (%v), want 256", size, has)
	}
}

// An HSM exists so that key material cannot be extracted. A scanner that read
// one would defeat the control it is inventorying.
func TestPKCS11KeysAreRedactedAndCarryNoMaterial(t *testing.T) {
	result := scanExport(t, hsmExport)

	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetKey {
			continue
		}
		if !finding.Redacted {
			t.Errorf("HSM key %q is not marked redacted", finding.Name)
		}
		if !strings.Contains(finding.Snippet, "contents never read") {
			t.Errorf("evidence does not state material was never read: %s", finding.Snippet)
		}
	}

	serialised, _ := json.Marshal(result.Findings)
	for _, forbidden := range []string{"CKA_VALUE", "PRIVATE KEY-----", "BEGIN RSA"} {
		if strings.Contains(string(serialised), forbidden) {
			t.Errorf("findings contain %q", forbidden)
		}
	}
}

// An extractable key in an HSM defeats the module's whole purpose, so it is a
// finding in its own right.
func TestPKCS11FlagsExtractableKeys(t *testing.T) {
	for _, finding := range scanExport(t, hsmExport).Findings {
		if !strings.Contains(finding.Name, "legacy-wrapping") {
			continue
		}
		if !strings.Contains(finding.Snippet, "EXTRACTABLE") {
			t.Errorf("an extractable HSM key was not flagged: %s", finding.Snippet)
		}
		if !strings.Contains(finding.Snippet, "NOT SENSITIVE") {
			t.Errorf("a non-sensitive HSM key was not flagged: %s", finding.Snippet)
		}
		return
	}
	t.Fatal("legacy-wrapping key not produced")
}

// An export that cannot say what produced it cannot be audited.
func TestPKCS11RejectsExportWithoutCollector(t *testing.T) {
	path := writeExport(t, `{"slots": []}`)
	engine := &PKCS11Engine{ExportPath: path}

	_, err := engine.Scan(context.Background(), Target{})
	if err == nil {
		t.Fatal("an export with no collector was accepted")
	}
	if !strings.Contains(err.Error(), "collected it") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPKCS11RejectsMalformedExport(t *testing.T) {
	engine := &PKCS11Engine{ExportPath: writeExport(t, "{not json")}
	if _, err := engine.Scan(context.Background(), Target{}); err == nil {
		t.Error("a malformed export was accepted")
	}
}

func TestPKCS11UnavailableWithoutExport(t *testing.T) {
	engine := &PKCS11Engine{}
	err := engine.Available(context.Background(), Target{})
	if err == nil {
		t.Fatal("expected the engine to refuse to run with no export")
	}
	if !strings.Contains(err.Error(), "TRINETRA_PKCS11_EXPORT") {
		t.Errorf("the reason is not actionable: %v", err)
	}
}

func TestPKCS11KeyTypeMapping(t *testing.T) {
	cases := []struct {
		object    PKCS11Object
		algorithm string
		size      int
	}{
		{PKCS11Object{KeyType: "CKK_RSA", ModulusBits: 4096}, "rsa", 4096},
		{PKCS11Object{KeyType: "CKK_AES", ModulusBits: 256}, "aes", 256},
		{PKCS11Object{KeyType: "CKK_DES3"}, "3des", 168},
		{PKCS11Object{KeyType: "CKK_EC_EDWARDS"}, "ed25519", 255},
		// A vendor-specific type must not be mislabelled.
		{PKCS11Object{KeyType: "CKK_VENDOR_SOMETHING"}, "", 0},
		{PKCS11Object{}, "", 0},
	}

	for _, tc := range cases {
		algorithm, size, _ := pkcs11KeyType(tc.object)
		if algorithm != tc.algorithm || size != tc.size {
			t.Errorf("pkcs11KeyType(%q) = (%q,%d), want (%q,%d)",
				tc.object.KeyType, algorithm, size, tc.algorithm, tc.size)
		}
	}
}

func TestNormaliseECParams(t *testing.T) {
	cases := map[string]string{
		"prime256v1": "P-256",
		"secp256r1":  "P-256",
		"nistp384":   "P-384",
		"secp521r1":  "P-521",
		"secp256k1":  "secp256k1",
		"":           "",
	}
	for input, want := range cases {
		if got := normaliseECParams(input); got != want {
			t.Errorf("normaliseECParams(%q) = %q, want %q", input, got, want)
		}
	}
}

// An export with no slots is a valid result: an estate with no HSMs is a real
// answer, not an error.
func TestPKCS11EmptyExportIsValid(t *testing.T) {
	result := scanExport(t, `{"collector": "pkcs11-tool", "slots": []}`)
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

func keysOf(m map[string]cbom.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
