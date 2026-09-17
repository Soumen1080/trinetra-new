// Package cbom turns scanner output into a CycloneDX 1.6 CBOM document.
//
// Finding is the one shape every scanner reduces its output to. Whatever
// produced it — Semgrep, CBOMkit, Syft, a PKCS#11 enumeration — a finding
// arrives here and nothing downstream can tell the difference.
//
// Values in this package are Trinetra's canonical snake_case vocabulary (P6).
// Translation to the CycloneDX wire format happens in vocab.go and nowhere else.
package cbom

// AssetType mirrors app/models/enums.py AssetType.
type AssetType string

const (
	AssetAlgorithm       AssetType = "algorithm"
	AssetKey             AssetType = "key"
	AssetCertificate     AssetType = "certificate"
	AssetProtocol        AssetType = "protocol"
	AssetLibrary         AssetType = "library"
	AssetHardwareModule  AssetType = "hardware_module"
	AssetCloudService    AssetType = "cloud_service"
	AssetRelatedMaterial AssetType = "related_material"
)

// Primitive mirrors app/models/enums.py Primitive.
type Primitive string

const (
	PrimitiveBlockCipher  Primitive = "block_cipher"
	PrimitiveStreamCipher Primitive = "stream_cipher"
	PrimitiveHash         Primitive = "hash"
	PrimitiveMAC          Primitive = "mac"
	PrimitiveAEAD         Primitive = "aead"
	PrimitiveSignature    Primitive = "signature"
	PrimitivePKE          Primitive = "pke"
	PrimitiveKEM          Primitive = "kem"
	PrimitiveKeyAgreement Primitive = "key_agreement"
	PrimitiveKDF          Primitive = "kdf"
	PrimitiveDRBG         Primitive = "drbg"
	PrimitiveOther        Primitive = "other"
)

// Purpose mirrors app/models/enums.py Purpose.
type Purpose string

const (
	PurposeEncryption       Purpose = "encryption"
	PurposeDecryption       Purpose = "decryption"
	PurposeDigitalSignature Purpose = "digital_signature"
	PurposeVerify           Purpose = "verify"
	PurposeKeyEncapsulation Purpose = "key_encapsulation"
	PurposeKeyAgreement     Purpose = "key_agreement"
	PurposeKeyDerivation    Purpose = "key_derivation"
	PurposeHashing          Purpose = "hashing"
	PurposeAuthentication   Purpose = "authentication"
	PurposeIntegrity        Purpose = "integrity"
	PurposeRandomGeneration Purpose = "random_generation"
	PurposeOther            Purpose = "other"
)

// Confidence mirrors app/models/enums.py Confidence. Three levels only: a
// numeric confidence invites arithmetic the evidence does not support.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// DetectionMethod mirrors app/models/enums.py DetectionMethod.
type DetectionMethod string

const (
	DetectSemgrepPattern DetectionMethod = "semgrep_pattern"
	DetectSemgrepTaint   DetectionMethod = "semgrep_taint"
	DetectTreeSitterAST  DetectionMethod = "tree_sitter_ast"
	DetectCBOMkit        DetectionMethod = "cbomkit_engine"
	DetectDependency     DetectionMethod = "dependency_manifest"
	DetectSBOMIngest     DetectionMethod = "sbom_ingest"
	DetectCertificate    DetectionMethod = "certificate_parse"
	DetectConfigParse    DetectionMethod = "config_parse"
	DetectOther          DetectionMethod = "other"
)

// Location is where in the target a finding was observed. Path is always
// relative to the scan target root — an absolute path would leak the scanner's
// filesystem layout into evidence that reaches the UI.
type Location struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	EndLine int    `json:"end_line,omitempty"`
	Symbol  string `json:"symbol,omitempty"`
}

// Finding is one cryptographic asset, as observed by one engine.
//
// Every field a scanner might fail to observe is a pointer or empty-able, and
// absent means *not observed* (P3). Nothing here is given a plausible default:
// AES.new(key, MODE_GCM) genuinely does not state a key size, and the finding
// must say so rather than guess 128 or 256.
type Finding struct {
	AssetType AssetType `json:"asset_type"`
	Name      string    `json:"name"`

	// Algorithm is the normalised algorithm name. It MUST stay empty for
	// library findings: a package name is dependency evidence, not an
	// algorithm, and populating it would let the risk engine manufacture an
	// attack model out of "OpenSSL is installed".
	Algorithm string `json:"algorithm,omitempty"`

	OID       string    `json:"oid,omitempty"`
	Primitive Primitive `json:"primitive,omitempty"`
	Purposes  []Purpose `json:"purposes,omitempty"`

	// The R19 fields. A nil KeySizeBits means the call site did not state one.
	KeySizeBits  *int   `json:"key_size_bits,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Padding      string `json:"padding,omitempty"`
	Curve        string `json:"curve,omitempty"`
	ParameterSet string `json:"parameter_set,omitempty"`

	Location        Location        `json:"location"`
	DetectionMethod DetectionMethod `json:"detection_method"`
	Confidence      Confidence      `json:"confidence"`
	RuleID          string          `json:"rule_id,omitempty"`
	Snippet         string          `json:"snippet,omitempty"`

	// DataCategory carries taint evidence: what the code at this site was
	// observed to protect. It is evidence of what the code does, never a
	// business decision, so it enters the context chain below a user's
	// confirmation and never above it.
	DataCategory string `json:"data_category,omitempty"`

	// Redacted marks a finding whose snippet was withheld because it contained
	// key material. Trinetra stores no secrets.
	Redacted bool `json:"redacted,omitempty"`
}

// IsLibrary reports whether this finding is dependency evidence rather than an
// observed algorithm use.
func (f Finding) IsLibrary() bool { return f.AssetType == AssetLibrary }

// Normalise applies the invariants that must hold however a finding was
// produced, so an engine adapter cannot violate them by omission.
func (f Finding) Normalise() Finding {
	if f.AssetType == "" {
		f.AssetType = AssetAlgorithm
	}
	if f.Confidence == "" {
		f.Confidence = ConfidenceLow
	}
	// The rule that keeps the risk engine honest, applied at the boundary as
	// well as in the Python schema and the database CHECK constraint.
	if f.IsLibrary() {
		f.Algorithm = ""
		f.KeySizeBits = nil
		f.Mode = ""
		f.Padding = ""
		f.Curve = ""
	}
	return f
}

// KeySize returns the observed key size and whether one was observed at all.
// Callers must branch on ok rather than treating 0 as a size.
func (f Finding) KeySize() (int, bool) {
	if f.KeySizeBits == nil {
		return 0, false
	}
	return *f.KeySizeBits, true
}

// IntPtr is a helper for engines that have a key size to report.
func IntPtr(v int) *int { return &v }
