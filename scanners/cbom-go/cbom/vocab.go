package cbom

// Canonical -> CycloneDX translation (P6).
//
// This file is the exact inverse of backend/app/schemas/vocab.py. The two
// tables must stay inverses of each other, and a shared fixture
// (contracts/vocab-fixture.json) drives round-trip tests on both sides so that
// editing one without the other fails the build rather than silently corrupting
// one direction of translation.

// TrinetraAssetTypeProperty disambiguates canonical types that share one
// CycloneDX assetType spelling.
const TrinetraAssetTypeProperty = "trinetra:asset-type"

// TrinetraDataCategoryProperty carries taint evidence through the wire format.
const TrinetraDataCategoryProperty = "trinetra:data-category"

// TrinetraKeySizeProperty carries an observed key size. CycloneDX's
// parameterSetIdentifier is a string and overloaded; this stays unambiguous.
const TrinetraKeySizeProperty = "trinetra:key-size-bits"

// Cloud-service attributes. CycloneDX has no structural place for these, so a
// managed key's provider, region and ownership travel as namespaced properties.
// KeyManagement in particular is load-bearing: who controls a key decides
// whether migrating it is a code change or a vendor negotiation.
const (
	TrinetraCloudProviderProperty = "trinetra:cloud-provider"
	TrinetraCloudServiceProperty  = "trinetra:cloud-service"
	TrinetraKeyManagementProperty = "trinetra:key-management"
	TrinetraResourceProperty      = "trinetra:resource-id"
	TrinetraRegionProperty        = "trinetra:region"
)

var assetTypeToWire = map[AssetType]string{
	AssetAlgorithm:       "algorithm",
	AssetKey:             "related-crypto-material",
	AssetCertificate:     "certificate",
	AssetProtocol:        "protocol",
	AssetLibrary:         "library",
	AssetHardwareModule:  "related-crypto-material",
	AssetCloudService:    "related-crypto-material",
	AssetRelatedMaterial: "related-crypto-material",
}

// ambiguousAssetTypes share a wire spelling and therefore need the
// trinetra:asset-type property to survive a round trip.
var ambiguousAssetTypes = map[AssetType]bool{
	AssetKey:            true,
	AssetHardwareModule: true,
	AssetCloudService:   true,
}

var primitiveToWire = map[Primitive]string{
	PrimitiveBlockCipher:  "block-cipher",
	PrimitiveStreamCipher: "stream-cipher",
	PrimitiveHash:         "hash",
	PrimitiveMAC:          "mac",
	PrimitiveAEAD:         "ae",
	PrimitiveSignature:    "signature",
	PrimitivePKE:          "pke",
	PrimitiveKEM:          "kem",
	PrimitiveKeyAgreement: "key-agree",
	PrimitiveKDF:          "kdf",
	PrimitiveDRBG:         "drbg",
	PrimitiveOther:        "other",
}

var purposeToWire = map[Purpose]string{
	PurposeEncryption:       "encrypt",
	PurposeDecryption:       "decrypt",
	PurposeDigitalSignature: "sign",
	PurposeVerify:           "verify",
	PurposeKeyEncapsulation: "encapsulate",
	PurposeKeyAgreement:     "keygen",
	PurposeKeyDerivation:    "derive",
	PurposeHashing:          "digest",
	PurposeAuthentication:   "tag",
	PurposeIntegrity:        "verify-integrity",
	PurposeRandomGeneration: "generate",
	PurposeOther:            "other",
}

// AssetTypeToWire returns the CycloneDX assetType for a canonical type.
func AssetTypeToWire(t AssetType) string {
	if wire, ok := assetTypeToWire[t]; ok {
		return wire
	}
	return "algorithm"
}

// AssetTypeNeedsHint reports whether exporting t requires the disambiguating
// trinetra:asset-type property.
func AssetTypeNeedsHint(t AssetType) bool { return ambiguousAssetTypes[t] }

// PrimitiveToWire returns the CycloneDX primitive for a canonical primitive.
func PrimitiveToWire(p Primitive) string {
	if wire, ok := primitiveToWire[p]; ok {
		return wire
	}
	return "other"
}

// PurposeToWire returns the CycloneDX cryptoFunction for a canonical purpose.
func PurposeToWire(p Purpose) string {
	if wire, ok := purposeToWire[p]; ok {
		return wire
	}
	return "other"
}

// VocabTables exposes the mappings so the round-trip fixture test can assert
// they match the Python side member for member.
func VocabTables() (map[string]string, map[string]string, map[string]string) {
	assets := make(map[string]string, len(assetTypeToWire))
	for k, v := range assetTypeToWire {
		assets[string(k)] = v
	}
	primitives := make(map[string]string, len(primitiveToWire))
	for k, v := range primitiveToWire {
		primitives[string(k)] = v
	}
	purposes := make(map[string]string, len(purposeToWire))
	for k, v := range purposeToWire {
		purposes[string(k)] = v
	}
	return assets, primitives, purposes
}
