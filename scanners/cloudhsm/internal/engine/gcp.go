package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/cbom"
)

// GCPEngine inventories Google Cloud KMS (11C.4b).
//
// **Metadata only**, as everywhere in this service. The calls it makes list
// key rings, crypto keys and their primary versions; none can return key
// material.
//
// Required role, and nothing more: **roles/cloudkms.viewer**. No permission
// that can encrypt, decrypt or export.
//
// Authentication is an **OAuth access token supplied by the operator**, not a
// credential Trinetra manages. GCP's token acquisition is a service-account or
// workload-identity flow that does not belong inside a scanner, and passing a
// short-lived token in means Trinetra never holds a long-lived GCP secret.
type GCPEngine struct {
	// Project is the GCP project id.
	Project string
	// AccessToken is a short-lived OAuth token.
	AccessToken string
	// Endpoint overrides the API base, for a private deployment or a test.
	Endpoint string
	Client   *http.Client
}

// NewGCPEngine reads configuration from the environment.
func NewGCPEngine() *GCPEngine {
	return &GCPEngine{
		Project:     os.Getenv("TRINETRA_GCP_PROJECT"),
		AccessToken: os.Getenv("TRINETRA_GCP_TOKEN"),
		Endpoint:    os.Getenv("TRINETRA_GCP_ENDPOINT"),
		Client:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (e *GCPEngine) Name() string { return "gcp-kms" }

func (e *GCPEngine) Detects() []string {
	return []string{"kms key rings", "crypto keys", "protection level (software vs hsm)"}
}

func (e *GCPEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "gcp-kms-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run, so a missing credential reads as
// a named gap rather than "you have no keys".
func (e *GCPEngine) Available(_ context.Context, target Target) error {
	if target.Provider != "" && !strings.EqualFold(target.Provider, "gcp") {
		return fmt.Errorf("target provider is %q, not gcp", target.Provider)
	}
	if strings.TrimSpace(e.Project) == "" {
		return fmt.Errorf("no GCP project configured (TRINETRA_GCP_PROJECT)")
	}
	if strings.TrimSpace(e.AccessToken) == "" {
		return fmt.Errorf("no GCP access token configured (TRINETRA_GCP_TOKEN)")
	}
	if target.Region == "" {
		return fmt.Errorf("no GCP location configured for this target")
	}
	return nil
}

func (e *GCPEngine) baseURL(target Target) string {
	if target.Endpoint != "" {
		return strings.TrimSuffix(target.Endpoint, "/")
	}
	if e.Endpoint != "" {
		return strings.TrimSuffix(e.Endpoint, "/")
	}
	return "https://cloudkms.googleapis.com"
}

type gcpKeyRingList struct {
	KeyRings []struct {
		Name string `json:"name"`
	} `json:"keyRings"`
	NextPageToken string `json:"nextPageToken"`
}

type gcpCryptoKeyList struct {
	CryptoKeys    []gcpCryptoKey `json:"cryptoKeys"`
	NextPageToken string         `json:"nextPageToken"`
}

type gcpCryptoKey struct {
	Name            string `json:"name"`
	Purpose         string `json:"purpose"`
	CreateTime      string `json:"createTime"`
	RotationPeriod  string `json:"rotationPeriod"`
	NextRotation    string `json:"nextRotationTime"`
	VersionTemplate struct {
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	} `json:"versionTemplate"`
	Primary struct {
		Name            string `json:"name"`
		State           string `json:"state"`
		Algorithm       string `json:"algorithm"`
		ProtectionLevel string `json:"protectionLevel"`
	} `json:"primary"`
}

// Scan enumerates key rings and the crypto keys in each.
func (e *GCPEngine) Scan(ctx context.Context, target Target) (Result, error) {
	var result Result
	base := e.baseURL(target)
	parent := fmt.Sprintf("projects/%s/locations/%s", e.Project, target.Region)

	raw, err := e.get(ctx, fmt.Sprintf("%s/v1/%s/keyRings", base, parent))
	if err != nil {
		return Result{}, err
	}

	var rings gcpKeyRingList
	if err := json.Unmarshal(raw, &rings); err != nil {
		return Result{}, fmt.Errorf("gcp key ring listing could not be parsed: %w", err)
	}

	for _, ring := range rings.KeyRings {
		keysRaw, err := e.get(ctx, fmt.Sprintf("%s/v1/%s/cryptoKeys", base, ring.Name))
		if err != nil {
			// A ring that cannot be read is a hole in the inventory.
			result.Gaps = append(result.Gaps, Gap{
				Path:   gcpResourcePath(ring.Name),
				Kind:   "permission_denied",
				Reason: "the key ring exists but its keys could not be listed",
				Count:  1,
			})
			continue
		}

		var keys gcpCryptoKeyList
		if err := json.Unmarshal(keysRaw, &keys); err != nil {
			result.Gaps = append(result.Gaps, Gap{
				Path:   gcpResourcePath(ring.Name),
				Kind:   "unparseable",
				Reason: "the key listing could not be parsed",
				Count:  1,
			})
			continue
		}

		for _, key := range keys.CryptoKeys {
			result.ObjectsInspected++
			result.Findings = append(result.Findings, gcpKeyFinding(key, target.Region))
		}

		if keys.NextPageToken != "" {
			result.Gaps = append(result.Gaps, Gap{
				Path: gcpResourcePath(ring.Name),
				Kind: "partial_metadata",
				Reason: "the key ring returned more keys than one page; " +
					"only the first page was inventoried",
				Count: 1,
			})
		}
	}

	return result, nil
}

func (e *GCPEngine) get(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+e.AccessToken)
	request.Header.Set("Accept", "application/json")

	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	response, err := client.Do(request)
	if err != nil {
		// The URL names the customer's project; the error must not echo it.
		return nil, fmt.Errorf("gcp kms request failed")
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp kms returned status %d", response.StatusCode)
	}
	return body, nil
}

// gcpKeyFinding converts a crypto key into a cloud-service artefact.
func gcpKeyFinding(key gcpCryptoKey, location string) cbom.Finding {
	// The primary version's algorithm is what is actually in use; the template
	// is only what new versions will get.
	algorithmSpec := key.Primary.Algorithm
	if algorithmSpec == "" {
		algorithmSpec = key.VersionTemplate.Algorithm
	}

	protection := key.Primary.ProtectionLevel
	if protection == "" {
		protection = key.VersionTemplate.ProtectionLevel
	}

	algorithm, keySize, curve := gcpAlgorithm(algorithmSpec)

	finding := cbom.Finding{
		AssetType:       cbom.AssetCloudService,
		Name:            gcpKeyName(key.Name),
		Algorithm:       algorithm,
		Curve:           curve,
		ParameterSet:    algorithmSpec,
		DetectionMethod: cbom.DetectCloudAPI,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "gcp:kms",
		Location: cbom.Location{
			Path:   gcpResourcePath(key.Name),
			Symbol: key.Name,
		},
		Purposes: gcpPurposes(key.Purpose),
		Snippet:  describeGCPKey(key, algorithmSpec, protection),
		Extra: map[string]string{
			cbom.TrinetraCloudProviderProperty: "gcp",
			cbom.TrinetraCloudServiceProperty:  gcpServiceKind(protection),
			cbom.TrinetraKeyManagementProperty: "customer_managed",
			cbom.TrinetraResourceProperty:      key.Name,
			cbom.TrinetraRegionProperty:        location,
		},
	}

	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}
	return finding.Normalise()
}

// gcpAlgorithm maps a CryptoKeyVersionAlgorithm to canonical values.
//
// GCP's names encode algorithm, size and digest in one string, e.g.
// RSA_SIGN_PKCS1_2048_SHA256 or EC_SIGN_P256_SHA256. An unrecognised name
// yields an empty algorithm rather than a guess: a new GCP algorithm must not
// be silently classified as something it is not.
func gcpAlgorithm(spec string) (algorithm string, keySize int, curve string) {
	upper := strings.ToUpper(strings.TrimSpace(spec))

	switch {
	case upper == "GOOGLE_SYMMETRIC_ENCRYPTION":
		// Documented as AES-256-GCM.
		return "aes", 256, ""

	case strings.HasPrefix(upper, "RSA_"):
		for _, size := range []int{2048, 3072, 4096} {
			if strings.Contains(upper, fmt.Sprintf("_%d_", size)) ||
				strings.HasSuffix(upper, fmt.Sprintf("_%d", size)) {
				return "rsa", size, ""
			}
		}
		// An RSA key whose size is not in the name: report the algorithm and
		// leave the size unobserved rather than assuming one.
		return "rsa", 0, ""

	case strings.HasPrefix(upper, "EC_"):
		switch {
		case strings.Contains(upper, "P256K"):
			return "ecdsa", 256, "secp256k1"
		case strings.Contains(upper, "P256"):
			return "ecdsa", 256, "P-256"
		case strings.Contains(upper, "P384"):
			return "ecdsa", 384, "P-384"
		}
		return "ecdsa", 0, ""

	case strings.HasPrefix(upper, "HMAC_"):
		for _, size := range []int{256, 384, 512, 224} {
			if strings.Contains(upper, fmt.Sprintf("SHA%d", size)) {
				return "hmac", size, ""
			}
		}
		return "hmac", 0, ""

	case strings.HasPrefix(upper, "PQ_") || strings.Contains(upper, "ML_DSA") ||
		strings.Contains(upper, "SLH_DSA"):
		// GCP has begun shipping PQC algorithms. Recognise them as
		// quantum-safe families rather than falling through to "unknown".
		switch {
		case strings.Contains(upper, "ML_DSA"):
			return "ml-dsa", 0, ""
		case strings.Contains(upper, "SLH_DSA"):
			return "slh-dsa", 0, ""
		}
		return "", 0, ""

	default:
		return "", 0, ""
	}
}

// gcpServiceKind distinguishes a software key from one held in an HSM.
//
// This is load-bearing: an HSM-protected key cannot be migrated the same way a
// software key can.
func gcpServiceKind(protection string) string {
	switch strings.ToUpper(strings.TrimSpace(protection)) {
	case "HSM":
		return "cloud_hsm"
	case "EXTERNAL", "EXTERNAL_VPC":
		return "vault"
	default:
		return "kms"
	}
}

func gcpPurposes(purpose string) []cbom.Purpose {
	switch strings.ToUpper(strings.TrimSpace(purpose)) {
	case "ENCRYPT_DECRYPT":
		return []cbom.Purpose{cbom.PurposeEncryption, cbom.PurposeDecryption}
	case "ASYMMETRIC_SIGN":
		return []cbom.Purpose{cbom.PurposeDigitalSignature, cbom.PurposeVerify}
	case "ASYMMETRIC_DECRYPT":
		return []cbom.Purpose{cbom.PurposeDecryption}
	case "MAC":
		return []cbom.Purpose{cbom.PurposeAuthentication}
	default:
		return nil
	}
}

// gcpKeyName extracts the final segment of a resource name.
func gcpKeyName(name string) string {
	trimmed := strings.Trim(strings.TrimSpace(name), "/")
	if trimmed == "" {
		return "gcp key"
	}
	segments := strings.Split(trimmed, "/")
	return segments[len(segments)-1]
}

// gcpResourcePath builds the inventory identifier from the resource name.
//
// GCP resource names are already hierarchical and unique, so the path is the
// name with the redundant field labels stripped.
func gcpResourcePath(name string) string {
	trimmed := strings.Trim(strings.TrimSpace(name), "/")
	if trimmed == "" {
		return "gcp/kms/unknown"
	}

	segments := strings.Split(trimmed, "/")
	var values []string
	for i := 1; i < len(segments); i += 2 {
		values = append(values, segments[i])
	}
	if len(values) == 0 {
		return "gcp/kms/" + trimmed
	}
	return "gcp/kms/" + strings.Join(values, "/")
}

func describeGCPKey(key gcpCryptoKey, algorithmSpec, protection string) string {
	parts := []string{"gcp kms crypto key"}

	if algorithmSpec != "" {
		parts = append(parts, "algorithm "+algorithmSpec)
	}
	if key.Purpose != "" {
		parts = append(parts, "purpose "+key.Purpose)
	}

	switch strings.ToUpper(strings.TrimSpace(protection)) {
	case "HSM":
		parts = append(parts, "protection HSM — material is held in hardware")
	case "SOFTWARE":
		parts = append(parts, "protection SOFTWARE")
	case "":
		parts = append(parts, "protection level not recorded")
	default:
		parts = append(parts, "protection "+protection)
	}

	if key.Primary.State != "" {
		parts = append(parts, "state "+strings.ToLower(key.Primary.State))
	}
	if key.RotationPeriod != "" {
		parts = append(parts, "rotation every "+key.RotationPeriod)
	} else {
		// No rotation policy is itself a finding, and must not read as "rotates".
		parts = append(parts, "no rotation period configured")
	}

	return strings.Join(parts, "; ")
}
