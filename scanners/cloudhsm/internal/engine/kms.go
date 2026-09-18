package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/cbom"
)

// KMSEngine inventories AWS KMS keys (R7).
//
// **Metadata only.** The three calls it makes -- ListKeys, DescribeKey,
// ListAliases -- are the complete read-only surface needed to answer "what keys
// exist and what are they made of". None of them can return key material, which
// is the point: a KMS exists so that key material never leaves it, and a
// scanner that extracted one would defeat the control it is inventorying.
//
// Required IAM policy, and nothing more:
//
//	kms:ListKeys, kms:DescribeKey, kms:ListAliases
type KMSEngine struct {
	Credentials Credentials
	Client      *http.Client
	// Now is injected so request signing is deterministic in tests.
	Now func() time.Time
}

// NewKMSEngine returns an engine using environment credentials.
func NewKMSEngine() *KMSEngine {
	return &KMSEngine{
		Credentials: CredentialsFromEnvironment(),
		Client:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (e *KMSEngine) Name() string { return "aws-kms" }

func (e *KMSEngine) Detects() []string {
	return []string{"kms keys", "key specs", "key management ownership"}
}

func (e *KMSEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "aws-kms-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run.
//
// A missing credential is the single most likely reason a cloud inventory comes
// back thin, so it must surface as a named gap rather than as "no keys found" —
// which would tell the user they have nothing to migrate.
func (e *KMSEngine) Available(_ context.Context, target Target) error {
	if target.Provider != "" && !strings.EqualFold(target.Provider, "aws") {
		return fmt.Errorf("target provider is %q, not aws", target.Provider)
	}
	if !e.Credentials.IsComplete() {
		return fmt.Errorf("AWS credentials are not configured (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)")
	}
	if target.Region == "" {
		return fmt.Errorf("no AWS region configured for this target")
	}
	return nil
}

// endpointFor returns the KMS URL for a target.
func (e *KMSEngine) endpointFor(target Target) string {
	if target.Endpoint != "" {
		return target.Endpoint
	}
	return fmt.Sprintf("https://kms.%s.amazonaws.com/", target.Region)
}

type kmsListKeysResponse struct {
	Keys []struct {
		KeyID  string `json:"KeyId"`
		KeyArn string `json:"KeyArn"`
	} `json:"Keys"`
	NextMarker string `json:"NextMarker"`
	Truncated  bool   `json:"Truncated"`
}

type kmsKeyMetadata struct {
	KeyID        string   `json:"KeyId"`
	Arn          string   `json:"Arn"`
	Description  string   `json:"Description"`
	Enabled      bool     `json:"Enabled"`
	KeyState     string   `json:"KeyState"`
	KeyUsage     string   `json:"KeyUsage"`
	KeySpec      string   `json:"KeySpec"`
	Origin       string   `json:"Origin"`
	KeyManager   string   `json:"KeyManager"`
	CreationDate float64  `json:"CreationDate"`
	MultiRegion  bool     `json:"MultiRegion"`
	SigningAlgos []string `json:"SigningAlgorithms"`
	EncryptAlgos []string `json:"EncryptionAlgorithms"`
}

type kmsDescribeKeyResponse struct {
	KeyMetadata kmsKeyMetadata `json:"KeyMetadata"`
}

type kmsListAliasesResponse struct {
	Aliases []struct {
		AliasName   string `json:"AliasName"`
		TargetKeyID string `json:"TargetKeyId"`
	} `json:"Aliases"`
}

// Scan enumerates keys and describes each one.
func (e *KMSEngine) Scan(ctx context.Context, target Target) (Result, error) {
	var result Result

	aliases, err := e.listAliases(ctx, target)
	if err != nil {
		// Aliases are a convenience: without them keys are still inventoried,
		// just less legibly. Record the gap and continue.
		result.Gaps = append(result.Gaps, Gap{
			Kind:   "partial_metadata",
			Reason: "key aliases could not be listed; findings are named by key id",
			Count:  1,
		})
		aliases = map[string]string{}
	}

	keyIDs, err := e.listKeys(ctx, target)
	if err != nil {
		return Result{}, err
	}

	for _, keyID := range keyIDs {
		metadata, err := e.describeKey(ctx, target, keyID)
		if err != nil {
			// A key that cannot be described is a hole in the inventory and
			// must be visible: it is often the one with a restrictive policy,
			// which makes it more interesting, not less.
			result.Gaps = append(result.Gaps, Gap{
				Path:   keyID,
				Kind:   "permission_denied",
				Reason: "the key exists but could not be described",
				Count:  1,
			})
			continue
		}

		result.ObjectsInspected++
		result.Findings = append(result.Findings,
			kmsFinding(metadata, aliases[metadata.KeyID], target.Region))
	}

	return result, nil
}

func (e *KMSEngine) call(ctx context.Context, target Target, action string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	request := signedRequest{
		Service:     "kms",
		Region:      target.Region,
		Endpoint:    e.endpointFor(target),
		Target:      "TrentService." + action,
		Body:        body,
		Credentials: e.Credentials,
		Now:         e.Now,
	}

	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return request.do(ctx, client)
}

// listKeys pages through every key in the region.
func (e *KMSEngine) listKeys(ctx context.Context, target Target) ([]string, error) {
	var (
		ids    []string
		marker string
	)

	// Bounded rather than unbounded: an account with a pathological key count
	// must not hang a scan, and 100 pages of 1000 keys is far beyond any real
	// deployment.
	for page := 0; page < 100; page++ {
		payload := map[string]any{"Limit": 1000}
		if marker != "" {
			payload["Marker"] = marker
		}

		raw, err := e.call(ctx, target, "ListKeys", payload)
		if err != nil {
			return nil, err
		}

		var response kmsListKeysResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			return nil, fmt.Errorf("kms ListKeys response could not be parsed: %w", err)
		}

		for _, key := range response.Keys {
			ids = append(ids, key.KeyID)
		}

		if !response.Truncated || response.NextMarker == "" {
			break
		}
		marker = response.NextMarker
	}

	return ids, nil
}

func (e *KMSEngine) describeKey(ctx context.Context, target Target, keyID string) (kmsKeyMetadata, error) {
	raw, err := e.call(ctx, target, "DescribeKey", map[string]any{"KeyId": keyID})
	if err != nil {
		return kmsKeyMetadata{}, err
	}

	var response kmsDescribeKeyResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return kmsKeyMetadata{}, fmt.Errorf("kms DescribeKey response could not be parsed: %w", err)
	}
	return response.KeyMetadata, nil
}

// listAliases maps key ids to their friendliest alias.
func (e *KMSEngine) listAliases(ctx context.Context, target Target) (map[string]string, error) {
	raw, err := e.call(ctx, target, "ListAliases", map[string]any{"Limit": 1000})
	if err != nil {
		return nil, err
	}

	var response kmsListAliasesResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("kms ListAliases response could not be parsed: %w", err)
	}

	aliases := make(map[string]string, len(response.Aliases))
	for _, alias := range response.Aliases {
		if alias.TargetKeyID == "" {
			continue
		}
		// An AWS-managed alias (alias/aws/...) is less informative than a
		// customer one, so a customer alias always wins.
		existing, seen := aliases[alias.TargetKeyID]
		if !seen || (strings.HasPrefix(existing, "alias/aws/") &&
			!strings.HasPrefix(alias.AliasName, "alias/aws/")) {
			aliases[alias.TargetKeyID] = alias.AliasName
		}
	}
	return aliases, nil
}

// kmsFinding converts key metadata into a cloud-service artefact.
//
// The key spec is the load-bearing field: RSA_2048 and ECC_NIST_P256 are
// Shor-breakable, SYMMETRIC_DEFAULT is not. Preserving it verbatim is what lets
// the risk engine reach a verdict without re-querying AWS.
func kmsFinding(metadata kmsKeyMetadata, alias, region string) cbom.Finding {
	algorithm, keySize, curve := kmsKeySpec(metadata.KeySpec)

	name := alias
	if name == "" {
		name = metadata.KeyID
	}
	name = strings.TrimPrefix(name, "alias/")

	finding := cbom.Finding{
		AssetType:       cbom.AssetCloudService,
		Name:            name,
		Algorithm:       algorithm,
		Curve:           curve,
		ParameterSet:    metadata.KeySpec,
		DetectionMethod: cbom.DetectCloudAPI,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "aws:kms",
		Location: cbom.Location{
			// A resource identifier, not a filesystem path. The region scopes
			// it so two accounts' keys never collide in the inventory.
			Path:   "aws/kms/" + region + "/" + metadata.KeyID,
			Symbol: metadata.Arn,
		},
		Purposes: kmsPurposes(metadata.KeyUsage),
		Snippet:  describeKMSKey(metadata),
		// CycloneDX has no structural place for these, so they travel as
		// namespaced properties and are lifted back into CloudServiceDetail on
		// ingest. Without them a KMS key ingests with no provider, no region
		// and no ownership — and ownership is what decides whether migration is
		// a code change or a vendor negotiation.
		Extra: map[string]string{
			cbom.TrinetraCloudProviderProperty: "aws",
			cbom.TrinetraCloudServiceProperty:  "kms",
			cbom.TrinetraKeyManagementProperty: kmsManagement(metadata.KeyManager),
			cbom.TrinetraResourceProperty:      metadata.Arn,
			cbom.TrinetraRegionProperty:        region,
		},
	}

	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}

	return finding.Normalise()
}

// kmsKeySpec maps an AWS key spec to canonical algorithm, size and curve.
//
// An unrecognised spec yields an empty algorithm rather than a guess: a new AWS
// key type must not be silently classified as something it is not.
func kmsKeySpec(spec string) (algorithm string, keySize int, curve string) {
	switch spec {
	case "RSA_2048":
		return "rsa", 2048, ""
	case "RSA_3072":
		return "rsa", 3072, ""
	case "RSA_4096":
		return "rsa", 4096, ""
	case "ECC_NIST_P256":
		return "ecdsa", 256, "P-256"
	case "ECC_NIST_P384":
		return "ecdsa", 384, "P-384"
	case "ECC_NIST_P521":
		return "ecdsa", 521, "P-521"
	case "ECC_SECG_P256K1":
		return "ecdsa", 256, "secp256k1"
	case "SYMMETRIC_DEFAULT":
		// AWS documents this as AES-256-GCM.
		return "aes", 256, ""
	case "HMAC_224":
		return "hmac", 224, ""
	case "HMAC_256":
		return "hmac", 256, ""
	case "HMAC_384":
		return "hmac", 384, ""
	case "HMAC_512":
		return "hmac", 512, ""
	case "SM2":
		return "sm2", 256, "sm2p256v1"
	default:
		return "", 0, ""
	}
}

func kmsPurposes(usage string) []cbom.Purpose {
	switch usage {
	case "SIGN_VERIFY":
		return []cbom.Purpose{cbom.PurposeDigitalSignature, cbom.PurposeVerify}
	case "ENCRYPT_DECRYPT":
		return []cbom.Purpose{cbom.PurposeEncryption, cbom.PurposeDecryption}
	case "GENERATE_VERIFY_MAC":
		return []cbom.Purpose{cbom.PurposeAuthentication}
	case "KEY_AGREEMENT":
		return []cbom.Purpose{cbom.PurposeKeyAgreement}
	default:
		return nil
	}
}

// describeKMSKey builds the evidence note.
//
// KeyManager is recorded because it changes what migration means: a
// provider-managed key cannot be rotated to a PQC algorithm on the customer's
// schedule, so it is a vendor dependency rather than an engineering task.
func describeKMSKey(metadata kmsKeyMetadata) string {
	parts := []string{"aws kms key " + metadata.KeyID}

	if metadata.KeySpec != "" {
		parts = append(parts, "spec "+metadata.KeySpec)
	}
	if metadata.KeyUsage != "" {
		parts = append(parts, "usage "+metadata.KeyUsage)
	}
	parts = append(parts, "management "+kmsManagement(metadata.KeyManager))
	if metadata.Origin != "" {
		parts = append(parts, "origin "+kmsOrigin(metadata.Origin))
	}
	if metadata.KeyState != "" {
		parts = append(parts, "state "+strings.ToLower(metadata.KeyState))
	}
	if metadata.MultiRegion {
		parts = append(parts, "multi-region")
	}
	if metadata.Description != "" {
		parts = append(parts, "description "+truncate(metadata.Description, 120))
	}

	return strings.Join(parts, "; ")
}

// kmsManagement translates AWS's KeyManager into the canonical vocabulary.
func kmsManagement(manager string) string {
	switch strings.ToUpper(manager) {
	case "CUSTOMER":
		return "customer_managed"
	case "AWS":
		return "provider_managed"
	default:
		// Unknown rather than an assumed default: who controls a key decides
		// whether migrating it is a code change or a vendor negotiation.
		return "unknown"
	}
}

// kmsOrigin says where the key material came from. EXTERNAL and CLOUDHSM both
// mean the customer holds material AWS did not generate, which changes the
// migration path.
func kmsOrigin(origin string) string {
	switch strings.ToUpper(origin) {
	case "AWS_KMS":
		return "aws_generated"
	case "EXTERNAL":
		return "imported"
	case "AWS_CLOUDHSM":
		return "cloudhsm"
	case "EXTERNAL_KEY_STORE":
		return "external_key_store"
	default:
		return strings.ToLower(origin)
	}
}

func truncate(text string, max int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "…"
}
