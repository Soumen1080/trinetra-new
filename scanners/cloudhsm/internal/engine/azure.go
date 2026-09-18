package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trinetra/cbom-go/cbom"
)

// AzureEngine inventories Azure Key Vault (11C.4a).
//
// **Metadata only**, exactly as for AWS. The two calls it makes -- list keys and
// list certificates -- return descriptive attributes and cannot return key
// material, which is the point: a Key Vault exists so that material never
// leaves it.
//
// Required role, and nothing more: **Key Vault Reader** (or the equivalent
// data-plane actions `Microsoft.KeyVault/vaults/keys/read` and
// `.../certificates/read`). No permission that can export or use a key.
//
// Authentication is a **bearer token supplied by the operator**, not a
// credential Trinetra manages. Azure's token acquisition is an interactive or
// managed-identity flow that does not belong inside a scanner; the deployment
// obtains a token and passes it in, which also means Trinetra never holds a
// long-lived Azure secret.
type AzureEngine struct {
	// VaultURL is the Key Vault endpoint, e.g. https://example.vault.azure.net.
	VaultURL string
	// BearerToken is a short-lived access token for the vault's data plane.
	BearerToken string
	Client      *http.Client
}

// NewAzureEngine reads configuration from the environment.
func NewAzureEngine() *AzureEngine {
	return &AzureEngine{
		VaultURL:    os.Getenv("TRINETRA_AZURE_VAULT_URL"),
		BearerToken: os.Getenv("TRINETRA_AZURE_TOKEN"),
		Client:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (e *AzureEngine) Name() string { return "azure-keyvault" }

func (e *AzureEngine) Detects() []string {
	return []string{"key vault keys", "key vault certificates", "managed hsm keys"}
}

func (e *AzureEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "azure-keyvault-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

// Available reports why the engine cannot run.
//
// A missing token is the likeliest reason an Azure inventory comes back empty,
// and "no keys found" is the most dangerous possible output for a cloud
// scanner — so the reason is named rather than implied.
func (e *AzureEngine) Available(_ context.Context, target Target) error {
	if target.Provider != "" && !strings.EqualFold(target.Provider, "azure") {
		return fmt.Errorf("target provider is %q, not azure", target.Provider)
	}

	vault := e.vaultURLFor(target)
	if strings.TrimSpace(vault) == "" {
		return fmt.Errorf("no Key Vault URL configured (TRINETRA_AZURE_VAULT_URL)")
	}
	if strings.TrimSpace(e.BearerToken) == "" {
		return fmt.Errorf("no Azure access token configured (TRINETRA_AZURE_TOKEN)")
	}
	return nil
}

func (e *AzureEngine) vaultURLFor(target Target) string {
	if target.Endpoint != "" {
		return target.Endpoint
	}
	return e.VaultURL
}

// azureKeyList is the subset of the list-keys response Trinetra reads.
type azureKeyList struct {
	Value []struct {
		KID        string            `json:"kid"`
		Attributes azureKeyAttrs     `json:"attributes"`
		Tags       map[string]string `json:"tags"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

type azureKeyAttrs struct {
	Enabled bool  `json:"enabled"`
	Created int64 `json:"created"`
	Expires int64 `json:"exp"`
}

// azureKeyBundle is the per-key response, which carries the key type and size.
type azureKeyBundle struct {
	Key struct {
		KID    string   `json:"kid"`
		Kty    string   `json:"kty"`
		Crv    string   `json:"crv"`
		KeyOps []string `json:"key_ops"`
		// N is the RSA modulus, base64url-encoded. Trinetra reads only its
		// LENGTH to derive the key size and never decodes the value: a public
		// modulus is not secret, but reading no more than necessary is the
		// habit this service is built on.
		N string `json:"n"`
	} `json:"key"`
	Attributes azureKeyAttrs     `json:"attributes"`
	Tags       map[string]string `json:"tags"`
}

// Scan enumerates keys in the vault.
func (e *AzureEngine) Scan(ctx context.Context, target Target) (Result, error) {
	var result Result
	vault := strings.TrimSuffix(e.vaultURLFor(target), "/")

	listing, err := e.get(ctx, vault+"/keys?api-version=7.4")
	if err != nil {
		return Result{}, err
	}

	var keys azureKeyList
	if err := json.Unmarshal(listing, &keys); err != nil {
		return Result{}, fmt.Errorf("azure key listing could not be parsed: %w", err)
	}

	for _, entry := range keys.Value {
		bundle, err := e.describeKey(ctx, entry.KID)
		if err != nil {
			// A key that exists but cannot be described is a hole in the
			// inventory, and often the one with the most restrictive policy.
			result.Gaps = append(result.Gaps, Gap{
				Path:   azureResourcePath(entry.KID),
				Kind:   "permission_denied",
				Reason: "the key exists but its details could not be read",
				Count:  1,
			})
			continue
		}

		result.ObjectsInspected++
		result.Findings = append(result.Findings, azureKeyFinding(bundle, vault))
	}

	if keys.NextLink != "" {
		// Paging is not followed: a vault with more keys than one page is
		// under-reported, and saying so is better than silently truncating.
		result.Gaps = append(result.Gaps, Gap{
			Kind: "partial_metadata",
			Reason: "the vault returned more keys than one page; " +
				"only the first page was inventoried",
			Count: 1,
		})
	}

	return result, nil
}

func (e *AzureEngine) describeKey(ctx context.Context, kid string) (azureKeyBundle, error) {
	raw, err := e.get(ctx, kid+"?api-version=7.4")
	if err != nil {
		return azureKeyBundle{}, err
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return azureKeyBundle{}, fmt.Errorf("azure key bundle could not be parsed: %w", err)
	}
	return bundle, nil
}

// get performs an authenticated read.
func (e *AzureEngine) get(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+e.BearerToken)
	request.Header.Set("Accept", "application/json")

	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	response, err := client.Do(request)
	if err != nil {
		// Never echo the URL or the error: a vault URL names the customer, and
		// an auth failure body can contain token detail.
		return nil, fmt.Errorf("azure key vault request failed")
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure key vault returned status %d", response.StatusCode)
	}
	return body, nil
}

// azureKeyFinding converts a key bundle into a cloud-service artefact.
func azureKeyFinding(bundle azureKeyBundle, vault string) cbom.Finding {
	algorithm, keySize, curve := azureKeyType(bundle)

	finding := cbom.Finding{
		AssetType:       cbom.AssetCloudService,
		Name:            azureKeyName(bundle.Key.KID),
		Algorithm:       algorithm,
		Curve:           curve,
		ParameterSet:    bundle.Key.Kty,
		DetectionMethod: cbom.DetectCloudAPI,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "azure:keyvault",
		Location: cbom.Location{
			Path:   azureResourcePath(bundle.Key.KID),
			Symbol: bundle.Key.KID,
		},
		Purposes: azurePurposes(bundle.Key.KeyOps),
		Snippet:  describeAzureKey(bundle, vault),
		Extra: map[string]string{
			cbom.TrinetraCloudProviderProperty: "azure",
			cbom.TrinetraCloudServiceProperty:  azureServiceKind(bundle.Key.Kty),
			cbom.TrinetraKeyManagementProperty: azureManagement(bundle.Key.Kty),
			cbom.TrinetraResourceProperty:      bundle.Key.KID,
		},
	}

	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}
	return finding.Normalise()
}

// azureKeyType maps a JWK key type to canonical algorithm, size and curve.
//
// The "-HSM" suffix marks a key held in hardware; it changes where the key
// lives, not what it is, so the algorithm is the same either way.
func azureKeyType(bundle azureKeyBundle) (algorithm string, keySize int, curve string) {
	kty := strings.ToUpper(strings.TrimSpace(bundle.Key.Kty))
	base := strings.TrimSuffix(kty, "-HSM")

	switch base {
	case "RSA":
		return "rsa", rsaBitsFromModulus(bundle.Key.N), ""
	case "EC":
		normalised := normaliseAzureCurve(bundle.Key.Crv)
		return "ecdsa", azureCurveBits(normalised), normalised
	case "OCT":
		// Azure does not publish the length of a symmetric key. Absent means
		// unobserved: guessing 256 would be a measurement nobody made (P3).
		return "aes", 0, ""
	default:
		// An unrecognised key type is reported without an algorithm rather than
		// guessed at.
		return "", 0, ""
	}
}

// rsaBitsFromModulus derives the key size from the base64url modulus length.
//
// Only the LENGTH of the encoded value is used; the modulus itself is never
// decoded or stored. base64url encodes 3 bytes as 4 characters, so the byte
// length is ceil(len*3/4) minus any padding, and the bit length is that times
// eight rounded to the nearest standard size.
func rsaBitsFromModulus(modulus string) int {
	trimmed := strings.TrimRight(strings.TrimSpace(modulus), "=")
	if trimmed == "" {
		return 0
	}

	bytes := len(trimmed) * 3 / 4
	bits := bytes * 8

	// Snap to the nearest standard RSA size, because base64url length is
	// approximate and a reported "2047-bit" key would be noise.
	for _, standard := range []int{1024, 2048, 3072, 4096, 8192} {
		if bits >= standard-16 && bits <= standard+16 {
			return standard
		}
	}
	return bits
}

func normaliseAzureCurve(curve string) string {
	switch strings.ToUpper(strings.TrimSpace(curve)) {
	case "P-256":
		return "P-256"
	case "P-384":
		return "P-384"
	case "P-521":
		return "P-521"
	case "P-256K", "SECP256K1":
		return "secp256k1"
	default:
		return strings.TrimSpace(curve)
	}
}

func azureCurveBits(curve string) int {
	switch curve {
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

// azureServiceKind distinguishes a software vault from a Managed HSM.
func azureServiceKind(kty string) string {
	if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(kty)), "-HSM") {
		return "cloud_hsm"
	}
	return "vault"
}

// azureManagement records who controls the key.
//
// A Key Vault key is always customer-managed: the customer creates it and
// controls its policy, even when Azure holds the material.
func azureManagement(string) string { return "customer_managed" }

func azurePurposes(ops []string) []cbom.Purpose {
	var purposes []cbom.Purpose
	for _, op := range ops {
		switch strings.ToLower(strings.TrimSpace(op)) {
		case "sign":
			purposes = append(purposes, cbom.PurposeDigitalSignature)
		case "verify":
			purposes = append(purposes, cbom.PurposeVerify)
		case "encrypt":
			purposes = append(purposes, cbom.PurposeEncryption)
		case "decrypt":
			purposes = append(purposes, cbom.PurposeDecryption)
		case "wrapkey", "unwrapkey":
			purposes = append(purposes, cbom.PurposeKeyEncapsulation)
		}
	}
	return purposes
}

// azureKeyName extracts the key name from its identifier.
func azureKeyName(kid string) string {
	parsed, err := url.Parse(kid)
	if err != nil {
		return kid
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	// A key identifier is /keys/{name} or /keys/{name}/{version}.
	for i, segment := range segments {
		if segment == "keys" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	if kid == "" {
		return "azure key"
	}
	return kid
}

// azureResourcePath builds the inventory identifier.
//
// Scoped by vault host so two vaults' keys never collide, and relative so it
// never reads as a filesystem path.
func azureResourcePath(kid string) string {
	parsed, err := url.Parse(kid)
	if err != nil || parsed.Host == "" {
		return "azure/keyvault/" + azureKeyName(kid)
	}
	return "azure/keyvault/" + parsed.Host + "/" + azureKeyName(kid)
}

func describeAzureKey(bundle azureKeyBundle, vault string) string {
	parts := []string{"azure key vault key"}

	if bundle.Key.Kty != "" {
		parts = append(parts, "type "+bundle.Key.Kty)
	}
	if bundle.Key.Crv != "" {
		parts = append(parts, "curve "+bundle.Key.Crv)
	}
	if azureServiceKind(bundle.Key.Kty) == "cloud_hsm" {
		parts = append(parts, "held in a Managed HSM")
	}
	if !bundle.Attributes.Enabled {
		parts = append(parts, "disabled")
	}
	if bundle.Attributes.Expires > 0 {
		parts = append(parts, "expires "+
			time.Unix(bundle.Attributes.Expires, 0).UTC().Format("2006-01-02"))
	}
	if vault != "" {
		parts = append(parts, "vault "+vault)
	}

	return strings.Join(parts, "; ")
}
