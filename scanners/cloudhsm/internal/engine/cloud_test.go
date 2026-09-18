package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// ---------------------------------------------------------------------------
// Azure Key Vault
// ---------------------------------------------------------------------------

// azureStub serves recorded Key Vault responses, so the adapter is testable
// without an Azure subscription.
func azureStub(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request must be authenticated; an unauthenticated one would
		// mean the adapter forgot the token.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/keys"):
			_, _ = w.Write([]byte(`{"value":[
              {"kid":"` + azureBase(r) + `/keys/payments-signing"},
              {"kid":"` + azureBase(r) + `/keys/data-wrapping"},
              {"kid":"` + azureBase(r) + `/keys/hsm-backed"}
            ]}`))

		case strings.Contains(r.URL.Path, "/keys/payments-signing"):
			// A 2048-bit modulus is 256 bytes, which base64url-encodes to 342
			// characters.
			_, _ = w.Write([]byte(`{"key":{
              "kid":"` + azureBase(r) + `/keys/payments-signing",
              "kty":"RSA","key_ops":["sign","verify"],
              "n":"` + strings.Repeat("A", 342) + `"},
              "attributes":{"enabled":true}}`))

		case strings.Contains(r.URL.Path, "/keys/data-wrapping"):
			_, _ = w.Write([]byte(`{"key":{
              "kid":"` + azureBase(r) + `/keys/data-wrapping",
              "kty":"EC","crv":"P-256","key_ops":["sign"]},
              "attributes":{"enabled":true}}`))

		case strings.Contains(r.URL.Path, "/keys/hsm-backed"):
			_, _ = w.Write([]byte(`{"key":{
              "kid":"` + azureBase(r) + `/keys/hsm-backed",
              "kty":"RSA-HSM","key_ops":["wrapKey","unwrapKey"],
              "n":"` + strings.Repeat("A", 342) + `"},
              "attributes":{"enabled":false}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func azureBase(r *http.Request) string {
	return "http://" + r.Host
}

func scanAzure(t *testing.T) Result {
	t.Helper()
	server := azureStub(t)

	e := &AzureEngine{
		VaultURL:    server.URL,
		BearerToken: "test-token",
		Client:      server.Client(),
	}
	target := Target{Provider: "azure", Endpoint: server.URL}

	if err := e.Available(context.Background(), target); err != nil {
		t.Fatalf("engine unavailable: %v", err)
	}
	result, err := e.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

func TestAzureInventoriesVaultKeys(t *testing.T) {
	result := scanAzure(t)

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 keys, got %d: %+v", len(result.Findings), result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetCloudService {
			t.Errorf("%q is not a cloud-service artefact", finding.Name)
		}
		if !strings.HasPrefix(finding.Location.Path, "azure/keyvault/") {
			t.Errorf("resource path = %q", finding.Location.Path)
		}
	}
}

// The key size is what makes an RSA vault key legible as Shor-breakable.
func TestAzureResolvesRSAKeySize(t *testing.T) {
	for _, finding := range scanAzure(t).Findings {
		if finding.Name != "payments-signing" {
			continue
		}
		if finding.Algorithm != "rsa" {
			t.Errorf("algorithm = %q, want rsa", finding.Algorithm)
		}
		if size, ok := finding.KeySize(); !ok || size != 2048 {
			t.Errorf("key size = %d (%v), want 2048", size, ok)
		}
		return
	}
	t.Fatal("payments-signing key not produced")
}

func TestAzureResolvesECCurve(t *testing.T) {
	for _, finding := range scanAzure(t).Findings {
		if finding.Name != "data-wrapping" {
			continue
		}
		if finding.Curve != "P-256" {
			t.Errorf("curve = %q, want P-256", finding.Curve)
		}
		if size, ok := finding.KeySize(); !ok || size != 256 {
			t.Errorf("key size = %d (%v), want 256", size, ok)
		}
		return
	}
	t.Fatal("data-wrapping key not produced")
}

// A Managed HSM key cannot be migrated the same way a software key can, so the
// distinction must reach the artefact.
func TestAzureDistinguishesManagedHSM(t *testing.T) {
	var sawHSM bool
	for _, finding := range scanAzure(t).Findings {
		if finding.Name != "hsm-backed" {
			continue
		}
		sawHSM = true
		if finding.Extra[cbom.TrinetraCloudServiceProperty] != "cloud_hsm" {
			t.Errorf("service kind = %q, want cloud_hsm",
				finding.Extra[cbom.TrinetraCloudServiceProperty])
		}
		if !strings.Contains(finding.Snippet, "Managed HSM") {
			t.Errorf("evidence does not mention the HSM: %q", finding.Snippet)
		}
		// The algorithm is unchanged by where the key lives.
		if finding.Algorithm != "rsa" {
			t.Errorf("algorithm = %q, want rsa", finding.Algorithm)
		}
	}
	if !sawHSM {
		t.Fatal("hsm-backed key not produced")
	}
}

// Azure does not publish a symmetric key's length. Absent means unobserved:
// guessing 256 would be a measurement nobody made (P3).
func TestAzureSymmetricKeySizeStaysUnobserved(t *testing.T) {
	algorithm, size, _ := azureKeyType(azureKeyBundle{
		Key: struct {
			KID    string   `json:"kid"`
			Kty    string   `json:"kty"`
			Crv    string   `json:"crv"`
			KeyOps []string `json:"key_ops"`
			N      string   `json:"n"`
		}{Kty: "oct"},
	})

	if algorithm != "aes" {
		t.Errorf("algorithm = %q, want aes", algorithm)
	}
	if size != 0 {
		t.Errorf("size = %d; Azure does not publish it, so it must stay unobserved", size)
	}
}

func TestRSABitsFromModulus(t *testing.T) {
	cases := map[int]int{
		342: 2048, // 256 bytes
		512: 3072, // 384 bytes
		683: 4096, // 512 bytes
		0:   0,
	}
	for encoded, want := range cases {
		if got := rsaBitsFromModulus(strings.Repeat("A", encoded)); got != want {
			t.Errorf("rsaBitsFromModulus(len %d) = %d, want %d", encoded, got, want)
		}
	}
}

// A missing token must be a named reason, never silence — "no keys found" is
// the most dangerous possible output for a cloud scanner.
func TestAzureUnavailableWithoutToken(t *testing.T) {
	e := &AzureEngine{VaultURL: "https://example.vault.azure.net"}
	err := e.Available(context.Background(), Target{Provider: "azure"})
	if err == nil {
		t.Fatal("expected the engine to refuse to run without a token")
	}
	if !strings.Contains(err.Error(), "TRINETRA_AZURE_TOKEN") {
		t.Errorf("the reason is not actionable: %v", err)
	}
}

func TestAzureUnavailableWithoutVaultURL(t *testing.T) {
	e := &AzureEngine{BearerToken: "x"}
	if err := e.Available(context.Background(), Target{Provider: "azure"}); err == nil {
		t.Error("expected the engine to require a vault URL")
	}
}

func TestAzureRejectsNonAzureTargets(t *testing.T) {
	e := &AzureEngine{VaultURL: "https://v", BearerToken: "t"}
	if err := e.Available(context.Background(), Target{Provider: "aws"}); err == nil {
		t.Error("the Azure engine accepted an AWS target")
	}
}

// Credentials must never reach a finding.
func TestAzureFindingsCarryNoToken(t *testing.T) {
	serialised, err := json.Marshal(scanAzure(t).Findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"test-token", "Bearer", "Authorization"} {
		if strings.Contains(string(serialised), forbidden) {
			t.Errorf("findings contain %q", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// GCP Cloud KMS
// ---------------------------------------------------------------------------

func gcpStub(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/keyRings"):
			_, _ = w.Write([]byte(`{"keyRings":[
              {"name":"projects/demo/locations/europe-west1/keyRings/payments"}
            ]}`))

		case strings.HasSuffix(r.URL.Path, "/cryptoKeys"):
			_, _ = w.Write([]byte(`{"cryptoKeys":[
              {
                "name":"projects/demo/locations/europe-west1/keyRings/payments/cryptoKeys/signing",
                "purpose":"ASYMMETRIC_SIGN",
                "rotationPeriod":"7776000s",
                "versionTemplate":{"protectionLevel":"HSM","algorithm":"RSA_SIGN_PKCS1_2048_SHA256"},
                "primary":{"state":"ENABLED","algorithm":"RSA_SIGN_PKCS1_2048_SHA256","protectionLevel":"HSM"}
              },
              {
                "name":"projects/demo/locations/europe-west1/keyRings/payments/cryptoKeys/at-rest",
                "purpose":"ENCRYPT_DECRYPT",
                "versionTemplate":{"protectionLevel":"SOFTWARE","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION"},
                "primary":{"state":"ENABLED","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel":"SOFTWARE"}
              }
            ]}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func scanGCP(t *testing.T) Result {
	t.Helper()
	server := gcpStub(t)

	e := &GCPEngine{
		Project:     "demo",
		AccessToken: "test-token",
		Client:      server.Client(),
	}
	target := Target{Provider: "gcp", Region: "europe-west1", Endpoint: server.URL}

	if err := e.Available(context.Background(), target); err != nil {
		t.Fatalf("engine unavailable: %v", err)
	}
	result, err := e.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

func TestGCPInventoriesCryptoKeys(t *testing.T) {
	result := scanGCP(t)

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 keys, got %d: %+v", len(result.Findings), result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetCloudService {
			t.Errorf("%q is not a cloud-service artefact", finding.Name)
		}
		if !strings.HasPrefix(finding.Location.Path, "gcp/kms/") {
			t.Errorf("resource path = %q", finding.Location.Path)
		}
	}
}

func TestGCPResolvesAlgorithmsFromVersionNames(t *testing.T) {
	byName := map[string]cbom.Finding{}
	for _, finding := range scanGCP(t).Findings {
		byName[finding.Name] = finding
	}

	signing, ok := byName["signing"]
	if !ok {
		t.Fatalf("signing key missing; got %v", keysOf(byName))
	}
	if signing.Algorithm != "rsa" {
		t.Errorf("algorithm = %q, want rsa", signing.Algorithm)
	}
	if size, has := signing.KeySize(); !has || size != 2048 {
		t.Errorf("key size = %d (%v), want 2048", size, has)
	}
	// The provider's own spelling is preserved so a reader can check the console.
	if signing.ParameterSet != "RSA_SIGN_PKCS1_2048_SHA256" {
		t.Errorf("parameter set = %q", signing.ParameterSet)
	}

	atRest, ok := byName["at-rest"]
	if !ok {
		t.Fatalf("at-rest key missing; got %v", keysOf(byName))
	}
	if atRest.Algorithm != "aes" {
		t.Errorf("algorithm = %q, want aes", atRest.Algorithm)
	}
}

// An HSM-protected key cannot be migrated the same way a software key can.
func TestGCPRecordsProtectionLevel(t *testing.T) {
	byName := map[string]cbom.Finding{}
	for _, finding := range scanGCP(t).Findings {
		byName[finding.Name] = finding
	}

	if got := byName["signing"].Extra[cbom.TrinetraCloudServiceProperty]; got != "cloud_hsm" {
		t.Errorf("HSM key service kind = %q, want cloud_hsm", got)
	}
	if !strings.Contains(byName["signing"].Snippet, "held in hardware") {
		t.Errorf("evidence does not state the HSM protection: %q", byName["signing"].Snippet)
	}
	if got := byName["at-rest"].Extra[cbom.TrinetraCloudServiceProperty]; got != "kms" {
		t.Errorf("software key service kind = %q, want kms", got)
	}
}

// No rotation policy is itself a finding and must not read as "rotates".
func TestGCPStatesAbsentRotationPolicy(t *testing.T) {
	for _, finding := range scanGCP(t).Findings {
		if finding.Name == "at-rest" {
			if !strings.Contains(finding.Snippet, "no rotation period configured") {
				t.Errorf("an absent rotation policy was not stated: %q", finding.Snippet)
			}
			return
		}
	}
	t.Fatal("at-rest key not produced")
}

func TestGCPAlgorithmMapping(t *testing.T) {
	cases := []struct {
		spec      string
		algorithm string
		size      int
		curve     string
	}{
		{"GOOGLE_SYMMETRIC_ENCRYPTION", "aes", 256, ""},
		{"RSA_SIGN_PKCS1_2048_SHA256", "rsa", 2048, ""},
		{"RSA_DECRYPT_OAEP_4096_SHA512", "rsa", 4096, ""},
		{"EC_SIGN_P256_SHA256", "ecdsa", 256, "P-256"},
		{"EC_SIGN_P384_SHA384", "ecdsa", 384, "P-384"},
		{"EC_SIGN_SECP256K1_SHA256", "ecdsa", 256, "secp256k1"},
		{"HMAC_SHA256", "hmac", 256, ""},
		// PQC algorithms are recognised as their families rather than unknown.
		{"PQ_SIGN_ML_DSA_65", "ml-dsa", 0, ""},
		{"PQ_SIGN_SLH_DSA_SHA2_128S", "slh-dsa", 0, ""},
		// An unrecognised spec must not be guessed at.
		{"SOME_FUTURE_ALGORITHM", "", 0, ""},
		{"", "", 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			algorithm, size, curve := gcpAlgorithm(tc.spec)
			if algorithm != tc.algorithm || size != tc.size || curve != tc.curve {
				t.Errorf("gcpAlgorithm(%q) = (%q,%d,%q), want (%q,%d,%q)",
					tc.spec, algorithm, size, curve, tc.algorithm, tc.size, tc.curve)
			}
		})
	}
}

func TestGCPResourcePath(t *testing.T) {
	got := gcpResourcePath(
		"projects/demo/locations/europe-west1/keyRings/payments/cryptoKeys/signing")
	want := "gcp/kms/demo/europe-west1/payments/signing"
	if got != want {
		t.Errorf("gcpResourcePath = %q, want %q", got, want)
	}
}

func TestGCPUnavailableWithoutCredentials(t *testing.T) {
	cases := map[string]*GCPEngine{
		"no project": {AccessToken: "t"},
		"no token":   {Project: "demo"},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			err := e.Available(context.Background(),
				Target{Provider: "gcp", Region: "europe-west1"})
			if err == nil {
				t.Error("expected the engine to refuse to run")
			}
		})
	}
}

func TestGCPRequiresLocation(t *testing.T) {
	// GCP KMS resources are location-scoped; there is no sensible default.
	e := &GCPEngine{Project: "demo", AccessToken: "t"}
	if err := e.Available(context.Background(), Target{Provider: "gcp"}); err == nil {
		t.Error("expected the engine to require a location")
	}
}

func TestGCPFindingsCarryNoToken(t *testing.T) {
	serialised, err := json.Marshal(scanGCP(t).Findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"test-token", "Bearer", "Authorization"} {
		if strings.Contains(string(serialised), forbidden) {
			t.Errorf("findings contain %q", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// Cross-provider
// ---------------------------------------------------------------------------

// The risk engine must see one shape regardless of provider.
func TestAllProvidersProduceTheSameArtefactShape(t *testing.T) {
	for name, findings := range map[string][]cbom.Finding{
		"azure": scanAzure(t).Findings,
		"gcp":   scanGCP(t).Findings,
	} {
		t.Run(name, func(t *testing.T) {
			for _, finding := range findings {
				if finding.AssetType != cbom.AssetCloudService {
					t.Errorf("%q is not a cloud-service artefact", finding.Name)
				}
				if finding.DetectionMethod != cbom.DetectCloudAPI {
					t.Errorf("%q detection method = %q, want cloud_api",
						finding.Name, finding.DetectionMethod)
				}
				for _, required := range []string{
					cbom.TrinetraCloudProviderProperty,
					cbom.TrinetraCloudServiceProperty,
					cbom.TrinetraKeyManagementProperty,
					cbom.TrinetraResourceProperty,
				} {
					if finding.Extra[required] == "" {
						t.Errorf("%q is missing %s", finding.Name, required)
					}
				}
			}
		})
	}
}

// A provider that is configured but unreachable must be a named gap, never
// silence — the Phase 4 rule extended to every provider.
func TestUnconfiguredProvidersBecomeNamedGaps(t *testing.T) {
	registry := NewRegistry(
		&KMSEngine{},   // no credentials
		&AzureEngine{}, // no vault or token
		&GCPEngine{},   // no project or token
	)

	result, _, err := registry.RunAll(context.Background(),
		Target{Provider: "azure"})

	if err == nil {
		t.Fatal("expected the scan to fail when no engine is available")
	}
	if len(result.Gaps) != 3 {
		t.Fatalf("expected a gap per unavailable engine, got %d: %+v",
			len(result.Gaps), result.Gaps)
	}
	for _, gap := range result.Gaps {
		if gap.Kind != "engine_unavailable" {
			t.Errorf("gap kind = %q", gap.Kind)
		}
		// The reason must name what was not inventoried, so a thin result is
		// never mistaken for an empty estate.
		if !strings.Contains(gap.Reason, "not inventoried") {
			t.Errorf("gap does not say what was lost: %q", gap.Reason)
		}
	}
}
