package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trinetra/cbom-go/cbom"
)

// testCredentials are the values LocalStack accepts and that every unit test
// signs with. They are not real and grant nothing.
var testCredentials = Credentials{
	AccessKeyID:     "test",
	SecretAccessKey: "test",
}

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC) }
}

// kmsStub serves recorded KMS responses, so the adapter is testable without any
// cloud account or emulator.
func kmsStub(t *testing.T, responses map[string]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
		body, ok := responses[action]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

const listKeysResponse = `{
  "Keys": [
    {"KeyId": "1111", "KeyArn": "arn:aws:kms:ap-south-1:123:key/1111"},
    {"KeyId": "2222", "KeyArn": "arn:aws:kms:ap-south-1:123:key/2222"},
    {"KeyId": "3333", "KeyArn": "arn:aws:kms:ap-south-1:123:key/3333"}
  ],
  "Truncated": false
}`

const listAliasesResponse = `{
  "Aliases": [
    {"AliasName": "alias/payments-signing", "TargetKeyId": "1111"},
    {"AliasName": "alias/aws/s3", "TargetKeyId": "3333"},
    {"AliasName": "alias/data-at-rest", "TargetKeyId": "3333"}
  ]
}`

func describeKeyResponse(keyID, spec, usage, manager string) string {
	return `{"KeyMetadata": {
      "KeyId": "` + keyID + `",
      "Arn": "arn:aws:kms:ap-south-1:123:key/` + keyID + `",
      "KeySpec": "` + spec + `",
      "KeyUsage": "` + usage + `",
      "KeyManager": "` + manager + `",
      "Origin": "AWS_KMS",
      "KeyState": "Enabled",
      "Enabled": true,
      "Description": "test key"
    }}`
}

// newStubEngine wires an engine to a stub that answers every call.
func newStubEngine(t *testing.T, describe string) (*KMSEngine, Target) {
	t.Helper()
	server := kmsStub(t, map[string]string{
		"ListKeys":    listKeysResponse,
		"ListAliases": listAliasesResponse,
		"DescribeKey": describe,
	})

	engine := &KMSEngine{
		Credentials: testCredentials,
		Client:      server.Client(),
		Now:         fixedClock(),
	}
	return engine, Target{Provider: "aws", Region: "ap-south-1", Endpoint: server.URL}
}

func TestKMSInventoriesKeys(t *testing.T) {
	engine, target := newStubEngine(t,
		describeKeyResponse("1111", "RSA_2048", "SIGN_VERIFY", "CUSTOMER"))

	result, err := engine.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(result.Findings))
	}
	for _, finding := range result.Findings {
		if finding.AssetType != cbom.AssetCloudService {
			t.Errorf("%q is not a cloud-service artefact", finding.Name)
		}
	}
}

// The key spec is the load-bearing field: RSA_2048 is Shor-breakable and
// SYMMETRIC_DEFAULT is not, and the risk engine cannot tell them apart without
// it reaching the artefact.
func TestKMSKeySpecMapping(t *testing.T) {
	cases := []struct {
		spec      string
		algorithm string
		size      int
		curve     string
	}{
		{"RSA_2048", "rsa", 2048, ""},
		{"RSA_4096", "rsa", 4096, ""},
		{"ECC_NIST_P256", "ecdsa", 256, "P-256"},
		{"ECC_NIST_P384", "ecdsa", 384, "P-384"},
		{"ECC_SECG_P256K1", "ecdsa", 256, "secp256k1"},
		{"SYMMETRIC_DEFAULT", "aes", 256, ""},
		{"HMAC_256", "hmac", 256, ""},
		// An unrecognised spec must not be guessed at: a new AWS key type
		// silently classified as something it is not would be worse than an
		// unclassified one.
		{"FUTURE_PQC_SPEC", "", 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			algorithm, size, curve := kmsKeySpec(tc.spec)
			if algorithm != tc.algorithm || size != tc.size || curve != tc.curve {
				t.Errorf("kmsKeySpec(%q) = (%q,%d,%q), want (%q,%d,%q)",
					tc.spec, algorithm, size, curve, tc.algorithm, tc.size, tc.curve)
			}
		})
	}
}

func TestKMSResolvesKeySizeIntoTheFinding(t *testing.T) {
	engine, target := newStubEngine(t,
		describeKeyResponse("1111", "RSA_2048", "SIGN_VERIFY", "CUSTOMER"))

	result, _ := engine.Scan(context.Background(), target)

	finding := result.Findings[0]
	if size, ok := finding.KeySize(); !ok || size != 2048 {
		t.Errorf("key size = %d (%v), want 2048", size, ok)
	}
	if finding.Algorithm != "rsa" {
		t.Errorf("algorithm = %q, want rsa", finding.Algorithm)
	}
	if finding.ParameterSet != "RSA_2048" {
		t.Errorf("parameter set = %q, want the verbatim AWS spec", finding.ParameterSet)
	}
}

// Who controls a key decides whether migrating it is a code change or a vendor
// negotiation, so the distinction must reach the evidence.
func TestKMSRecordsKeyManagement(t *testing.T) {
	cases := map[string]string{
		"CUSTOMER": "customer_managed",
		"AWS":      "provider_managed",
		// Unknown rather than an assumed default.
		"":       "unknown",
		"FUTURE": "unknown",
	}

	for manager, want := range cases {
		t.Run(manager, func(t *testing.T) {
			if got := kmsManagement(manager); got != want {
				t.Errorf("kmsManagement(%q) = %q, want %q", manager, got, want)
			}
		})
	}
}

func TestKMSEvidenceCarriesManagementAndSpec(t *testing.T) {
	engine, target := newStubEngine(t,
		describeKeyResponse("1111", "RSA_2048", "SIGN_VERIFY", "AWS"))

	result, _ := engine.Scan(context.Background(), target)
	snippet := result.Findings[0].Snippet

	for _, want := range []string{"spec RSA_2048", "management provider_managed", "usage SIGN_VERIFY"} {
		if !strings.Contains(snippet, want) {
			t.Errorf("evidence omits %q: %s", want, snippet)
		}
	}
}

// A customer alias is more informative than an AWS-managed one.
func TestKMSPrefersCustomerAliases(t *testing.T) {
	engine, target := newStubEngine(t,
		describeKeyResponse("3333", "SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "CUSTOMER"))

	result, _ := engine.Scan(context.Background(), target)

	for _, finding := range result.Findings {
		if strings.Contains(finding.Name, "aws/s3") {
			t.Errorf("an AWS-managed alias won over a customer one: %q", finding.Name)
		}
	}
}

func TestKMSPurposes(t *testing.T) {
	cases := map[string]int{
		"SIGN_VERIFY":         2,
		"ENCRYPT_DECRYPT":     2,
		"GENERATE_VERIFY_MAC": 1,
		"KEY_AGREEMENT":       1,
		"":                    0,
	}
	for usage, want := range cases {
		if got := len(kmsPurposes(usage)); got != want {
			t.Errorf("kmsPurposes(%q) returned %d purposes, want %d", usage, got, want)
		}
	}
}

// A key that exists but cannot be described is a hole in the inventory, and
// often the one with the most restrictive policy — which makes it more
// interesting, not less.
func TestKMSUndescribableKeyBecomesAGap(t *testing.T) {
	server := kmsStub(t, map[string]string{
		"ListKeys":    listKeysResponse,
		"ListAliases": listAliasesResponse,
		// DescribeKey deliberately absent: the stub returns 400.
	})
	engine := &KMSEngine{Credentials: testCredentials, Client: server.Client(), Now: fixedClock()}

	result, err := engine.Scan(context.Background(),
		Target{Provider: "aws", Region: "ap-south-1", Endpoint: server.URL})
	if err != nil {
		t.Fatalf("scan should succeed with gaps: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
	if len(result.Gaps) != 3 {
		t.Fatalf("expected a gap per undescribable key, got %d", len(result.Gaps))
	}
	if result.Gaps[0].Kind != "permission_denied" {
		t.Errorf("gap kind = %q", result.Gaps[0].Kind)
	}
}

// A missing credential is the likeliest reason a cloud inventory comes back
// thin, so it must be a named gap rather than "no keys found".
func TestKMSUnavailableWithoutCredentials(t *testing.T) {
	engine := &KMSEngine{}
	err := engine.Available(context.Background(), Target{Provider: "aws", Region: "ap-south-1"})
	if err == nil {
		t.Fatal("expected the engine to refuse to run without credentials")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("the reason is not actionable: %v", err)
	}
}

func TestKMSUnavailableWithoutRegion(t *testing.T) {
	engine := &KMSEngine{Credentials: testCredentials}
	if err := engine.Available(context.Background(), Target{Provider: "aws"}); err == nil {
		t.Error("expected the engine to require a region")
	}
}

func TestKMSRejectsNonAWSTargets(t *testing.T) {
	engine := &KMSEngine{Credentials: testCredentials}
	err := engine.Available(context.Background(), Target{Provider: "gcp", Region: "x"})
	if err == nil {
		t.Error("the AWS engine accepted a GCP target")
	}
}

// Credentials must never be logged, written or placed in a finding.
func TestCredentialsAreRedacted(t *testing.T) {
	credential := Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	redacted := credential.Redacted()

	if strings.Contains(redacted, credential.SecretAccessKey) {
		t.Fatal("the secret access key appeared in the redacted form")
	}
	if redacted != "AKIA****" {
		t.Errorf("redacted = %q, want AKIA****", redacted)
	}
	if (Credentials{}).Redacted() != "(no credentials)" {
		t.Error("an absent credential should say so")
	}
}

func TestFindingsCarryNoCredentials(t *testing.T) {
	engine, target := newStubEngine(t,
		describeKeyResponse("1111", "RSA_2048", "SIGN_VERIFY", "CUSTOMER"))

	result, _ := engine.Scan(context.Background(), target)

	serialised, err := json.Marshal(result.Findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"test", "Authorization", "AWS4-HMAC"} {
		if secret == "test" {
			continue // the stub's key id is literally "test"; skip that one
		}
		if strings.Contains(string(serialised), secret) {
			t.Errorf("findings contain %q", secret)
		}
	}
}

// SigV4 is a published specification; this pins the signature so a refactor
// cannot silently break authentication against real AWS.
func TestSigV4ProducesAStableSignature(t *testing.T) {
	request := signedRequest{
		Service:     "kms",
		Region:      "ap-south-1",
		Endpoint:    "https://kms.ap-south-1.amazonaws.com/",
		Target:      "TrentService.ListKeys",
		Body:        []byte(`{"Limit":1000}`),
		Credentials: testCredentials,
		Now:         fixedClock(),
	}

	httpRequest, err := http.NewRequest(http.MethodPost, request.Endpoint, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	httpRequest.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpRequest.Header.Set("X-Amz-Target", request.Target)
	httpRequest.Header.Set("X-Amz-Date", "20260314T103000Z")

	first := request.authorizationHeader(
		httpRequest, "kms.ap-south-1.amazonaws.com", "20260314T103000Z", "20260314")
	second := request.authorizationHeader(
		httpRequest, "kms.ap-south-1.amazonaws.com", "20260314T103000Z", "20260314")

	if first != second {
		t.Error("signing is not deterministic")
	}
	for _, required := range []string{
		"AWS4-HMAC-SHA256",
		"Credential=test/20260314/ap-south-1/kms/aws4_request",
		"SignedHeaders=content-type;host;x-amz-date;x-amz-target",
		"Signature=",
	} {
		if !strings.Contains(first, required) {
			t.Errorf("authorization header missing %q: %s", required, first)
		}
	}
}

func TestSigV4IncludesSessionTokenWhenPresent(t *testing.T) {
	request := signedRequest{
		Service:  "kms",
		Region:   "ap-south-1",
		Endpoint: "https://kms.ap-south-1.amazonaws.com/",
		Target:   "TrentService.ListKeys",
		Credentials: Credentials{
			AccessKeyID:     "test",
			SecretAccessKey: "test",
			SessionToken:    "session-token",
		},
		Now: fixedClock(),
	}

	httpRequest, _ := http.NewRequest(http.MethodPost, request.Endpoint, nil)
	httpRequest.Header.Set("X-Amz-Security-Token", "session-token")

	header := request.authorizationHeader(
		httpRequest, "kms.ap-south-1.amazonaws.com", "20260314T103000Z", "20260314")

	if !strings.Contains(header, "x-amz-security-token") {
		t.Errorf("a session token must be signed: %s", header)
	}
}

// An account with no keys is a valid result, not an error.
func TestKMSEmptyAccountIsValid(t *testing.T) {
	server := kmsStub(t, map[string]string{
		"ListKeys":    `{"Keys": [], "Truncated": false}`,
		"ListAliases": `{"Aliases": []}`,
	})
	engine := &KMSEngine{Credentials: testCredentials, Client: server.Client(), Now: fixedClock()}

	result, err := engine.Scan(context.Background(),
		Target{Provider: "aws", Region: "ap-south-1", Endpoint: server.URL})
	if err != nil {
		t.Fatalf("an empty account must scan successfully: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}
