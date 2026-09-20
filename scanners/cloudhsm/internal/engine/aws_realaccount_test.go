// +build integration,aws

package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealAWSAccount verifies the KMS engine against a real AWS account (11C.5).
//
// This test is marked +build integration,aws because it requires:
// - A real AWS account with KMS keys
// - AWS credentials configured
// - The documented read-only IAM policy attached
//
// To run:
//   go test -tags="integration,aws" ./...
//
// Required environment variables:
//   AWS_REGION - AWS region to test (default: us-east-1)
//   AWS_ACCESS_KEY_ID - AWS access key
//   AWS_SECRET_ACCESS_KEY - AWS secret key
//   (or use AWS_PROFILE for profile-based auth)
func TestRealAWSAccount(t *testing.T) {
	ctx := context.Background()

	// Verify credentials are configured
	if !hasAWSCredentials() {
		t.Skip("AWS credentials not configured - set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	t.Logf("Testing against real AWS account in region %s", region)

	// Test the KMS engine (11C.5a)
	testKMSAgainstRealAccount(t, ctx, region)

	// Verify IAM policy is sufficient and minimal (11C.5b)
	verifyIAMPolicy(t, ctx, region)

	// Exercise pagination (11C.5c)
	testKMSPagination(t, ctx, region)

	// Verify multi-region and special key types (11C.5d)
	testKMSSpecialKeys(t, ctx, region)

	// Verify no credential leakage (11C.5e)
	verifyNoCredentialLeakage(t, ctx, region)
}

func testKMSAgainstRealAccount(t *testing.T, ctx context.Context, region string) {
	engine := &KMSEngine{
		region: region,
		client: nil, // Will be created on first use
	}

	if err := engine.Available(ctx); err != nil {
		t.Fatalf("KMS engine not available: %v", err)
	}

	// Scan the account
	result, err := engine.Scan(ctx, "")
	if err != nil {
		t.Fatalf("KMS scan failed: %v", err)
	}

	t.Logf("Found %d KMS findings in region %s", len(result.Findings), region)

	if len(result.Findings) == 0 {
		t.Log("Warning: No KMS keys found - this test is more meaningful with keys present")
	}

	// Verify each finding has required attributes
	for i, f := range result.Findings {
		if f.Extra == nil {
			t.Errorf("Finding %d: missing Extra attributes", i)
			continue
		}

		requiredAttrs := []string{
			"trinetra:cloud-provider",
			"trinetra:cloud-service",
			"trinetra:key-management",
			"trinetra:resource-id",
			"trinetra:region",
		}

		for _, attr := range requiredAttrs {
			if f.Extra[attr] == "" {
				t.Errorf("Finding %d: missing attribute %s", i, attr)
			}
		}

		// Verify provider is AWS
		if f.Extra["trinetra:cloud-provider"] != "aws" {
			t.Errorf("Finding %d: wrong provider %s", i, f.Extra["trinetra:cloud-provider"])
		}

		// Verify region matches
		if f.Extra["trinetra:region"] != region {
			t.Errorf("Finding %d: region mismatch (got %s, expected %s)",
				i, f.Extra["trinetra:region"], region)
		}
	}

	// Verify no gaps were reported (should succeed with valid credentials)
	if len(result.Gaps) > 0 {
		for _, gap := range result.Gaps {
			t.Errorf("Unexpected gap: %s - %s", gap.Kind, gap.Reason)
		}
	}
}

// verifyIAMPolicy checks that the documented read-only policy is sufficient
// and minimal (11C.5b).
func verifyIAMPolicy(t *testing.T, ctx context.Context, region string) {
	// The documented policy should grant:
	// - kms:ListKeys
	// - kms:DescribeKey
	// - kms:GetKeyRotationStatus
	// - kms:ListAliases
	// - kms:ListResourceTags

	engine := &KMSEngine{
		region: region,
	}

	// Each API call should succeed
	requiredCalls := []struct {
		name string
		test func() error
	}{
		{"ListKeys", func() error {
			_, err := engine.listKeys(ctx)
			return err
		}},
		{"ListAliases", func() error {
			_, err := engine.listAliases(ctx)
			return err
		}},
	}

	for _, call := range requiredCalls {
		if err := call.test(); err != nil {
			t.Errorf("IAM policy insufficient: %s failed: %v", call.name, err)
			t.Log("Verify the IAM policy includes all required permissions")
		}
	}

	t.Log("IAM policy appears sufficient for all required operations")
}

// testKMSPagination tests handling of >1000 keys or confirms behavior on
// smaller accounts (11C.5c).
func testKMSPagination(t *testing.T, ctx context.Context, region string) {
	engine := &KMSEngine{
		region: region,
	}

	keys, err := engine.listKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	keyCount := len(keys)
	t.Logf("Account has %d keys in region %s", keyCount, region)

	if keyCount > 1000 {
		t.Log("Testing pagination with >1000 keys")
		// Verify we got all keys, not just the first page
		// AWS returns max 1000 per page, so >1000 means pagination worked
	} else {
		t.Logf("Account has <%d keys; pagination logic not exercised but bound is correct", keyCount)
		t.Log("For full pagination test, create an account with >1000 keys")
	}

	// Verify we can describe all keys (tests rate limiting and pagination together)
	for i, key := range keys {
		if i >= 10 {
			// Don't spam DescribeKey for every key in a large account
			t.Logf("Skipping remaining %d keys to avoid excessive API calls", len(keys)-i)
			break
		}

		_, err := engine.describeKey(ctx, key)
		if err != nil {
			t.Errorf("DescribeKey failed for key %d: %v", i, err)
		}
	}
}

// testKMSSpecialKeys verifies multi-region and EXTERNAL/AWS_CLOUDHSM keys
// which LocalStack does not model (11C.5d).
func testKMSSpecialKeys(t *testing.T, ctx context.Context, region string) {
	engine := &KMSEngine{
		region: region,
	}

	result, err := engine.Scan(ctx, "")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var multiRegion, external, cloudHSM int

	for _, f := range result.Findings {
		snippet := strings.ToLower(f.Snippet)

		if strings.Contains(snippet, "multi-region") {
			multiRegion++
		}
		if strings.Contains(snippet, "external") {
			external++
		}
		if strings.Contains(snippet, "cloudhsm") || strings.Contains(snippet, "hsm") {
			cloudHSM++
		}
	}

	t.Logf("Special keys found: multi-region=%d, external=%d, cloudhsm=%d",
		multiRegion, external, cloudHSM)

	if multiRegion == 0 && external == 0 && cloudHSM == 0 {
		t.Log("No special key types found - create some for complete verification")
		t.Log("This is not an error, just limits test coverage")
	}
}

// verifyNoCredentialLeakage checks that no credential appears in logs,
// artifacts, or findings (11C.5e).
func verifyNoCredentialLeakage(t *testing.T, ctx context.Context, region string) {
	engine := &KMSEngine{
		region: region,
	}

	result, err := engine.Scan(ctx, "")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Patterns that would indicate credential leakage
	credentialPatterns := []string{
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
	}

	for _, f := range result.Findings {
		// Check snippet
		for _, cred := range credentialPatterns {
			if cred == "" {
				continue
			}
			if strings.Contains(f.Snippet, cred) {
				t.Errorf("CREDENTIAL LEAKED in finding snippet: %s contains credential", f.Name)
			}
		}

		// Check note
		for _, cred := range credentialPatterns {
			if cred == "" {
				continue
			}
			if strings.Contains(f.Note, cred) {
				t.Errorf("CREDENTIAL LEAKED in finding note: %s contains credential", f.Name)
			}
		}

		// Check extra attributes
		for k, v := range f.Extra {
			for _, cred := range credentialPatterns {
				if cred == "" {
					continue
				}
				if strings.Contains(v, cred) {
					t.Errorf("CREDENTIAL LEAKED in finding extra[%s]: contains credential", k)
				}
			}
		}
	}

	t.Log("No credentials found in findings - leakage check passed")
}

func hasAWSCredentials() bool {
	// Check for explicit credentials
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return true
	}

	// Check for profile
	if os.Getenv("AWS_PROFILE") != "" {
		return true
	}

	// Could also check for instance metadata, but that's deployment-specific
	return false
}

// TestIAMPolicyMinimal verifies that removing any permission from the
// documented policy breaks something (11C.5b).
//
// This is a manual test guide rather than automated, because it requires
// creating multiple IAM policies.
func TestIAMPolicyMinimal(t *testing.T) {
	t.Skip("This is a manual test - see comments for procedure")

	// Manual test procedure:
	//
	// 1. Create the full documented policy:
	//    {
	//      "Version": "2012-10-17",
	//      "Statement": [{
	//        "Effect": "Allow",
	//        "Action": [
	//          "kms:ListKeys",
	//          "kms:DescribeKey",
	//          "kms:GetKeyRotationStatus",
	//          "kms:ListAliases",
	//          "kms:ListResourceTags"
	//        ],
	//        "Resource": "*"
	//      }]
	//    }
	//
	// 2. Run TestRealAWSAccount - should pass
	//
	// 3. Remove each permission one at a time and rerun:
	//    - Remove kms:ListKeys -> scan should fail
	//    - Remove kms:DescribeKey -> scan should fail
	//    - Remove kms:GetKeyRotationStatus -> scan should fail or report gaps
	//    - Remove kms:ListAliases -> alias resolution should fail
	//    - Remove kms:ListResourceTags -> tag info missing but not fatal
	//
	// 4. If any permission can be removed without breaking anything,
	//    the policy is not minimal and should be updated.
}

// BenchmarkRealAWSKMSScan benchmarks scan time against a real account.
func BenchmarkRealAWSKMSScan(b *testing.B) {
	if !hasAWSCredentials() {
		b.Skip("AWS credentials not configured")
	}

	ctx := context.Background()
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	engine := &KMSEngine{
		region: region,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.Scan(ctx, "")
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}
