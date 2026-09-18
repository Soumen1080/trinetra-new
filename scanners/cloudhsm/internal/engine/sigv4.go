package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// AWS SigV4 request signing.
//
// Written here rather than pulled from the AWS SDK deliberately. Trinetra makes
// exactly three read-only KMS calls; the SDK is a large dependency tree for a
// scanner that must be vendorable for an air-gapped install (P7), and every
// transitive dependency in a service that holds cloud credentials is attack
// surface. The signing algorithm is a published specification and fits in one
// file.

// Credentials are read-only AWS credentials.
//
// Trinetra never writes them anywhere: not to the artifact store, not to logs,
// not into a finding. The documented IAM policy for this scanner is
// kms:ListKeys, kms:DescribeKey and kms:ListAliases — nothing that can read key
// material, because key material is precisely what a KMS exists to withhold.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// CredentialsFromEnvironment reads the standard AWS variables.
func CredentialsFromEnvironment() Credentials {
	return Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
}

// IsComplete reports whether both required parts are present.
func (c Credentials) IsComplete() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != ""
}

// Redacted renders the credential for logging without disclosing it.
//
// Only the key id appears, and only its first four characters: enough to tell
// two credentials apart in a log, not enough to be useful to a reader of that
// log. The secret never appears in any form.
func (c Credentials) Redacted() string {
	if c.AccessKeyID == "" {
		return "(no credentials)"
	}
	if len(c.AccessKeyID) <= 4 {
		return "****"
	}
	return c.AccessKeyID[:4] + "****"
}

// signedRequest builds and signs an AWS API request.
type signedRequest struct {
	Service     string
	Region      string
	Endpoint    string
	Target      string // the X-Amz-Target header, e.g. TrentService.ListKeys
	Body        []byte
	Credentials Credentials
	// Now is injected so signing is testable without a clock dependency.
	Now func() time.Time
}

// do signs and executes the request, returning the response body.
func (r signedRequest) do(ctx context.Context, client *http.Client) ([]byte, error) {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	stamp := now().UTC()

	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, r.Endpoint, bytes.NewReader(r.Body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	host := request.URL.Host
	amzDate := stamp.Format("20060102T150405Z")
	dateStamp := stamp.Format("20060102")

	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", r.Target)
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("Host", host)
	if r.Credentials.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", r.Credentials.SessionToken)
	}

	authorization := r.authorizationHeader(request, host, amzDate, dateStamp)
	request.Header.Set("Authorization", authorization)

	response, err := client.Do(request)
	if err != nil {
		// The URL can contain an endpoint an operator configured; the error
		// text is returned to the caller, so keep it free of the request body
		// and of any header.
		return nil, fmt.Errorf("request to %s failed", r.Service)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		// An AWS error body can echo the request, which for KMS includes key
		// identifiers but never key material. Truncate it anyway: an error
		// surface is not an evidence surface.
		return nil, fmt.Errorf("%s returned status %d", r.Service, response.StatusCode)
	}

	return body, nil
}

// authorizationHeader implements AWS Signature Version 4.
func (r signedRequest) authorizationHeader(
	request *http.Request, host, amzDate, dateStamp string,
) string {
	signedHeaders := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if r.Credentials.SessionToken != "" {
		signedHeaders = append(signedHeaders, "x-amz-security-token")
	}
	sort.Strings(signedHeaders)

	var canonicalHeaders strings.Builder
	for _, name := range signedHeaders {
		value := request.Header.Get(name)
		if name == "host" {
			value = host
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteString("\n")
	}

	payloadHash := sha256Hex(r.Body)
	signedHeaderList := strings.Join(signedHeaders, ";")

	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		canonicalURI(request.URL.Path),
		request.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaderList,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, r.Region, r.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+r.Credentials.SecretAccessKey), []byte(dateStamp)),
				[]byte(r.Region)),
			[]byte(r.Service)),
		[]byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		r.Credentials.AccessKeyID, scope, signedHeaderList, signature)
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
