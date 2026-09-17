package scannerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef" // 32 chars

func newTestServer(t *testing.T, scan ScanFunc) http.Handler {
	t.Helper()
	srv, err := NewServer(Config{
		Token:          testToken,
		ScannerName:    "test",
		ScannerVersion: "0.0.1",
		Scan:           scan,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv.Handler()
}

func okScan(context.Context, ScanRequest) (ScanResponse, error) {
	return ScanResponse{ArtifactReference: "cbom/x.json", FindingCount: 3}, nil
}

// A short shared secret on an internal network is still a weak secret.
func TestServerRejectsShortToken(t *testing.T) {
	_, err := NewServer(Config{Token: "tooshort", Scan: okScan})
	if err == nil {
		t.Fatal("expected a short token to be rejected")
	}
}

func TestScanRequiresBearerToken(t *testing.T) {
	handler := newTestServer(t, okScan)

	cases := map[string]string{
		"no header":     "",
		"wrong scheme":  "Basic " + testToken,
		"wrong token":   "Bearer " + strings.Repeat("f", 32),
		"empty token":   "Bearer ",
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/internal/v1/scan",
				strings.NewReader(`{"scan_id":"11111111-2222-3333-4444-555555555555","target_reference":"repo"}`))
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			// Distinguishing "no token" from "wrong token" tells an attacker
			// which half they got right.
			var body ErrorResponse
			_ = json.NewDecoder(rec.Body).Decode(&body)
			if body.Message != "invalid or missing credentials" {
				t.Errorf("auth failure message leaks detail: %q", body.Message)
			}
		})
	}
}

func TestScanRejectsNonUUIDScanID(t *testing.T) {
	handler := newTestServer(t, okScan)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/scan",
		strings.NewReader(`{"scan_id":"not-a-uuid","target_reference":"repo"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanRejectsUnknownFields(t *testing.T) {
	// Contract drift from a caller must fail at the boundary, not be silently
	// dropped.
	handler := newTestServer(t, okScan)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/scan",
		strings.NewReader(`{"scan_id":"11111111-2222-3333-4444-555555555555","target_reference":"repo","extra":"x"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanSucceeds(t *testing.T) {
	handler := newTestServer(t, okScan)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/scan",
		strings.NewReader(`{"scan_id":"11111111-2222-3333-4444-555555555555","target_reference":"repo"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body ScanResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "completed" || body.FindingCount != 3 {
		t.Errorf("unexpected response: %+v", body)
	}
	if body.ScannerVersion != "0.0.1" {
		t.Errorf("scanner version not reported: %+v", body)
	}
}

// Error messages reaching a client must never carry host paths or stack traces.
func TestScanErrorMessagesDoNotLeakInternals(t *testing.T) {
	leaky := func(context.Context, ScanRequest) (ScanResponse, error) {
		return ScanResponse{}, NewScanError(
			"invalid_target",
			"the target reference is not a valid location inside the scan root",
			http.StatusBadRequest,
			errStub{"/home/runner/scan-workdir/../../etc/passwd does not exist"},
		)
	}
	handler := newTestServer(t, leaky)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/scan",
		strings.NewReader(`{"scan_id":"11111111-2222-3333-4444-555555555555","target_reference":"../../etc"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "/home/runner") || strings.Contains(body, "etc/passwd") {
		t.Errorf("error response leaked internal detail: %s", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

type errStub struct{ msg string }

func (e errStub) Error() string { return e.msg }

func TestHealthEndpoint(t *testing.T) {
	handler := newTestServer(t, okScan)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/health", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", rec.Code)
	}
}
