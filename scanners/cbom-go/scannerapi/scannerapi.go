// Package scannerapi is the HTTP boundary every scanner service shares.
//
// One contract, implemented once: auth, body cap, UUID validation, safe error
// messages and graceful shutdown. Scanner ports are never published to the
// host; only the backend and worker can reach them.
package scannerapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// MaxBodyBytes caps request bodies at 1 MiB. The payload is a scan id and a
// target reference; anything larger is malformed or hostile.
const MaxBodyBytes = 1 << 20

// MinTokenLength is the shortest bearer token accepted. A short shared secret
// on an internal network is still a weak secret.
const MinTokenLength = 32

var uuidPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ScanRequest is the request body.
type ScanRequest struct {
	ScanID          string `json:"scan_id"`
	TargetReference string `json:"target_reference"`
}

// ScanResponse is returned on success.
type ScanResponse struct {
	ScanID            string `json:"scan_id"`
	Status            string `json:"status"`
	ArtifactReference string `json:"artifact_reference"`
	FindingCount      int    `json:"finding_count"`
	ScannerVersion    string `json:"scanner_version"`
}

// ErrorResponse is returned on failure. Messages here are safe by
// construction: no host paths, no stack traces, nothing that describes the
// scanner's filesystem.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScanFunc performs a scan. Returning a *ScanError controls the response code.
type ScanFunc func(ctx context.Context, req ScanRequest) (ScanResponse, error)

// ScanError is an error with a stable code and a client-safe message.
type ScanError struct {
	Code       string
	Message    string
	StatusCode int
	// Internal carries the real detail. It is logged, never returned.
	Internal error
}

func (e *ScanError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *ScanError) Unwrap() error { return e.Internal }

// NewScanError builds a client-safe error.
func NewScanError(code, message string, status int, internal error) *ScanError {
	return &ScanError{Code: code, Message: message, StatusCode: status, Internal: internal}
}

// Config configures a scanner server.
type Config struct {
	Token          string
	ScannerVersion string
	ScannerName    string
	Logger         *slog.Logger
	Scan           ScanFunc
}

// Server wraps the HTTP handlers.
type Server struct {
	cfg        Config
	tokenDigest [32]byte
}

// NewServer validates the config and returns a server.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Token) < MinTokenLength {
		return nil, fmt.Errorf("scanner token must be at least %d characters", MinTokenLength)
	}
	if cfg.Scan == nil {
		return nil, errors.New("scan function is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, tokenDigest: sha256.Sum256([]byte(cfg.Token))}, nil
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/scan", s.handleScan)
	mux.HandleFunc("GET /internal/v1/health", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"scanner": s.cfg.ScannerName,
		"version": s.cfg.ScannerVersion,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.authorised(r) {
		// Deliberately vague: distinguishing "no token" from "wrong token"
		// tells an attacker which half they got right.
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing credentials")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	var req ScanRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not a valid scan request")
		return
	}

	if !uuidPattern.MatchString(req.ScanID) {
		writeError(w, http.StatusBadRequest, "invalid_scan_id", "scan_id must be a UUID")
		return
	}
	if strings.TrimSpace(req.TargetReference) == "" {
		writeError(w, http.StatusBadRequest, "invalid_target", "target_reference is required")
		return
	}

	resp, err := s.cfg.Scan(r.Context(), req)
	if err != nil {
		var scanErr *ScanError
		if errors.As(err, &scanErr) {
			// The real cause is logged; the client sees only the safe message.
			s.cfg.Logger.Error("scan failed",
				"scan_id", req.ScanID, "code", scanErr.Code, "error", scanErr.Error())
			writeError(w, scanErr.StatusCode, scanErr.Code, scanErr.Message)
			return
		}
		s.cfg.Logger.Error("scan failed", "scan_id", req.ScanID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "scan_failed", "the scan could not be completed")
		return
	}

	resp.ScanID = req.ScanID
	resp.Status = "completed"
	resp.ScannerVersion = s.cfg.ScannerVersion
	writeJSON(w, http.StatusOK, resp)
}

// authorised compares the bearer token by SHA-256 digest in constant time, so
// the comparison leaks no timing information about the secret.
func (s *Server) authorised(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(header, "Bearer ")
	if !found {
		return false
	}
	presented := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(presented[:], s.tokenDigest[:]) == 1
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: message})
}

// ListenAndServe runs the server until ctx is cancelled, then shuts down
// gracefully so an in-flight scan is not cut off mid-write.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
