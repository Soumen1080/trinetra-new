// Package artifactstore writes CBOM documents into the shared volume.
//
// Writes are atomic and immutable. Immutability is what makes worker redelivery
// safe: if a scan is retried after the scanner already published its CBOM, the
// orchestrator finds the existing file and resumes at ingest rather than asking
// the scanner to overwrite it.
package artifactstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrAlreadyExists means a CBOM for this scan id was already published.
// Callers treat it as "resume at ingest", not as a failure.
var ErrAlreadyExists = errors.New("artifact already exists")

// Store writes artifacts beneath Root.
type Store struct {
	Root string
}

// New returns a Store rooted at root.
func New(root string) *Store { return &Store{Root: root} }

// CBOMPath is where a scan's document lives.
func (s *Store) CBOMPath(scanID string) string {
	return filepath.Join(s.Root, "cbom", scanID+".json")
}

// Exists reports whether a CBOM has already been published for this scan.
func (s *Store) Exists(scanID string) bool {
	_, err := os.Stat(s.CBOMPath(scanID))
	return err == nil
}

// WriteCBOM writes data for scanID, refusing to overwrite an existing file.
//
// The write goes to a temporary file in the destination directory and is then
// renamed. Rename within one filesystem is atomic, so a reader never observes a
// half-written document — which matters because the backend may poll for the
// file while the scanner is still running.
func (s *Store) WriteCBOM(scanID string, data []byte) (string, error) {
	dest := s.CBOMPath(scanID)

	if s.Exists(scanID) {
		return dest, fmt.Errorf("%w: %s", ErrAlreadyExists, scanID)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("create artifact directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".tmp-"+scanID+"-*")
	if err != nil {
		return "", fmt.Errorf("create temp artifact: %w", err)
	}
	tmpName := tmp.Name()

	// Clean up the temp file on any failure after this point.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write artifact: %w", err)
	}
	// Sync before rename: without it a crash can leave a renamed but empty
	// file, which looks like a valid published CBOM containing nothing.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sync artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close artifact: %w", err)
	}

	if err := os.Rename(tmpName, dest); err != nil {
		return "", fmt.Errorf("publish artifact: %w", err)
	}
	tmpName = "" // renamed successfully; nothing to clean up

	// Read-only once published, reinforcing immutability at the filesystem.
	_ = os.Chmod(dest, 0o444)

	return dest, nil
}

// Reference returns the store-relative reference handed back to the backend.
// The backend receives a reference, never an absolute host path.
func (s *Store) Reference(scanID string) string {
	return filepath.ToSlash(filepath.Join("cbom", scanID+".json"))
}
