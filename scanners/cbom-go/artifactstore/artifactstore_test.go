package artifactstore

import (
	"errors"
	"os"
	"testing"
)

// Immutability is what makes worker redelivery safe: a retried scan finds the
// existing document and resumes at ingest rather than overwriting it.
func TestWriteCBOMRefusesToOverwrite(t *testing.T) {
	store := New(t.TempDir())
	const scanID = "11111111-2222-3333-4444-555555555555"

	if _, err := store.WriteCBOM(scanID, []byte(`{"first":true}`)); err != nil {
		t.Fatalf("first write: %v", err)
	}

	_, err := store.WriteCBOM(scanID, []byte(`{"second":true}`))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second write = %v, want ErrAlreadyExists", err)
	}

	data, err := os.ReadFile(store.CBOMPath(scanID))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != `{"first":true}` {
		t.Errorf("the original document was modified: %s", data)
	}
}

func TestExistsReportsPublishedArtifacts(t *testing.T) {
	store := New(t.TempDir())
	const scanID = "11111111-2222-3333-4444-555555555555"

	if store.Exists(scanID) {
		t.Error("Exists reported true before any write")
	}
	if _, err := store.WriteCBOM(scanID, []byte(`{}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !store.Exists(scanID) {
		t.Error("Exists reported false after a successful write")
	}
}

// The backend receives a reference, never an absolute host path.
func TestReferenceIsRelative(t *testing.T) {
	store := New(`C:\artifact-store`)
	ref := store.Reference("abc")

	if ref != "cbom/abc.json" {
		t.Errorf("Reference = %q, want cbom/abc.json", ref)
	}
}

func TestWriteLeavesNoTempFilesBehind(t *testing.T) {
	root := t.TempDir()
	store := New(root)

	if _, err := store.WriteCBOM("11111111-2222-3333-4444-555555555555", []byte(`{}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, err := os.ReadDir(root + "/cbom")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if len(e.Name()) > 0 && e.Name()[0] == '.' {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}
