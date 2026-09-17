package targetpath

import (
	"errors"
	"path/filepath"
	"testing"
)

// Path resolution is a security boundary, not a convenience: the reference
// arrives from the backend over HTTP, and a crafted one must not let a scan
// read outside the directory it was given.
func TestResolveRejectsTraversal(t *testing.T) {
	root := t.TempDir()

	hostile := []string{
		"../etc/shadow",
		"../../etc/passwd",
		"repo/../../outside",
		"./../../escape",
		"a/b/../../../outside",
	}

	for _, ref := range hostile {
		t.Run(ref, func(t *testing.T) {
			if _, err := Resolve(root, ref); !errors.Is(err, ErrEscapesRoot) {
				t.Errorf("Resolve(%q) = %v, want ErrEscapesRoot", ref, err)
			}
		})
	}
}

func TestResolveRejectsAbsolutePaths(t *testing.T) {
	root := t.TempDir()

	for _, ref := range []string{"/etc/passwd", `C:\Windows\System32`, `\\server\share`} {
		t.Run(ref, func(t *testing.T) {
			if _, err := Resolve(root, ref); !errors.Is(err, ErrAbsolute) {
				t.Errorf("Resolve(%q) = %v, want ErrAbsolute", ref, err)
			}
		})
	}
}

func TestResolveRejectsEmpty(t *testing.T) {
	if _, err := Resolve(t.TempDir(), "   "); !errors.Is(err, ErrEmpty) {
		t.Errorf("expected ErrEmpty, got %v", err)
	}
}

func TestResolveAcceptsPathsInsideRoot(t *testing.T) {
	root := t.TempDir()

	for _, ref := range []string{"repo", "repo/src", "repo/src/../src", "./repo"} {
		t.Run(ref, func(t *testing.T) {
			got, err := Resolve(root, ref)
			if err != nil {
				t.Fatalf("Resolve(%q) unexpectedly failed: %v", ref, err)
			}
			rel, err := filepath.Rel(root, got)
			if err != nil || rel == ".." {
				t.Errorf("resolved path %q is outside root %q", got, root)
			}
		})
	}
}

// Evidence must never carry a host path.
func TestRelativeToStripsTheRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workdir")
	full := filepath.Join(root, "svc", "auth.py")

	got, err := RelativeTo(root, full)
	if err != nil {
		t.Fatalf("RelativeTo: %v", err)
	}
	if got != "svc/auth.py" {
		t.Errorf("RelativeTo = %q, want svc/auth.py", got)
	}
}
