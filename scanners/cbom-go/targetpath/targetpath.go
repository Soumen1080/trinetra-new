// Package targetpath resolves a caller-supplied target reference against the
// scanner's input root, rejecting anything that escapes it.
//
// The scanner receives a path from the backend over HTTP. Without this, a
// crafted target_reference such as "../../etc/shadow" would let a scan read
// outside the directory it was given — so resolution is a security boundary,
// not a convenience.
package targetpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var (
	// ErrEscapesRoot is returned when a reference resolves outside the root.
	ErrEscapesRoot = errors.New("target reference escapes the input root")
	// ErrAbsolute is returned for absolute paths, which are never accepted:
	// the caller must name a location relative to the shared input root.
	ErrAbsolute = errors.New("target reference must be relative")
	// ErrEmpty is returned for an empty reference.
	ErrEmpty = errors.New("target reference is empty")
)

// Resolve joins ref onto root and verifies the result stays inside root.
//
// Symlinks are deliberately NOT followed here: EvalSymlinks would resolve a
// link that points outside the root and then compare the resolved path, which
// is the correct check, but it also fails on paths that do not yet exist.
// Callers that need link-safety mount the input volume read-only, which is what
// the compose topology does.
func Resolve(root, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", ErrEmpty
	}
	if filepath.IsAbs(ref) || isWindowsAbs(ref) {
		return "", fmt.Errorf("%w: %q", ErrAbsolute, ref)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)

	joined := filepath.Clean(filepath.Join(absRoot, ref))

	// filepath.Rel is the reliable containment check: a result starting with
	// ".." means the path climbed out of the root.
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrEscapesRoot, ref)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrEscapesRoot, ref)
	}

	return joined, nil
}

// isWindowsAbs catches absolute paths that the host platform's filepath.IsAbs
// does not recognise.
//
// This must be platform-independent in BOTH directions. filepath.IsAbs on
// Windows rejects "C:\..." but accepts "/etc/passwd" as relative; on Linux the
// reverse. The scanner runs in a Linux container while developers test on
// Windows, so a reference is rejected if it is absolute under EITHER
// convention — otherwise a traversal blocked in production slips through in
// development, or worse, the other way round.
func isWindowsAbs(p string) bool {
	// UNC or POSIX root.
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") ||
		strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	// Drive-letter form: "C:" or "C:\..." or "c:/...".
	if len(p) >= 2 && p[1] == ':' {
		c := p[0] | 0x20 // lowercase
		return c >= 'a' && c <= 'z'
	}
	return false
}

// RelativeTo returns path expressed relative to root, for use in evidence.
// Evidence must never carry a host path: it would leak the scanner's
// filesystem layout into the UI and into exported reports.
func RelativeTo(root, path string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}
