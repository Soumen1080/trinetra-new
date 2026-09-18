package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// knowledgeBasePath locates the committed profile, walking up so tests run from
// any directory.
func knowledgeBasePath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "knowledge", "crypto-libraries-2026.1.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("knowledge base not found")
	return ""
}

func loadKB(t *testing.T) *KnowledgeBase {
	t.Helper()
	kb, err := LoadKnowledgeBase(knowledgeBasePath(t))
	if err != nil {
		t.Fatalf("load knowledge base: %v", err)
	}
	return kb
}

// The committed profile must load and validate, or the service will not start.
func TestCommittedKnowledgeBaseIsValid(t *testing.T) {
	kb := loadKB(t)

	if kb.Version == "" {
		t.Error("knowledge base has no version")
	}
	if len(kb.Libraries) < 10 {
		t.Errorf("only %d libraries; the curated set should be broader", len(kb.Libraries))
	}
}

// Every judgement Trinetra makes must be traceable to a source.
func TestEveryLibraryCitesASource(t *testing.T) {
	for _, library := range loadKB(t).Libraries {
		if library.Citation == "" {
			t.Errorf("%s has no citation", library.DisplayName)
		}
	}
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	kb := loadKB(t)

	for _, name := range []string{"openssl", "OpenSSL", "OPENSSL", "  openssl  "} {
		if _, ok := kb.Lookup(name); !ok {
			t.Errorf("Lookup(%q) failed", name)
		}
	}
}

func TestLookupRejectsUnknownPackages(t *testing.T) {
	kb := loadKB(t)

	// A JPEG decoder is not a crypto library; classifying it as one would bury
	// the real inventory in noise.
	for _, name := range []string{"libjpeg", "zlib", "ncurses", "python3"} {
		if _, ok := kb.Lookup(name); ok {
			t.Errorf("%q was classified as a crypto library", name)
		}
	}
}

// "We do not know" is not "it does not support PQC". Collapsing the two would
// let the recommendation engine assert a fact nobody established.
func TestSupportsPQCDistinguishesUnknownFromUnsupported(t *testing.T) {
	kb := loadKB(t)

	openssl, ok := kb.Lookup("openssl")
	if !ok {
		t.Fatal("openssl missing from the knowledge base")
	}

	supported, known := openssl.SupportsPQC("3.5.0")
	if !known || !supported {
		t.Errorf("OpenSSL 3.5.0 should be known PQC-capable, got (%v,%v)", supported, known)
	}

	supported, known = openssl.SupportsPQC("1.1.1w")
	if !known || supported {
		t.Errorf("OpenSSL 1.1.1w should be known NOT PQC-capable, got (%v,%v)", supported, known)
	}

	// No version observed: the answer is "not known", never "not supported".
	supported, known = openssl.SupportsPQC("")
	if known || supported {
		t.Errorf("an unobserved version must yield (false,false), got (%v,%v)", supported, known)
	}

	// A library with no PQCSince entry: also "not known".
	sodium, ok := kb.Lookup("libsodium")
	if !ok {
		t.Fatal("libsodium missing")
	}
	if _, known := sodium.SupportsPQC("1.0.18"); known {
		t.Error("a library with no pqc_since entry must report 'not known'")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"3.5.0", "3.5.0", 0, true},
		{"3.5.1", "3.5.0", 1, true},
		{"3.4.9", "3.5.0", -1, true},
		{"3.5", "3.5.0", 0, true},
		{"v1.72", "1.72", 0, true},
		// Distro packaging suffixes must not defeat the comparison.
		{"3.0.11-1ubuntu2", "3.0.0", 1, true},
		{"1.1.1w-0+deb11u1", "3.5.0", -1, true},
		// Unparseable versions report failure rather than guessing.
		{"master", "3.5.0", 0, false},
		{"", "3.5.0", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got, ok := compareVersions(tc.a, tc.b)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// A non-numeric version must not produce a PQC claim.
func TestSupportsPQCRefusesUnparseableVersions(t *testing.T) {
	kb := loadKB(t)
	openssl, _ := kb.Lookup("openssl")

	if _, known := openssl.SupportsPQC("git-master"); known {
		t.Error("an unparseable version produced a PQC verdict")
	}
}

func TestDeprecatedPackagesAreFlagged(t *testing.T) {
	kb := loadKB(t)

	profile, ok := kb.Lookup("pycrypto")
	if !ok {
		t.Fatal("pycrypto missing from the knowledge base")
	}
	if !profile.IsDeprecated("pycrypto") {
		t.Error("pycrypto should be flagged deprecated")
	}
	if profile.IsDeprecated("pycryptodome") {
		t.Error("pycryptodome is the maintained successor and must not be flagged")
	}
}

// A malformed profile must fail at load, not silently mis-classify packages.
func TestLoadRejectsInvalidProfiles(t *testing.T) {
	cases := map[string]string{
		"no version":   `{"libraries":[{"names":["x"],"display_name":"X","citation":"c"}]}`,
		"no libraries": `{"version":"v1","libraries":[]}`,
		"no citation":  `{"version":"v1","libraries":[{"names":["x"],"display_name":"X"}]}`,
		"no names":     `{"version":"v1","libraries":[{"display_name":"X","citation":"c"}]}`,
		"malformed":    `{not json`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kb.json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := LoadKnowledgeBase(path); err == nil {
				t.Error("expected the profile to be rejected")
			}
		})
	}
}

// Two profiles claiming one package name would make classification depend on
// map ordering.
func TestLoadRejectsDuplicatePackageNames(t *testing.T) {
	content := `{"version":"v1","libraries":[
      {"names":["openssl"],"display_name":"A","citation":"c"},
      {"names":["OpenSSL"],"display_name":"B","citation":"c"}
    ]}`

	path := filepath.Join(t.TempDir(), "kb.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadKnowledgeBase(path)
	if err == nil {
		t.Fatal("duplicate package names were accepted")
	}
	if !strings.Contains(err.Error(), "claimed by both") {
		t.Errorf("unexpected error: %v", err)
	}
}

// OpenSSL's letter releases (1.1.1w, 3.0.2a) are patch-level and never add
// primitives, so they must compare equal to the bare numeric version rather
// than failing to parse -- these are the most common versions in real images.
func TestCompareVersionsHandlesLetterReleases(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.1w", "1.1.1", 0},
		{"3.0.2a", "3.0.2", 0},
		{"1.1.1w", "3.5.0", -1},
		{"3.5.0", "1.1.1w", 1},
	}

	for _, tc := range cases {
		got, ok := compareVersions(tc.a, tc.b)
		if !ok {
			t.Errorf("compare(%q,%q) failed to parse", tc.a, tc.b)
			continue
		}
		if got != tc.want {
			t.Errorf("compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// A real-world OpenSSL version from a Debian image must yield a usable verdict.
func TestOpenSSLDebianVersionResolves(t *testing.T) {
	kb := loadKB(t)
	openssl, _ := kb.Lookup("libssl1.1")

	supported, known := openssl.SupportsPQC("1.1.1w-0+deb11u1")
	if !known {
		t.Fatal("a real Debian OpenSSL version was not orderable")
	}
	if supported {
		t.Error("OpenSSL 1.1.1w was reported PQC-capable")
	}
}
