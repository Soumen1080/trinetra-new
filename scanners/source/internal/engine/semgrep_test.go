package engine

import (
	"testing"

	"github.com/trinetra/cbom-go/cbom"
)

// The message-interpolation contract: Semgrep OSS emits no metavars field, so
// the message is the only channel that can carry a key size back. These tests
// pin the parser that reads it back out.
func TestParseMessageCaptures(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    map[string]string
	}{
		{
			name:    "key size",
			message: "RSA key generation. trinetra:key_size=2048",
			want:    map[string]string{"key_size": "2048"},
		},
		{
			name:    "mode",
			message: "AES cipher construction. trinetra:mode=MODE_CBC",
			want:    map[string]string{"mode": "MODE_CBC"},
		},
		{
			name:    "transformation with slashes",
			message: "JCA cipher. trinetra:transformation=AES/GCM/NoPadding",
			want:    map[string]string{"transformation": "AES/GCM/NoPadding"},
		},
		{
			name:    "multiple captures",
			message: "x trinetra:key_size=256 y trinetra:mode=gcm",
			want:    map[string]string{"key_size": "256", "mode": "gcm"},
		},
		{
			name:    "quoted value is unwrapped",
			message: `trinetra:algorithm="MD5"`,
			want:    map[string]string{"algorithm": "MD5"},
		},
		{
			// An unresolved metavariable arrives literally. Storing it would
			// fabricate a key size out of the string "$BITS".
			name:    "unresolved metavariable is discarded",
			message: "RSA key generation. trinetra:key_size=$BITS",
			want:    map[string]string{},
		},
		{
			name:    "no captures",
			message: "MD5 hash in use.",
			want:    map[string]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMessageCaptures(tc.message)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("capture[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestApplyTransformation(t *testing.T) {
	cases := []struct {
		transform   string
		wantAlgo    string
		wantMode    string
		wantPadding string
		wantSize    int // 0 means none observed
	}{
		{"AES/CBC/PKCS5Padding", "aes", "cbc", "pkcs7", 0},
		{"AES/GCM/NoPadding", "aes", "gcm", "none", 0},
		{"AES/ECB/PKCS5Padding", "aes", "ecb", "pkcs7", 0},
		{"RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "rsa", "ecb", "oaep", 0},
		// Node-style names carry the size in the algorithm string.
		{"aes-256-cbc", "aes", "cbc", "", 256},
		{"aes-128-gcm", "aes", "gcm", "", 128},
	}

	for _, tc := range cases {
		t.Run(tc.transform, func(t *testing.T) {
			var f cbom.Finding
			applyTransformation(&f, tc.transform)

			if f.Algorithm != tc.wantAlgo {
				t.Errorf("algorithm = %q, want %q", f.Algorithm, tc.wantAlgo)
			}
			if f.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", f.Mode, tc.wantMode)
			}
			if f.Padding != tc.wantPadding {
				t.Errorf("padding = %q, want %q", f.Padding, tc.wantPadding)
			}
			size, ok := f.KeySize()
			if tc.wantSize == 0 {
				if ok {
					t.Errorf("key size %d reported but none was stated", size)
				}
			} else if !ok || size != tc.wantSize {
				t.Errorf("key size = %d (%v), want %d", size, ok, tc.wantSize)
			}
		})
	}
}

// "AES" alone is not an answer; "AES-128-CBC" is. This is R19.
func TestDeriveName(t *testing.T) {
	cases := []struct {
		name string
		in   cbom.Finding
		want string
	}{
		{
			name: "algorithm with size and mode",
			in:   cbom.Finding{Algorithm: "aes", KeySizeBits: cbom.IntPtr(128), Mode: "cbc"},
			want: "AES-128-CBC",
		},
		{
			name: "algorithm with size only",
			in:   cbom.Finding{Algorithm: "rsa", KeySizeBits: cbom.IntPtr(2048)},
			want: "RSA-2048",
		},
		{
			// The honest name when the call site did not state a size.
			name: "mode without size",
			in:   cbom.Finding{Algorithm: "aes", Mode: "gcm"},
			want: "AES-GCM",
		},
		{
			name: "curve",
			in:   cbom.Finding{Algorithm: "ecdsa", Curve: "SECP256R1"},
			want: "ECDSA-SECP256R1",
		},
		{
			name: "bare algorithm",
			in:   cbom.Finding{Algorithm: "md5"},
			want: "MD5",
		},
		{
			name: "no algorithm yields no name",
			in:   cbom.Finding{},
			want: "",
		},
		{
			// "other" carries no information and must not pollute the name.
			name: "unknown mode is omitted",
			in:   cbom.Finding{Algorithm: "aes", Mode: "other"},
			want: "AES",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveName(tc.in); got != tc.want {
				t.Errorf("deriveName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormaliseMode(t *testing.T) {
	cases := map[string]string{
		"MODE_CBC": "cbc",
		"MODE_GCM": "gcm",
		"cbc":      "cbc",
		"ECB":      "ecb",
		"":         "",
		"WEIRD":    "other",
	}
	for in, want := range cases {
		if got := normaliseMode(in); got != want {
			t.Errorf("normaliseMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// A rule without trinetra metadata is not a Trinetra rule. Inventing a finding
// from one would let an arbitrary third-party rule pack inject artefacts.
func TestRulesWithoutTrinetraMetadataAreIgnored(t *testing.T) {
	e := NewSemgrepEngine(nil)
	result := e.adapt("/root", semgrepOutput{
		Results: []semgrepResult{{
			CheckID: "some.third.party.rule",
			Path:    "/root/svc/auth.py",
		}},
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}

// Semgrep exits non-zero when findings exist, so exit status alone cannot
// distinguish success from failure. Parseable JSON is the real signal.
func TestParseSemgrepOutputRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"", "   ", "not json", "{unclosed"} {
		if _, err := parseSemgrepOutput([]byte(raw)); err == nil {
			t.Errorf("expected an error for %q", raw)
		}
	}
}

func TestParseSemgrepOutputAcceptsEmptyResults(t *testing.T) {
	// A repository genuinely free of cryptography is a valid result.
	out, err := parseSemgrepOutput([]byte(`{"results":[],"errors":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("expected no results, got %d", len(out.Results))
	}
}

// Errors from a tool become coverage gaps: a file the scanner could not parse
// is a hole in the inventory, and the user must be able to see it.
func TestSemgrepErrorsBecomeCoverageGaps(t *testing.T) {
	e := NewSemgrepEngine(nil)
	result := e.adapt("/root", semgrepOutput{
		Errors: []semgrepError{{
			Message: "Syntax error at line 12",
			Path:    "/root/svc/broken.py",
			Level:   "warn",
		}},
	})

	if len(result.Gaps) != 1 {
		t.Fatalf("expected one gap, got %d", len(result.Gaps))
	}
	if result.Gaps[0].Kind != "unparseable" {
		t.Errorf("gap kind = %q, want unparseable", result.Gaps[0].Kind)
	}
}

// Evidence must never carry a host path.
func TestSanitiseErrorTruncatesAndCollapses(t *testing.T) {
	got := sanitiseError("first line\nsecond line with detail")
	if got != "first line" {
		t.Errorf("sanitiseError kept more than the first line: %q", got)
	}
	if sanitiseError("") != "the file could not be parsed" {
		t.Error("an empty message should produce a usable fallback")
	}
}

func TestTruncateSnippetIsBounded(t *testing.T) {
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'x'
	}
	if got := truncateSnippet(string(long)); len(got) > 520 {
		t.Errorf("snippet not bounded: %d chars", len(got))
	}
}

// Taint evidence must attach to the artefacts it describes, and never invent a
// category for a file that produced none.
func TestApplyDataCategories(t *testing.T) {
	findings := []cbom.Finding{
		{Name: "AES-CBC", Location: cbom.Location{Path: "svc/patient.py", Line: 30}},
		{Name: "SHA-256", Location: cbom.Location{Path: "svc/patient.py", Line: 44}},
		{Name: "MD5", Location: cbom.Location{Path: "svc/other.py", Line: 3}},
	}
	annotations := []cbom.Finding{
		{DataCategory: "aadhaar_pii", Location: cbom.Location{Path: "svc/patient.py", Line: 32}},
		{DataCategory: "health_record", Location: cbom.Location{Path: "svc/patient.py", Line: 38}},
	}

	got := applyDataCategories(findings, annotations)

	// Several categories in one file are all carried; Track A's precedence rule
	// decides which governs, and that decision is the risk engine's, not ours.
	if got[0].DataCategory != "aadhaar_pii,health_record" {
		t.Errorf("categories = %q, want aadhaar_pii,health_record", got[0].DataCategory)
	}
	if got[1].DataCategory != "aadhaar_pii,health_record" {
		t.Errorf("second finding in the same file missed the categories: %q", got[1].DataCategory)
	}
	// A file with no taint evidence must stay empty rather than inherit.
	if got[2].DataCategory != "" {
		t.Errorf("a file with no taint evidence was given category %q", got[2].DataCategory)
	}
}

func TestApplyDataCategoriesNeverOverwrites(t *testing.T) {
	findings := []cbom.Finding{{
		Name:         "AES-CBC",
		DataCategory: "payment_card",
		Location:     cbom.Location{Path: "a.py", Line: 1},
	}}
	annotations := []cbom.Finding{{
		DataCategory: "aadhaar_pii",
		Location:     cbom.Location{Path: "a.py", Line: 2},
	}}

	got := applyDataCategories(findings, annotations)
	if got[0].DataCategory != "payment_card" {
		t.Errorf("an already-resolved category was overwritten: %q", got[0].DataCategory)
	}
}

func TestApplyDataCategoriesIsDeterministic(t *testing.T) {
	findings := []cbom.Finding{{Name: "AES", Location: cbom.Location{Path: "a.py"}}}

	forward := applyDataCategories(slicesClone(findings), []cbom.Finding{
		{DataCategory: "zeta", Location: cbom.Location{Path: "a.py"}},
		{DataCategory: "alpha", Location: cbom.Location{Path: "a.py"}},
	})
	reverse := applyDataCategories(slicesClone(findings), []cbom.Finding{
		{DataCategory: "alpha", Location: cbom.Location{Path: "a.py"}},
		{DataCategory: "zeta", Location: cbom.Location{Path: "a.py"}},
	})

	if forward[0].DataCategory != reverse[0].DataCategory {
		t.Errorf("annotation order changed the result: %q vs %q",
			forward[0].DataCategory, reverse[0].DataCategory)
	}
}

func slicesClone(in []cbom.Finding) []cbom.Finding {
	out := make([]cbom.Finding, len(in))
	copy(out, in)
	return out
}
