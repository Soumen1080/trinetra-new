package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/trinetra/cbom-go/cbom"
)

// PKIEngine finds certificates and key material on a filesystem (R3, R2).
//
// This is what cbomkit-theia contributes when it is installed. Go's crypto/x509
// is the same parser theia uses, so the engine is written here rather than left
// as a hole: an inventory that cannot see the certificate a service presents is
// missing the artefact most likely to be quantum-vulnerable today.
//
// **Trinetra stores no secret material.** A private key yields a finding with a
// fingerprint and a redaction flag, never the key itself. That is not a
// convention here -- it is enforced by never reading the key bytes into a
// finding in the first place.
type PKIEngine struct {
	// MaxFileBytes bounds what is read. A multi-gigabyte file is not a
	// certificate, and reading one would stall a scan.
	MaxFileBytes int64
	// MaxFiles bounds directory traversal.
	MaxFiles int
}

// NewPKIEngine returns an engine with sensible bounds.
func NewPKIEngine() *PKIEngine {
	return &PKIEngine{MaxFileBytes: 4 << 20, MaxFiles: 50_000}
}

func (e *PKIEngine) Name() string { return "pki" }

// SupportsImages is false: this engine reads a filesystem. Image layers are
// unpacked by the container runtime path, and until that exists an image target
// is reported as a gap rather than silently yielding no certificates.
func (e *PKIEngine) SupportsImages() bool { return false }

func (e *PKIEngine) Detects() []string {
	return []string{"x509 certificates", "public keys", "private key material"}
}

func (e *PKIEngine) Tool() cbom.Tool {
	return cbom.Tool{
		Vendor:  "Trinetra",
		Name:    "pki-scanner",
		Version: ScannerVersion,
		Licence: "Apache-2.0",
	}
}

func (e *PKIEngine) Available(context.Context) error { return nil }

// pemExtensions are the files worth opening. Scanning every file for a PEM
// header would read whole container filesystems for a handful of hits.
var pemExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".der": true,
	".key": true, ".p12": true, ".pfx": true, ".jks": true,
	".keystore": true, ".truststore": true, ".pub": true, ".csr": true,
}

// Scan walks the target directory for certificates and keys.
func (e *PKIEngine) Scan(ctx context.Context, target Target) (Result, error) {
	if target.Path == "" {
		return Result{}, fmt.Errorf("pki engine requires a filesystem path")
	}

	var result Result
	seen := 0

	walkErr := filepath.WalkDir(target.Path, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// An unreadable directory is a coverage gap, not a scan failure.
			result.Gaps = append(result.Gaps, Gap{
				Path:   relativeOrBase(target.Path, path),
				Kind:   "permission_denied",
				Reason: "the path could not be read",
				Count:  1,
			})
			return nil
		}
		if entry.IsDir() {
			return nil
		}

		seen++
		if seen > e.MaxFiles {
			return filepath.SkipAll
		}

		extension := strings.ToLower(filepath.Ext(path))
		if !pemExtensions[extension] {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if info.Size() > e.MaxFileBytes {
			result.Gaps = append(result.Gaps, Gap{
				Path:   relativeOrBase(target.Path, path),
				Kind:   "too_large",
				Reason: fmt.Sprintf("file exceeds the %d byte scan limit", e.MaxFileBytes),
				Count:  1,
			})
			return nil
		}

		result.FilesScanned++

		findings, gaps := e.inspectFile(target.Path, path)
		result.Findings = append(result.Findings, findings...)
		result.Gaps = append(result.Gaps, gaps...)
		return nil
	})

	if walkErr != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

// inspectFile parses every PEM block in a file.
func (e *PKIEngine) inspectFile(root, path string) ([]cbom.Finding, []Gap) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, []Gap{{
			Path:   relativeOrBase(root, path),
			Kind:   "permission_denied",
			Reason: "the file could not be read",
			Count:  1,
		}}
	}

	location := relativeOrBase(root, path)

	// DER files carry a single binary certificate with no PEM armour.
	if strings.EqualFold(filepath.Ext(path), ".der") {
		if finding, ok := certificateFinding(raw, location, 0); ok {
			return []cbom.Finding{finding}, nil
		}
		return nil, nil
	}

	var (
		findings []cbom.Finding
		gaps     []Gap
		rest     = raw
		index    int
	)

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		finding, ok := e.blockToFinding(block, location, index)
		if ok {
			findings = append(findings, finding)
		}
		index++
	}

	// A keystore is real key material Trinetra cannot open without a password.
	// Reporting the gap is the honest outcome; silently skipping it would make
	// a keystore-bearing image look clean.
	if isKeystore(path) && len(findings) == 0 {
		gaps = append(gaps, Gap{
			Path:   location,
			Kind:   "unparseable",
			Reason: "keystore is password-protected and was not opened; its contents are not inventoried",
			Count:  1,
		})
	}

	return findings, gaps
}

func (e *PKIEngine) blockToFinding(block *pem.Block, location string, index int) (cbom.Finding, bool) {
	switch {
	case strings.Contains(block.Type, "CERTIFICATE REQUEST"):
		return cbom.Finding{}, false

	case block.Type == "CERTIFICATE":
		return certificateFinding(block.Bytes, location, index)

	case strings.Contains(block.Type, "PRIVATE KEY"):
		return privateKeyFinding(block, location, index)

	case strings.Contains(block.Type, "PUBLIC KEY"):
		return publicKeyFinding(block, location, index)

	default:
		return cbom.Finding{}, false
	}
}

// certificateFinding parses a certificate into an artefact.
//
// Signature algorithm and public-key algorithm are kept SEPARATE, because they
// carry different risk: a quantum-vulnerable signature is an authenticity
// problem that matters at CRQC time, while a vulnerable public key is a
// confidentiality problem that is retroactive. Collapsing them into one
// "algorithm" field would lose that distinction before the risk engine sees it.
func certificateFinding(der []byte, location string, index int) (cbom.Finding, bool) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return cbom.Finding{}, false
	}

	algorithm, keySize, curve := describePublicKey(certificate.PublicKey)

	finding := cbom.Finding{
		AssetType:       cbom.AssetCertificate,
		Name:            certificateName(certificate),
		Algorithm:       algorithm,
		Curve:           curve,
		DetectionMethod: cbom.DetectCertificate,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "pki:x509",
		Location:        cbom.Location{Path: location, Line: index + 1},
		Snippet:         describeCertificate(certificate),
	}
	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}

	return finding.Normalise(), true
}

// privateKeyFinding records that key material exists, never what it is.
func privateKeyFinding(block *pem.Block, location string, index int) (cbom.Finding, bool) {
	algorithm, keySize, curve := describePrivateKey(block)

	finding := cbom.Finding{
		AssetType:       cbom.AssetKey,
		Name:            keyName(block.Type, algorithm, keySize),
		Algorithm:       algorithm,
		Curve:           curve,
		DetectionMethod: cbom.DetectCertificate,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "pki:private-key",
		Location:        cbom.Location{Path: location, Line: index + 1},
		// The snippet describes the finding; it never contains the key. The
		// flag tells the UI and the report that material was withheld rather
		// than absent.
		Snippet:  "private key material present in the filesystem; contents withheld",
		Redacted: true,
	}
	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}

	return finding.Normalise(), true
}

func publicKeyFinding(block *pem.Block, location string, index int) (cbom.Finding, bool) {
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return cbom.Finding{}, false
	}

	algorithm, keySize, curve := describePublicKey(key)

	finding := cbom.Finding{
		AssetType:       cbom.AssetKey,
		Name:            keyName(block.Type, algorithm, keySize),
		Algorithm:       algorithm,
		Curve:           curve,
		DetectionMethod: cbom.DetectCertificate,
		Confidence:      cbom.ConfidenceHigh,
		RuleID:          "pki:public-key",
		Location:        cbom.Location{Path: location, Line: index + 1},
		Snippet:         "public key; fingerprint " + fingerprint(block.Bytes),
	}
	if keySize > 0 {
		finding.KeySizeBits = cbom.IntPtr(keySize)
	}

	return finding.Normalise(), true
}

// describePublicKey extracts algorithm, size and curve without touching secrets.
func describePublicKey(key any) (algorithm string, keySize int, curve string) {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return "rsa", typed.N.BitLen(), ""
	case *ecdsa.PublicKey:
		if typed.Curve != nil && typed.Curve.Params() != nil {
			return "ecdsa", typed.Curve.Params().BitSize, typed.Curve.Params().Name
		}
		return "ecdsa", 0, ""
	case ed25519.PublicKey:
		return "ed25519", 255, "Ed25519"
	default:
		// An unrecognised key type is reported without an algorithm rather
		// than guessed at: "unknown" is honest, a wrong name is not.
		return "", 0, ""
	}
}

// describePrivateKey reads only the parameters, never the secret scalar.
func describePrivateKey(block *pem.Block) (algorithm string, keySize int, curve string) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return "rsa", key.N.BitLen(), ""
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		if key.Curve != nil && key.Curve.Params() != nil {
			return "ecdsa", key.Curve.Params().BitSize, key.Curve.Params().Name
		}
		return "ecdsa", 0, ""
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch typed := parsed.(type) {
		case *rsa.PrivateKey:
			return "rsa", typed.N.BitLen(), ""
		case *ecdsa.PrivateKey:
			if typed.Curve != nil && typed.Curve.Params() != nil {
				return "ecdsa", typed.Curve.Params().BitSize, typed.Curve.Params().Name
			}
			return "ecdsa", 0, ""
		case ed25519.PrivateKey:
			return "ed25519", 255, "Ed25519"
		}
	}

	// An encrypted key block cannot be parsed, and that is fine: its presence
	// is the finding, and the parameters stay unobserved (P3).
	return "", 0, ""
}

func certificateName(certificate *x509.Certificate) string {
	subject := strings.TrimSpace(certificate.Subject.CommonName)
	if subject == "" && len(certificate.DNSNames) > 0 {
		subject = certificate.DNSNames[0]
	}
	if subject == "" {
		subject = strings.TrimSpace(certificate.Subject.String())
	}
	if subject == "" {
		return "X.509 certificate"
	}
	return subject
}

// describeCertificate is the evidence note. It carries the facts a reviewer
// needs -- issuer, validity, both algorithms -- in one line.
func describeCertificate(certificate *x509.Certificate) string {
	parts := []string{
		"issuer " + certificate.Issuer.CommonName,
		"not_before " + certificate.NotBefore.UTC().Format("2006-01-02"),
		"not_after " + certificate.NotAfter.UTC().Format("2006-01-02"),
		"signature " + certificate.SignatureAlgorithm.String(),
		"public_key " + certificate.PublicKeyAlgorithm.String(),
	}
	if certificate.IsCA {
		parts = append(parts, "CA")
	}
	if isSelfSigned(certificate) {
		parts = append(parts, "self-signed")
	}
	parts = append(parts, "fingerprint "+fingerprint(certificate.Raw))
	return strings.Join(parts, "; ")
}

func isSelfSigned(certificate *x509.Certificate) bool {
	return certificate.Subject.String() == certificate.Issuer.String()
}

func keyName(blockType, algorithm string, keySize int) string {
	name := strings.ToUpper(algorithm)
	if name == "" {
		name = strings.TrimSpace(strings.ReplaceAll(blockType, "ENCRYPTED ", ""))
		if name == "" {
			name = "key"
		}
	}
	if keySize > 0 {
		return fmt.Sprintf("%s-%d", name, keySize)
	}
	return name
}

// fingerprint identifies key material without disclosing it.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])[:32]
}

func isKeystore(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p12", ".pfx", ".jks", ".keystore", ".truststore":
		return true
	default:
		return false
	}
}

// relativeOrBase keeps evidence free of host paths.
func relativeOrBase(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(path)
}
