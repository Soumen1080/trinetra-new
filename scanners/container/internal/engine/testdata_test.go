package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Fixtures are generated rather than committed, for two reasons: a committed
// private key in a repository is exactly the finding this scanner exists to
// report, and generating them proves the parser handles real DER rather than a
// hand-copied blob.

// writeRSACertificate writes a self-signed RSA certificate and its private key.
func writeRSACertificate(t *testing.T, dir string, bits int) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "payments.example.org",
			Organization: []string{"Example"},
		},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{"payments.example.org"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "server.crt")
	writePEM(t, certPath, "CERTIFICATE", der)

	keyPath = filepath.Join(dir, "server.key")
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))

	return certPath, keyPath
}

// writeECCertificate writes a self-signed P-256 certificate.
func writeECCertificate(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "internal-ca.example.org"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(dir, "ca.pem")
	writePEM(t, path, "CERTIFICATE", der)
	return path
}

// writePublicKey writes a standalone PKIX public key.
func writePublicKey(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	path := filepath.Join(dir, "signing.pub")
	writePEM(t, path, "PUBLIC KEY", der)
	return path
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// nginxConfig declares a weak TLS floor and a strong one, plus a commented
// directive that must NOT be detected.
const nginxConfig = `
server {
    listen 443 ssl;
    server_name payments.example.org;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

    # ssl_protocols TLSv1.0 TLSv1.1;
    # This line is commented out and must not produce a finding.

    ssl_certificate /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
}
`

// legacyConfig declares protocols that are findings in their own right.
const legacyConfig = `
[system_default_sect]
MinProtocol = TLSv1.0
CipherString = DEFAULT@SECLEVEL=1
`

const sshdConfig = `
Port 22
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1
HostKeyAlgorithms ssh-rsa,rsa-sha2-512
Ciphers aes128-ctr,aes256-ctr
# Ciphers 3des-cbc
`

// cleanConfig performs no cryptography and must yield zero findings.
const cleanConfig = `
server {
    listen 80;
    server_name example.org;
    root /var/www/html;
    # We used to have ssl_protocols TLSv1.0 here, but it was removed.
}
`
