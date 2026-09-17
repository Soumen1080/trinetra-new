package positive

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
)

// WeakRSA is expected to be detected as RSA-2048.
func WeakRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// LegacyDigests is expected to yield MD5 and SHA1 findings.
func LegacyDigests(data []byte) ([16]byte, [20]byte) {
	return md5.Sum(data), sha1.Sum(data)
}

// NewAES is expected to yield an AES finding with no key size stated.
func NewAES(key []byte) (interface{}, error) {
	return aes.NewCipher(key)
}

// NewECDSA is expected to yield an ECDSA finding.
func NewECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
