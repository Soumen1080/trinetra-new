package negative

// Negative fixture: MUST produce zero findings.

// Identifiers that look like crypto but are plain values.
var (
	md5  = "label"
	aes  = 256
	rsa  = struct{ Bits int }{Bits: 2048}
	sha1 = false
)

// Commented-out real calls:
//   md5.New()
//   rsa.GenerateKey(rand.Reader, 2048)
//   aes.NewCipher(key)

// Describe returns prose, not ciphertext.
func Describe() string {
	return "This service documents RSA and AES but calls neither."
}
