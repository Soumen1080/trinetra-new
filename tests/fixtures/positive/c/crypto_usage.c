/* Positive fixture for the OpenSSL C detectors (not covered by CBOMkit). */
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>

/* Expect MD5. */
void legacy_digest(MD5_CTX *ctx) { MD5_Init(ctx); }

/* Expect RSA-2048, key size carried through message interpolation. */
RSA *make_rsa(void) { return RSA_generate_key(2048, RSA_F4, NULL, NULL); }

/* Expect AES. */
const EVP_CIPHER *aes_cipher(void) { return EVP_aes_256_gcm(); }
