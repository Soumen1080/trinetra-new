"""Positive fixture: real cryptographic API calls that MUST be detected."""
import hashlib

from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def weak_rsa():
    # Expect: RSA-1024, key size resolved through message interpolation.
    return RSA.generate(1024)


def rsa_via_cryptography():
    # Expect: RSA-2048.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def aes_cbc(key, iv):
    # Expect: AES-CBC. The key size is NOT stated here, so the finding must
    # carry no key size and degrade to NEEDS_CONTEXT rather than guessing.
    return AES.new(key, AES.MODE_CBC, iv)


def aes_gcm(key):
    # Expect: AES-GCM, again with no key size.
    return AES.new(key, AES.MODE_GCM)


def legacy_digest(data):
    # Expect: MD5 and SHA1, both classically broken.
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()


def modern_digest(data):
    # Expect: SHA256.
    return hashlib.sha256(data).hexdigest()


def ec_key():
    # Expect: ECDSA with curve SECP256R1.
    return ec.generate_private_key(ec.SECP256R1())


def triple_des(key):
    # Expect: 3DES.
    return DES3.new(key, DES3.MODE_CBC)
