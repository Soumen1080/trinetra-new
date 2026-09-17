"""Negative fixture: MUST produce zero findings.

Every construct here mentions cryptography without performing any. A rule that
matches bare identifiers rather than call expressions will fire on these, which
is exactly the failure this fixture exists to catch.
"""

# A variable that merely shares a name with an algorithm.
rsa = "some string"
aes = "another string"
md5 = None
sha1 = 42

# A dictionary whose keys look like algorithms.
config = {"rsa": 2048, "aes": 256, "md5": True}

# Comments that name crypto but call nothing:
# RSA.generate(1024)
# hashlib.md5(data)
# AES.new(key, AES.MODE_ECB)

DOCUMENTATION = """
This module used to call RSA.generate(2048) and hashlib.md5(payload),
but that code was removed. Mentioning it in a docstring is not a use.
"""


def describe():
    """Return prose about algorithms without invoking any."""
    return "We support RSA, AES and SHA-256 in our documentation only."


class RSAConfigPlaceholder:
    """A class named after an algorithm that implements none of it."""

    md5 = "not a call"
    aes_mode = "MODE_CBC"
