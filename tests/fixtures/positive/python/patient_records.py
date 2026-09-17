"""Positive fixture for taint analysis: PII reaching a crypto sink.

This file deliberately BOTH constructs a cipher and feeds PII into it, because
that is what real code does. The taint rules must attach a data-category to the
crypto artefact discovered in the same file -- that link is what gives Mosca's X
its scanner-evidence tier.
"""
import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


class Patient:
    def __init__(self, aadhaar_number, medical_record_id):
        self.aadhaar_number = aadhaar_number
        self.medical_record_id = medical_record_id


def build_cipher(key, iv):
    # Expect: AES-CBC, in the same file as the PII flow below, so the artefact
    # should carry trinetra:data-category.
    return AES.new(key, AES.MODE_CBC, iv)


def wrapping_key():
    # Expect: RSA-2048 protecting long-lived health data.
    return RSA.generate(2048)


def protect(patient, key, iv):
    # Expect: trinetra:data-category=aadhaar_pii via a genuine source->sink path.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(patient.aadhaar_number)


def protect_records(patient, key, iv):
    # Expect: health_record.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(patient.medical_record_id)


def fingerprint(patient):
    # Expect: SHA-256 over a record identifier.
    return hashlib.sha256(patient.medical_record_id.encode()).hexdigest()
