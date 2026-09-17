"""Positive fixture for taint analysis: PII reaching a crypto sink."""
from Crypto.Cipher import AES


class Patient:
    def __init__(self, aadhaar_number, medical_record_id):
        self.aadhaar_number = aadhaar_number
        self.medical_record_id = medical_record_id


def protect(patient, cipher):
    # Expect: trinetra:data-category=aadhaar_pii via a genuine source->sink path.
    return cipher.encrypt(patient.aadhaar_number)


def protect_records(patient, cipher):
    # Expect: health_record.
    return cipher.encrypt(patient.medical_record_id)
