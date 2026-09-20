"""Tests for security hardening: redaction, snippet sanitization, and security headers."""

from __future__ import annotations

import logging
from io import StringIO
from starlette.testclient import TestClient

from app.api.main import create_app
from app.services.security import (
    RedactingFormatter,
    redact_secrets,
    sanitize_evidence_snippet,
)


def test_redact_private_key() -> None:
    sample_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+mP7Xy...fakekeymaterial...12345\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = redact_secrets(f"Loaded key: {sample_key} for server")
    assert "[REDACTED_PRIVATE_KEY]" in result
    assert "MIIEowIBAAKCAQEA0Y1+mP7Xy" not in result


def test_redact_aws_credentials() -> None:
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE and some secret"
    result = redact_secrets(text)
    assert "[REDACTED_AWS_KEY]" in result
    assert "AKIAIOSFODNN7EXAMPLE" not in result


def test_redact_jwt() -> None:
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    text = f"User authenticated with {token}"
    result = redact_secrets(text)
    assert "[REDACTED_JWT]" in result
    assert "doNotLeakThisSignature" not in result


def test_redacting_formatter() -> None:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter("%(levelname)s: %(message)s"))

    logger = logging.getLogger("test_redact")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    secret_msg = "Client token is Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    logger.info(secret_msg)

    logged = stream.getvalue()
    assert "Bearer [REDACTED_BEARER_TOKEN]" in logged
    assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" not in logged


def test_sanitize_evidence_snippet() -> None:
    snippet = "private_key = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----'\nencrypt(data)"
    sanitized = sanitize_evidence_snippet(snippet)
    assert "[REDACTED_PRIVATE_KEY]" in sanitized
    assert "MIGHAgEAMBMGByqGSM49" not in sanitized
    assert "encrypt(data)" in sanitized


def test_security_headers_present() -> None:
    app = create_app()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in response.headers
    assert "Content-Security-Policy" in response.headers
