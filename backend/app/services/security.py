"""Security hardening: secret redaction, snippet sanitization, and security headers.

Ensures sensitive material (private keys, API tokens, cloud credentials) is never
leaked into application logs, database evidence snippets, or HTTP responses.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from collections.abc import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Common secret regex patterns
REDACTION_PATTERNS = [
    # PEM Private Keys
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # AWS Access Key ID
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Access Key assignment
    (
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        r"aws_secret_access_key=[REDACTED_AWS_SECRET]",
    ),
    # JWT Tokens
    (
        re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b"),
        "[REDACTED_JWT]",
    ),
    # Authorization: Bearer
    (
        re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{16,}", re.IGNORECASE),
        "Bearer [REDACTED_BEARER_TOKEN]",
    ),
    # Generic API Key / Secret assignments
    (
        re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|password|secret|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-.~+/=]{16,}['\"]"
        ),
        r"\1=[REDACTED_SECRET]",
    ),
    # GCP private_key in service account JSON
    (
        re.compile(r'"private_key":\s*"-----BEGIN PRIVATE KEY[^"]+"'),
        '"private_key": "[REDACTED_GCP_PRIVATE_KEY]"',
    ),
]


def redact_secrets(text: str) -> str:
    """Scrub known secret formats from a string."""
    if not text:
        return text
    scrubbed = text
    for pattern, replacement in REDACTION_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


def sanitize_evidence_snippet(snippet: str | None) -> str | None:
    """Sanitize code evidence snippets before persisting to the database.

    Removes private keys, cloud tokens, and sensitive credential assignments
    while keeping the line structure intact for UI display.
    """
    if not snippet:
        return snippet
    return redact_secrets(snippet)


class RedactingFormatter(logging.Formatter):
    """Logging formatter that scrubs credentials from log outputs."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_secrets(original)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard security response headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
        )
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


__all__ = [
    "RedactingFormatter",
    "SecurityHeadersMiddleware",
    "redact_secrets",
    "sanitize_evidence_snippet",
]
