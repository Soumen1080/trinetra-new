"""Content-hash caching and incremental rescan support.

When a scan target's content has not changed (determined by sha256 content hash),
re-running the scanner is redundant. ArtefactCache identifies identical prior
scans, allowing instantaneous completion by reusing verified findings.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import tables
from app.models.base import utcnow
from app.models.enums import ScanStatus


def compute_content_hash(data: str | bytes | Path) -> str:
    """Compute sha256 digest of string, bytes, or file contents."""
    hasher = hashlib.sha256()
    if isinstance(data, Path):
        with open(data, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    else:
        hasher.update(data)
    return hasher.hexdigest()


def cache_key(target_identifier: str, scanner_kind: str, content_hash: str) -> str:
    """Generate a deterministic cache key."""
    composite = f"{target_identifier}:{scanner_kind}:{content_hash}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


class ArtefactCache:
    """Query and clone cached scan artefacts."""

    @staticmethod
    def find_cached_scan(
        session: Session,
        *,
        target_identifier: str,
        content_hash: str,
    ) -> tables.Scan | None:
        """Find the latest succeeded scan with the matching target and content_hash."""
        if not content_hash:
            return None
        stmt = (
            select(tables.Scan)
            .where(
                tables.Scan.target_identifier == target_identifier,
                tables.Scan.content_hash == content_hash,
                tables.Scan.status.in_([ScanStatus.SUCCEEDED.value, ScanStatus.PARTIAL.value]),
            )
            .order_by(tables.Scan.created_at.desc())
            .limit(1)
        )
        return session.scalar(stmt)

    @staticmethod
    def clone_artefacts(
        session: Session,
        *,
        source_scan_id: str,
        target_scan_id: str,
    ) -> int:
        """Clone all artefacts from source_scan to target_scan.

        Returns count of cloned artefacts.
        """
        source_artefacts = session.scalars(
            select(tables.Artefact).where(tables.Artefact.scan_id == source_scan_id)
        ).all()

        cloned_count = 0
        for src in source_artefacts:
            cloned = tables.Artefact(
                id=str(uuid.uuid4()),
                scan_id=target_scan_id,
                application_id=src.application_id,
                type=src.type,
                name=src.name,
                algorithm=src.algorithm,
                oid=src.oid,
                primitive=src.primitive,
                purpose=src.purpose,
                key_size_bits=src.key_size_bits,
                size_or_version=src.size_or_version,
                mode=src.mode,
                padding=src.padding,
                curve=src.curve,
                quantum_vulnerability=src.quantum_vulnerability,
                nist_security_level=src.nist_security_level,
                location=src.location,
                used_for=src.used_for,
                observed_data_category=src.observed_data_category,
                discovered_by=src.discovered_by,
                detail_json=src.detail_json,
                evidence_json=src.evidence_json,
                raw_cbom=src.raw_cbom,
                first_seen=src.first_seen,
                last_seen=utcnow(),
            )
            session.add(cloned)
            cloned_count += 1

        return cloned_count


__all__ = ["ArtefactCache", "cache_key", "compute_content_hash"]
