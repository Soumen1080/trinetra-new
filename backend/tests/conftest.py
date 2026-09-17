"""Shared fixtures.

The suite runs against SQLite so it needs no service to be up. The JSON columns
carry a SQLite variant for exactly this reason: schema tests that require a
running PostgreSQL get skipped in practice, and a skipped test protects nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.base import Base
from app.models.enums import (
    AssetType,
    CipherMode,
    Confidence,
    DetectionMethod,
    NistSecurityLevel,
    Primitive,
    Purpose,
    QuantumVulnerability,
    ScannerKind,
)
from app.models.tables import Scan
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact
from app.schemas.common import Evidence, SourceLocation

OBSERVED_AT = datetime(2026, 3, 14, 10, 30, tzinfo=UTC)
SCAN_TARGET = "https://git.example.org/payments-api"


@pytest.fixture
def engine():
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine) -> Iterator[Session]:
    factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with factory() as session:
        yield session


@pytest.fixture
def scan_row(session: Session) -> Scan:
    """A persisted scan, since artefacts require one via foreign key."""
    scan = Scan(
        id="scan-001",
        target_kind="git_repository",
        target_identifier=SCAN_TARGET,
        status="succeeded",
        started_at=OBSERVED_AT,
        finished_at=OBSERVED_AT,
    )
    session.add(scan)
    session.commit()
    return scan


@pytest.fixture
def evidence() -> Evidence:
    return Evidence(
        location=SourceLocation(path="svc/auth.py", line=20, symbol="issue_token"),
        detection_method=DetectionMethod.SEMGREP_PATTERN,
        confidence=Confidence.HIGH,
        snippet="cipher = AES.new(key, AES.MODE_CBC, iv)",
        rule_id="trinetra.python.aes-cbc",
    )


@pytest.fixture
def artefact(evidence: Evidence) -> CryptoArtefact:
    """A fully populated algorithm artefact, including the R19 fields."""
    return CryptoArtefact.from_evidence(
        scan_target=SCAN_TARGET,
        asset_type=AssetType.ALGORITHM,
        name="AES-128-CBC",
        evidence=[evidence],
        discovered_by=ScannerKind.SOURCE,
        observed_at=OBSERVED_AT,
        algorithm="aes",
        primitive=Primitive.BLOCK_CIPHER,
        purposes=[Purpose.ENCRYPTION],
        quantum_vulnerability=QuantumVulnerability.GROVER_WEAKENED,
        nist_security_level=NistSecurityLevel.LEVEL_1,
        detail=AlgorithmDetail(mode=CipherMode.CBC, key_size_bits=128),
    )
