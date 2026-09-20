"""Performance benchmarks and incremental rescan verification."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.database import initialise_database
from app.models import tables
from app.models.enums import ScanStatus, ScanTargetKind
from app.services.cbom_ingest import ingest_document
from app.services.scan_orchestrator import ScannerResponse, execute_scan


def _generate_synthetic_cbom(component_count: int) -> dict[str, Any]:
    components = []
    for i in range(component_count):
        components.append(
            {
                "type": "cryptographic-asset",
                "name": f"AES-256-GCM-{i}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "block-cipher",
                        "parameterSetIdentifier": "256",
                        "mode": "gcm",
                    },
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": f"src/module_{i % 50}/crypto.py",
                            "line": (i % 200) + 1,
                        }
                    ]
                },
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-09-20T00:00:00Z",
            "tools": [{"vendor": "Trinetra", "name": "bench", "version": "1.0"}],
        },
        "components": components,
    }


def test_large_cbom_ingest_performance() -> None:
    # 5,000 components ingested in under 10 seconds
    count = 5000
    cbom = _generate_synthetic_cbom(count)

    start = time.monotonic()
    result = ingest_document(cbom, scan_target="bench-repo")
    elapsed = time.monotonic() - start

    assert len(result.artefacts) == count
    assert elapsed < 10.0, f"Ingest took {elapsed:.2f}s, expected < 10.0s"


class MockGateway:
    def __init__(self, artifact_ref: str) -> None:
        self.artifact_ref = artifact_ref
        self.call_count = 0

    def scan(self, *, endpoint: str, scan_id: str, target_reference: str) -> ScannerResponse:
        self.call_count += 1
        return ScannerResponse(
            artifact_reference=self.artifact_ref,
            finding_count=10,
            scanner_version="1.0.0",
        )


def test_incremental_rescan_reuses_cache(tmp_path: Path, monkeypatch: Any) -> None:
    # Set artifact store environment
    monkeypatch.setenv("TRINETRA_ARTIFACT_STORE", str(tmp_path))

    # Write a test CBOM to artifact store
    cbom = _generate_synthetic_cbom(10)
    cbom_path = tmp_path / "cbom.json"
    cbom_path.write_text(json.dumps(cbom), encoding="utf-8")

    db_path = tmp_path / "bench.db"
    engine = create_engine(f"sqlite:///{db_path}")
    initialise_database(engine)
    session_factory = sessionmaker(bind=engine)

    gateway = MockGateway("cbom.json")
    target_repo = "https://github.com/org/benchmarked-repo.git"
    content_hash = "fixed-sha256-hash-abc123"

    # Scan 1: Fresh run
    scan1_id = str(uuid.uuid4())
    with session_factory() as session:
        scan1 = tables.Scan(
            id=scan1_id,
            target_identifier=target_repo,
            target_kind=ScanTargetKind.GIT_REPOSITORY.value,
            status=ScanStatus.QUEUED.value,
            content_hash=content_hash,
        )
        session.add(scan1)
        session.commit()

    execute_scan(session_factory, scan1_id, gateway=gateway, content_hash=content_hash)
    assert gateway.call_count == 1

    with session_factory() as session:
        scan1 = session.get(tables.Scan, scan1_id)
        assert scan1.status == ScanStatus.SUCCEEDED.value
        assert len(scan1.artefacts) == 10

    # Scan 2: Rescan with the same content_hash
    scan2_id = str(uuid.uuid4())
    with session_factory() as session:
        scan2 = tables.Scan(
            id=scan2_id,
            target_identifier=target_repo,
            target_kind=ScanTargetKind.GIT_REPOSITORY.value,
            status=ScanStatus.QUEUED.value,
            content_hash=content_hash,
        )
        session.add(scan2)
        session.commit()

    execute_scan(session_factory, scan2_id, gateway=gateway, content_hash=content_hash)
    # Gateway should NOT have been called again!
    assert gateway.call_count == 1

    with session_factory() as session:
        scan2 = session.get(tables.Scan, scan2_id)
        assert scan2.status == ScanStatus.SUCCEEDED.value
        assert len(scan2.artefacts) == 10
