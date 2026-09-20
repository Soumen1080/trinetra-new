"""Tests for error resilience: graceful handling of malformed inputs and scanner failures."""

from __future__ import annotations

import json
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


def _minimal_valid_cbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-09-20T00:00:00Z",
            "tools": [
                {
                    "vendor": "Trinetra",
                    "name": "test-scanner",
                    "version": "1.0.0",
                }
            ],
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "RSA-2048",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "asymmetric",
                        "parameterSetIdentifier": "2048",
                    },
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": "src/crypto.py",
                            "line": 42,
                        }
                    ]
                },
            }
        ],
    }


def test_malformed_component_does_not_abort_ingest() -> None:
    doc = _minimal_valid_cbom()
    # Add a malformed component that violates schema/parsing
    doc["components"].append(
        {
            "type": "cryptographic-asset",
            # Missing name entirely
            "cryptoProperties": {"assetType": "algorithm"},
            "evidence": {"occurrences": []},
        }
    )
    # Add another valid component
    doc["components"].append(
        {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
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
                        "location": "src/cipher.py",
                        "line": 10,
                    }
                ]
            },
        }
    )

    result = ingest_document(doc, scan_target="test-repo")
    # Should successfully ingest the 2 valid artefacts
    assert len(result.artefacts) == 2
    # The malformed component should be recorded as skipped and in gaps
    assert result.skipped_components >= 1
    assert any(gap.kind == "unparseable" for gap in result.gaps)


class FailingGateway:
    def scan(self, *, endpoint: str, scan_id: str, target_reference: str) -> ScannerResponse:
        raise RuntimeError("SCANNER_UNAVAILABLE")


def test_scanner_gateway_failure_marks_scan_failed(tmp_path: Path, monkeypatch: Any) -> None:
    db_path = tmp_path / "test_resilience.db"
    engine = create_engine(f"sqlite:///{db_path}")
    initialise_database(engine)
    session_factory = sessionmaker(bind=engine)

    scan_id = str(uuid.uuid4())
    with session_factory() as session:
        scan = tables.Scan(
            id=scan_id,
            target_identifier="https://github.com/example/broken-repo.git",
            target_kind=ScanTargetKind.GIT_REPOSITORY.value,
            status=ScanStatus.QUEUED.value,
        )
        session.add(scan)
        session.commit()

    execute_scan(session_factory, scan_id, gateway=FailingGateway())

    with session_factory() as session:
        scan = session.get(tables.Scan, scan_id)
        assert scan is not None
        assert scan.status == ScanStatus.FAILED.value
        assert scan.finished_at is not None
        assert scan.errors_json is not None
        assert scan.errors_json[0]["code"] == "SCANNER_UNAVAILABLE"
        assert scan.errors_json[0]["is_retryable"] is True
