"""End-to-end integration test of the full Trinetra pipeline.

Walks the complete lifecycle:
1. Scan: mock scanner gateway emits CycloneDX CBOM -> execute_scan ingests artefacts
2. Risk: pure engines assess Shor vulnerability and Mosca deficit -> persisted
3. Recommend: PQC alternatives generated -> persisted
4. Export: CycloneDX, SARIF, Native JSON, and CSV export verified
5. API Render: TestClient hits /api/scans/{id}/artefacts and /api/dashboard
"""

from __future__ import annotations

import csv
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.main import create_app
from app.api.security import hash_password
from app.engines.final_risk_engine import RiskSettings
from app.engines.profiles import load_risk_profiles
from app.engines.profiles.loader import load_pqc_evidence_profile
from app.exporters import ExportFormat, export
from app.models import tables
from app.models.base import Base
from app.models.enums import ScanStatus, ScanTargetKind
from app.models.tables import Project, ProjectMembership, Scan, User
from app.api.presenters import scan_result_from_rows
from app.schemas.mapping import (
    artefact_from_row,
    assessment_from_row,
    recommendation_from_row,
)
from app.services.risk_assessment import apply_risk_settings_and_rescore
from app.services.scan_orchestrator import ScannerResponse, execute_scan


class MockPipelineGateway:
    def __init__(self, artifact_ref: str) -> None:
        self.artifact_ref = artifact_ref

    def scan(self, *, endpoint: str, scan_id: str, target_reference: str) -> ScannerResponse:
        return ScannerResponse(
            artifact_reference=self.artifact_ref,
            finding_count=2,
            scanner_version="1.0.0",
        )


def _sample_cbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-09-20T00:00:00Z",
            "tools": [{"vendor": "Trinetra", "name": "source-scanner", "version": "1.0.0"}],
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "RSA-2048",
                "properties": [
                    {"name": "trinetra:algorithm", "value": "rsa"},
                    {"name": "trinetra:key-size-bits", "value": "2048"},
                    {"name": "trinetra:detection-method", "value": "semgrep-taint"},
                    {"name": "trinetra:confidence", "value": "high"},
                ],
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "asymmetric",
                        "parameterSetIdentifier": "2048",
                        "cryptoFunctions": ["key-agreement"],
                    },
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": "src/auth/keys.py",
                            "line": 45,
                            "snippet": "key = RSA.generate(2048)",
                        }
                    ]
                },
            },
            {
                "type": "cryptographic-asset",
                "name": "AES-128-CBC",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "block-cipher",
                        "parameterSetIdentifier": "128",
                        "mode": "cbc",
                    },
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": "src/data/cipher.py",
                            "line": 12,
                            "snippet": "cipher = AES.new(key, AES.MODE_CBC)",
                        }
                    ]
                },
            },
        ],
    }


def test_full_pipeline_lifecycle(tmp_path: Path, monkeypatch: Any) -> None:
    # 1. Setup artifact store and DB
    monkeypatch.setenv("TRINETRA_ARTIFACT_STORE", str(tmp_path))
    cbom_file = tmp_path / "target_cbom.json"
    cbom_file.write_text(json.dumps(_sample_cbom()), encoding="utf-8")

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)

    # Provision user, project, and scan
    user_id = str(uuid.uuid4())
    project_id = "project-e2e"
    scan_id = str(uuid.uuid4())

    with factory() as session:
        user = User(
            id=user_id,
            username="analyst",
            password_hash=hash_password("analystpassword123"),
            role="analyst",
        )
        project = Project(id=project_id, tenant_id="tenant-1", name="E2E Project")
        membership = ProjectMembership(project_id=project.id, user_id=user.id)
        scan = Scan(
            id=scan_id,
            project_id=project_id,
            target_identifier="https://github.com/example/payments-service.git",
            target_kind=ScanTargetKind.GIT_REPOSITORY.value,
            status=ScanStatus.QUEUED.value,
        )
        session.add_all([user, project, membership, scan])
        session.commit()

    # 2. Execute scan via orchestrator
    gateway = MockPipelineGateway("target_cbom.json")
    execute_scan(factory, scan_id, gateway=gateway)

    with factory() as session:
        scan_row = session.get(Scan, scan_id)
        assert scan_row is not None
        assert scan_row.status == ScanStatus.SUCCEEDED.value
        assert len(scan_row.artefacts) == 2
        artefact_ids = [a.id for a in scan_row.artefacts]

    # 3. Apply risk assessment and recommendation
    profiles = load_risk_profiles()
    pqc_profile = load_pqc_evidence_profile()
    with factory() as session:
        scan_row = session.get(Scan, scan_id)
        for art in scan_row.artefacts:
            if "RSA" in art.name:
                session.add(
                    tables.ArtefactContext(
                        id=str(uuid.uuid4()),
                        artefact_id=art.id,
                        business_criticality="critical",
                        data_classification="restricted",
                        exposure="internet",
                        data_lifetime_years=10,
                        migration_time_years=3.0,
                        provenance_json={
                            "data_lifetime_years": {
                                "tier": "user",
                                "source_detail": "Security analyst review",
                            },
                            "migration_time_years": {
                                "tier": "user",
                                "source_detail": "Engineering estimation",
                            },
                        },
                    )
                )
        session.commit()

    settings = RiskSettings(planning_horizon_years=8.0)
    with factory() as session:
        rescore_result = apply_risk_settings_and_rescore(
            session,
            setting_id=str(uuid.uuid4()),
            setting_version="v1",
            project_id=project_id,
            profiles=profiles,
            settings=settings,
            assessment_id_for=lambda art_id: f"risk-{art_id}",
            assessed_at=datetime.now(UTC),
            recommendation_profile=pqc_profile,
        )
        session.commit()
        assert rescore_result.artefacts_rescored == 2
        assert rescore_result.recommendations_created >= 1

    # 4. Verify Exporters (SARIF, CycloneDX, Native JSON, CSV)
    with factory() as session:
        scan_row = session.get(Scan, scan_id)
        artefacts = [artefact_from_row(a) for a in scan_row.artefacts]
        from sqlalchemy import select
        from app.models.tables import RiskAssessment as RiskRow
        from app.models.tables import Recommendation as RecRow
        assessments = [
            assessment_from_row(r)
            for r in session.scalars(select(RiskRow).where(RiskRow.artefact_id.in_(artefact_ids))).all()
        ]
        recommendations = [
            recommendation_from_row(r)
            for r in session.scalars(select(RecRow)).all()
        ]

        scan_result = scan_result_from_rows(scan_row, scan_row.artefacts)

    # Export CycloneDX
    cdx_out = export(scan_result, assessments, recommendations, fmt=ExportFormat.CYCLONEDX)
    assert isinstance(cdx_out, str)
    cdx_data = json.loads(cdx_out)
    assert cdx_data["bomFormat"] == "CycloneDX"

    # Export SARIF
    sarif_out = export(scan_result, assessments, recommendations, fmt=ExportFormat.SARIF)
    assert isinstance(sarif_out, str)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"

    # Export Native JSON
    json_out = export(scan_result, assessments, recommendations, fmt=ExportFormat.NATIVE_JSON)
    assert isinstance(json_out, str)
    native_data = json.loads(json_out)
    assert "scan" in native_data
    assert "artefacts" in native_data

    # Export CSV
    csv_out = export(scan_result, assessments, recommendations, fmt=ExportFormat.CSV)
    assert isinstance(csv_out, str)
    csv_reader = list(csv.reader(csv_out.splitlines()))
    assert len(csv_reader) >= 3  # Header + 2 artefacts

    # 5. API Render: TestClient hits endpoints
    app = create_app(
        engine=engine,
        session_factory=factory,
        initialise_schema=False,
        report_store=tmp_path / "reports",
    )
    client = TestClient(app)

    login = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "analystpassword123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Project-ID": project_id,
    }

    # Verify artefacts API
    art_resp = client.get(f"/api/scans/{scan_id}/artefacts", headers=headers)
    assert art_resp.status_code == 200
    art_json = art_resp.json()
    assert art_json["page"]["total"] == 2
    items = art_json["items"]
    assert len(items) == 2
    algorithms = {item["algorithm"] for item in items}
    assert "rsa" in algorithms

    # Verify dashboard API
    dash_resp = client.get("/api/dashboard/summary", headers=headers)
    assert dash_resp.status_code == 200
    dash_json = dash_resp.json()
    assert "total_artefacts" in dash_json
    assert dash_json["total_artefacts"] >= 2
