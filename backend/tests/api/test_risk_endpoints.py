from __future__ import annotations

from pathlib import Path
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.main import create_app
from app.api.security import hash_password
from app.models.base import Base, utcnow
from app.models.enums import AssetType, QuantumVulnerability
from app.models.tables import (
    Application,
    Artefact,
    Project,
    ProjectMembership,
    RiskAssessment,
    Scan,
    User,
)


class RecordingDispatcher:
    def __init__(self) -> None:
        self.scan_ids: list[str] = []

    def dispatch(self, scan_id: str) -> str:
        self.scan_ids.append(scan_id)
        return f"task-{scan_id}"


def _client(
    tmp_path: Path,
) -> tuple[TestClient, sessionmaker[Session], RecordingDispatcher]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with factory() as session:
        admin = User(
            id="admin-1",
            username="admin",
            password_hash=hash_password("correct horse battery staple"),
            role="admin",
        )
        project = Project(id="project-1", tenant_id="tenant-a", name="Payments")
        membership = ProjectMembership(project_id=project.id, user_id=admin.id)
        app = Application(
            id="app-1",
            project_id=project.id,
            name="Payment Gateway",
            business_criticality="critical",
            data_classification="confidential",
            data_retention_years=7,
            migration_time_years=2.0,
        )
        scan = Scan(
            id="scan-1",
            project_id=project.id,
            target_kind="git_repository",
            target_identifier="https://github.com/example/repo.git",
            target_reference="main",
            status="succeeded",
        )
        art1 = Artefact(
            id="art-1",
            scan_id=scan.id,
            application_id=app.id,
            type="algorithm",
            name="RSA-2048",
            algorithm="RSA",
            key_size_bits=2048,
            quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN.value,
            discovered_by="source",
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        art2 = Artefact(
            id="art-2",
            scan_id=scan.id,
            application_id=app.id,
            type="algorithm",
            name="AES-256-GCM",
            algorithm="AES",
            mode="GCM",
            key_size_bits=256,
            quantum_vulnerability=QuantumVulnerability.QUANTUM_SAFE.value,
            discovered_by="source",
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        art3 = Artefact(
            id="art-3",
            scan_id=scan.id,
            application_id=app.id,
            type="library",
            name="OpenSSL",
            quantum_vulnerability=QuantumVulnerability.NOT_APPLICABLE.value,
            discovered_by="source",
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        art_proto = Artefact(
            id="art-proto-1",
            scan_id=scan.id,
            application_id=app.id,
            type=AssetType.PROTOCOL.value,
            name="TLS 1.3",
            algorithm="TLS",
            quantum_vulnerability=QuantumVulnerability.QUANTUM_SAFE.value,
            discovered_by="source",
            detail_json={
                "detail_type": "protocol",
                "protocol": "tls",
                "version": "1.3",
                "is_observed": True,
            },
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        ass1 = RiskAssessment(
            id=str(uuid.uuid4()),
            artefact_id=art1.id,
            status="scored",
            priority="p0",
            final_score=9.2,
            policy_version="1.0",
            weights_version="1.0",
            assessed_at=utcnow(),
        )
        session.add_all(
            [admin, project, membership, app, scan, art1, art2, art3, art_proto, ass1]
        )
        session.commit()
    dispatcher = RecordingDispatcher()
    fastapi_app = create_app(
        engine=engine,
        session_factory=factory,
        scan_dispatcher=dispatcher,
        initialise_schema=False,
        report_store=tmp_path / "reports",
    )
    return TestClient(fastapi_app), factory, dispatcher


def _headers(client: TestClient) -> dict[str, str]:
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    return {
        "Authorization": f"Bearer {login.json()['access_token']}",
        "X-Project-ID": "project-1",
    }


def test_mosca_timeline_returns_computed_data(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/mosca-timeline", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    item = next(d for d in data if d["application_id"] == "app-1")
    assert item["application_name"] == "Payment Gateway"
    assert item["x_years"] == 7
    assert item["z_years"] == 2.0
    assert item["at_risk_count"] == 1


def test_risk_heatmap_returns_matrix(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/heatmap", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "cells" in data
    assert data["total"] == 4
    assert len(data["cells"]) > 0


def test_dependency_graph_returns_nodes_and_edges(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/dependency-graph", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    node_types = {n["type"] for n in data["nodes"]}
    assert "application" in node_types
    assert "library" in node_types
    assert "algorithm" in node_types


def test_hndl_returns_vulnerable_artefacts(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/hndl", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["page"]["total"] == 1
    assert data["items"][0]["name"] == "RSA-2048"


def test_compliance_posture_returns_standards(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/compliance", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data["standards"]) == 4
    assert len(data["systems"]) >= 1
    sys = data["systems"][0]
    assert sys["systemName"] == "Payment Gateway"
    assert sys["status"] == "non_compliant"


def test_algorithm_inventory_groups_by_algorithm(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/risk/algorithm-inventory", headers=headers)
    assert res.status_code == 200
    data = res.json()
    algos = {d["algorithm"] for d in data}
    assert "RSA" in algos
    assert "AES" in algos


def test_observed_vs_declared_route(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    headers = _headers(client)
    res = client.get("/api/applications/app-1/observed-vs-declared", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["application_id"] == "app-1"
    assert "summary" in data
