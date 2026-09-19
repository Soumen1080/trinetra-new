from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.main import create_app
from app.api.security import hash_password
from app.models.base import Base, utcnow
from app.models.tables import (
    Application,
    Artefact,
    Project,
    ProjectMembership,
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
        session.add_all(
            [
                admin,
                project,
                ProjectMembership(project_id=project.id, user_id=admin.id),
            ]
        )
        session.commit()
    dispatcher = RecordingDispatcher()
    app = create_app(
        engine=engine,
        session_factory=factory,
        scan_dispatcher=dispatcher,
        initialise_schema=False,
        report_store=tmp_path / "reports",
    )
    return TestClient(app), factory, dispatcher


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


def test_scan_lifecycle_is_project_scoped_and_idempotent(tmp_path: Path) -> None:
    client, _, dispatcher = _client(tmp_path)
    headers = _headers(client)

    response = client.post(
        "/api/scans",
        headers={**headers, "Idempotency-Key": "scan-once"},
        json={
            "target_kind": "git_repository",
            "target_identifier": "https://git.example/payments",
        },
    )

    assert response.status_code == 202
    scan_id = response.json()["id"]
    assert dispatcher.scan_ids == [scan_id]
    assert client.get(f"/api/scans/{scan_id}", headers=headers).status_code == 200
    assert (
        client.get(f"/api/scans/{scan_id}/progress", headers=headers).json()[0]["stage"]
        == "queued"
    )

    retried = client.post(
        "/api/scans",
        headers={**headers, "Idempotency-Key": "scan-once"},
        json={
            "target_kind": "git_repository",
            "target_identifier": "https://git.example/payments",
        },
    )
    assert retried.status_code == 202
    assert retried.json()["id"] == scan_id
    assert dispatcher.scan_ids == [scan_id]


def test_cmdb_import_is_idempotent_and_marks_org_preset_provenance(
    tmp_path: Path,
) -> None:
    client, factory, _ = _client(tmp_path)
    headers = _headers(client)
    csv = (
        "name,owner,business_criticality,data_classification\n"
        "Payments API,Core,critical,confidential\n"
    )

    first = client.post(
        "/api/applications/import", headers=headers, json={"csv_content": csv}
    )
    second = client.post(
        "/api/applications/import", headers=headers, json={"csv_content": csv}
    )

    assert first.json() == {"created": 1, "updated": 0, "skipped": 0, "errors": []}
    assert second.json() == {"created": 0, "updated": 1, "skipped": 0, "errors": []}
    with factory() as session:
        rows = list(session.scalars(select(Application)))
        assert len(rows) == 1
        assert rows[0].provenance_json["business_criticality"]["tier"] == "org_preset"


def test_analyst_can_create_application_with_user_provenance(tmp_path: Path) -> None:
    client, factory, _ = _client(tmp_path)
    headers = _headers(client)

    response = client.post(
        "/api/applications",
        headers=headers,
        json={
            "name": "Identity service",
            "business_criticality": "high",
            "data_classification": "confidential",
        },
    )

    assert response.status_code == 201
    with factory() as session:
        application = session.get(Application, response.json()["id"])
        assert application is not None
        assert application.provenance_json["data_classification"]["tier"] == "user"


def test_authz_and_validation_use_stable_error_contract(tmp_path: Path) -> None:
    client, factory, _ = _client(tmp_path)
    headers = _headers(client)
    with factory() as session:
        viewer = User(
            id="viewer-1",
            username="viewer",
            password_hash=hash_password("viewer password long enough"),
            role="viewer",
        )
        session.add(viewer)
        session.add(ProjectMembership(project_id="project-1", user_id=viewer.id))
        session.commit()
    viewer_login = client.post(
        "/api/auth/login",
        json={"username": "viewer", "password": "viewer password long enough"},
    )
    viewer_headers = {
        "Authorization": f"Bearer {viewer_login.json()['access_token']}",
        "X-Project-ID": "project-1",
    }

    forbidden = client.post(
        "/api/scans",
        headers=viewer_headers,
        json={
            "target_kind": "git_repository",
            "target_identifier": "https://git.example/nope",
        },
    )
    invalid = client.post(
        "/api/scans", headers=headers, json={"target_kind": "git_repository"}
    )

    assert forbidden.status_code == 403
    assert forbidden.json()["code"] == "FORBIDDEN"
    assert invalid.status_code == 422
    assert invalid.json()["code"] == "VALIDATION_ERROR"


def test_browser_session_refreshes_csrf_and_bulk_reviews_are_project_scoped(
    tmp_path: Path,
) -> None:
    client, factory, _ = _client(tmp_path)
    headers = _headers(client)
    session = client.get("/api/auth/session")
    assert session.status_code == 200
    assert session.json()["user"]["username"] == "admin"
    assert session.json()["csrf_token"]

    with factory() as database:
        scan = Scan(
            id="scan-review",
            project_id="project-1",
            target_kind="git_repository",
            target_identifier="https://git.example/payments",
            status="succeeded",
        )
        database.add(scan)
        database.add(
            Artefact(
                id="artefact-review",
                scan_id=scan.id,
                name="RSA transport",
                type="algorithm",
                quantum_vulnerability="shor_broken",
                discovered_by="source",
                first_seen=utcnow(),
                last_seen=utcnow(),
            )
        )
        database.commit()

    review = client.post(
        "/api/artefacts/bulk-review",
        headers=headers,
        json={
            "artefact_ids": ["artefact-review"],
            "action": "false_positive",
            "reason": "Verified development fixture, not production traffic.",
        },
    )
    assert review.status_code == 200
    assert review.json() == {"updated": 1}
    inventory = client.get("/api/artefacts", headers=headers)
    assert inventory.status_code == 200
    item = inventory.json()["items"][0]
    assert item["review_status"] == "false_positive"
    assert item["review_reason"].startswith("Verified development")
