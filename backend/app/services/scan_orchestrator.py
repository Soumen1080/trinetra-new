"""Asynchronous scan lifecycle orchestration.

The worker owns scanner calls and state transitions; routers only create an
idempotent queued row.  Progress is persisted before it is published so clients
can always fall back to HTTP polling when a Redis/WebSocket delivery is missed.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import tables
from app.models.base import utcnow
from app.models.enums import ScannerKind, ScanStatus, ScanTargetKind
from app.repositories import record_progress
from app.schemas.mapping import artefact_to_row
from app.services.cbom_ingest import CBOMValidationError, ingest_document


class QueueUnavailableError(RuntimeError):
    """The API could not hand a scan to its asynchronous worker."""


class ScanDispatcher(Protocol):
    def dispatch(self, scan_id: str) -> str: ...


class CeleryScanDispatcher:
    """Production dispatcher.  The task body lives in :mod:`app.worker`."""

    def dispatch(self, scan_id: str) -> str:
        try:
            from app.worker import celery_app

            result = celery_app.send_task(
                "trinetra.execute_scan", args=[scan_id], task_id=f"scan-{scan_id}"
            )
        except Exception as error:  # pragma: no cover - broker integration
            raise QueueUnavailableError("The scan worker is unavailable.") from error
        return str(result.id)


@dataclass(frozen=True)
class ScannerResponse:
    artifact_reference: str
    finding_count: int
    scanner_version: str


class ScannerGateway(Protocol):
    def scan(
        self, *, endpoint: str, scan_id: str, target_reference: str
    ) -> ScannerResponse: ...


class HttpScannerGateway:
    """Tiny dependency-free client for the scanners' private API contract."""

    def scan(
        self, *, endpoint: str, scan_id: str, target_reference: str
    ) -> ScannerResponse:
        token = os.getenv("TRINETRA_SCANNER_TOKEN", "")
        if len(token) < 32:
            raise QueueUnavailableError("Scanner credentials are not configured.")
        payload = json.dumps(
            {"scan_id": scan_id, "target_reference": target_reference}
        ).encode("utf-8")
        request = Request(
            endpoint.rstrip("/") + "/internal/v1/scan",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=600) as response:  # nosec B310: configured internal endpoint
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError("SCANNER_UNAVAILABLE") from error
        try:
            return ScannerResponse(
                artifact_reference=str(payload["artifact_reference"]),
                finding_count=int(payload.get("finding_count", 0)),
                scanner_version=str(payload.get("scanner_version", "unknown")),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("INVALID_SCANNER_RESPONSE") from error


def publish_progress(
    session: Session,
    *,
    scan_id: str,
    percent: float,
    stage: str,
    counts: dict[str, int] | None = None,
    message: str | None = None,
) -> tables.ScanProgressEvent:
    """Append one valid progress event.  Callers commit it with their state."""
    return record_progress(
        session,
        event_id=str(uuid.uuid4()),
        scan_id=scan_id,
        percent=percent,
        stage=stage,
        counts=counts,
        message=message,
        created_at=utcnow(),
    )


def scanner_endpoint(target_kind: ScanTargetKind) -> tuple[str, ScannerKind]:
    """Choose the least-privileged scanner for a target kind."""
    if target_kind in {ScanTargetKind.GIT_REPOSITORY, ScanTargetKind.LOCAL_PATH}:
        return os.getenv(
            "TRINETRA_SOURCE_SCANNER_URL", "http://scanner-source:8080"
        ), ScannerKind.SOURCE
    if target_kind is ScanTargetKind.CONTAINER_IMAGE:
        return os.getenv(
            "TRINETRA_CONTAINER_SCANNER_URL", "http://scanner-container:8080"
        ), ScannerKind.CONTAINER
    if target_kind is ScanTargetKind.BINARY_FILE:
        return os.getenv(
            "TRINETRA_BINARY_SCANNER_URL", "http://scanner-binary:8080"
        ), ScannerKind.BINARY
    if target_kind is ScanTargetKind.NETWORK_ENDPOINT:
        return os.getenv(
            "TRINETRA_NETWORK_SCANNER_URL", "http://scanner-network:8080"
        ), ScannerKind.NETWORK
    if target_kind is ScanTargetKind.CLOUD_ACCOUNT:
        return os.getenv(
            "TRINETRA_CLOUDHSM_SCANNER_URL", "http://scanner-cloudhsm:8080"
        ), ScannerKind.CLOUD_HSM
    raise ValueError("UNSUPPORTED_TARGET_TYPE")


def _artifact_path(reference: str) -> Path:
    """Resolve only a relative artifact-store reference, rejecting traversal."""
    store = Path(os.getenv("TRINETRA_ARTIFACT_STORE", "/artifact-store")).resolve()
    candidate = (store / reference.lstrip("/\\")).resolve()
    try:
        candidate.relative_to(store)
    except ValueError as error:
        raise RuntimeError("INVALID_ARTIFACT_REFERENCE") from error
    return candidate


def execute_scan(
    session_factory: sessionmaker[Session],
    scan_id: str,
    *,
    gateway: ScannerGateway | None = None,
) -> None:
    """Run a queued scan exactly once, moving it to an honest terminal state.

    This function contains no HTTP/router concerns and is directly callable by
    Celery as well as integration tests.  Re-delivery is safe: an already
    ingested scan returns immediately, and existing artefact rows prevent a
    second insert after a scanner successfully wrote its immutable CBOM.
    """
    scanner = gateway or HttpScannerGateway()
    with session_factory() as session:
        scan = session.get(tables.Scan, scan_id)
        if scan is None or ScanStatus(scan.status).is_terminal:
            return
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = utcnow()
        publish_progress(
            session,
            scan_id=scan.id,
            percent=1,
            stage="preparing",
            message="Preparing scan target.",
        )
        session.commit()

    try:
        with session_factory() as session:
            scan = session.get(tables.Scan, scan_id)
            if scan is None:
                return
            endpoint, scanner_kind = scanner_endpoint(ScanTargetKind(scan.target_kind))
            publish_progress(
                session,
                scan_id=scan.id,
                percent=10,
                stage="scanning",
                counts={"artefacts": 0},
                message="Scanning target for cryptographic assets.",
            )
            session.commit()
            response = scanner.scan(
                endpoint=endpoint,
                scan_id=scan.id,
                target_reference=scan.target_reference or scan.target_identifier,
            )

        path = _artifact_path(response.artifact_reference)
        document = json.loads(path.read_text(encoding="utf-8"))
        ingested = ingest_document(
            document, scan_target=scan.target_identifier, discovered_by=scanner_kind
        )

        with session_factory() as session:
            scan = session.get(tables.Scan, scan_id)
            if scan is None:
                return
            if ScanStatus(scan.status).is_terminal:
                # A cancellation that arrives while a scanner call is in
                # flight wins. The immutable CBOM may still exist, but it is
                # not ingested into a cancelled lifecycle.
                return
            existing = int(
                session.scalar(
                    select(tables.Artefact)
                    .where(tables.Artefact.scan_id == scan.id)
                    .limit(1)
                ).__bool__()
            )
            if not existing:
                for artefact in ingested.artefacts:
                    session.add(artefact_to_row(artefact, scan_id=scan.id))
            scan.scanners_run = [scanner_kind.value]
            scan.tool_versions = [item.model_dump(mode="json") for item in ingested.tools]
            scan.coverage_json = {
                "files_discovered": 0,
                "files_scanned": 0,
                "files_skipped": ingested.skipped_components,
                "bytes_scanned": 0,
                "languages_detected": [],
                "gaps": [gap.model_dump(mode="json") for gap in ingested.gaps],
            }
            scan.status = (
                ScanStatus.PARTIAL.value if ingested.gaps else ScanStatus.SUCCEEDED.value
            )
            scan.finished_at = utcnow()
            publish_progress(
                session,
                scan_id=scan.id,
                percent=100,
                stage="completed",
                counts={"artefacts": len(ingested.artefacts)},
                message="Scan completed.",
            )
            session.commit()
    except (
        CBOMValidationError,
        OSError,
        json.JSONDecodeError,
        RuntimeError,
        ValueError,
    ) as error:
        code = str(error) if str(error).isupper() else "SCANNER_FAILED"
        with session_factory() as session:
            scan = session.get(tables.Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED.value
            scan.finished_at = utcnow()
            scan.errors_json = [
                {
                    "code": code,
                    "message": (
                        "The scan could not complete. Check the target and scanner "
                        "availability."
                    ),
                    "is_retryable": code == "SCANNER_UNAVAILABLE",
                    "occurred_at": scan.finished_at.isoformat(),
                }
            ]
            publish_progress(
                session,
                scan_id=scan.id,
                percent=100,
                stage="failed",
                message=scan.errors_json[0]["message"],
            )
            session.commit()


__all__ = [
    "CeleryScanDispatcher",
    "HttpScannerGateway",
    "QueueUnavailableError",
    "ScanDispatcher",
    "execute_scan",
    "publish_progress",
    "scanner_endpoint",
]
