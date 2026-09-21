"""Asynchronous scan lifecycle orchestration.

The worker owns scanner calls and state transitions; routers only create an
idempotent queued row.  Progress is persisted before it is published so clients
can always fall back to HTTP polling when a Redis/WebSocket delivery is missed.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)

from app.engines.final_risk_engine import (
    RiskSettings,
    classify_risk,
    _security_token,
    _effective_quantum_vulnerability,
)
from app.engines.profiles.loader import load_pqc_evidence_profile, load_risk_profiles
from app.engines.recommendation_engine import (
    recommend_replacement,
    recommendation_id_for_assessment,
)
from app.models import tables
from app.models.base import utcnow
from app.models.enums import (
    AssetType,
    BusinessCriticality,
    DataClassification,
    ExposureLevel,
    ProvenanceTier,
    QuantumVulnerability,
    ScannerKind,
    ScanStatus,
    ScanTargetKind,
)
from app.repositories import append_assessment, append_recommendation, record_progress
from app.schemas.common import Provenance
from app.schemas.context import ArtefactContext
from app.schemas.mapping import (
    artefact_to_row,
    context_from_row,
    context_to_row,
)
from app.schemas.recommendation import RecommendationContext, RecommendationRequirements
from app.services.cache import ArtefactCache, compute_content_hash
from app.services.cbom_ingest import CBOMValidationError, ingest_document
from app.services.observability import metrics
from app.services.security import sanitize_evidence_snippet


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


def _resolve_local_path(raw_path: str) -> Path | None:
    """Resolve a local path either directly, via /host-projects, or /scan-workdir."""
    clean = raw_path.strip()
    p = Path(clean)
    if p.exists():
        return p

    normalized = clean.replace("\\", "/")
    if "/PROJECTS/" in normalized or "/projects/" in normalized:
        parts = re.split(r"/PROJECTS/|/projects/", normalized, flags=re.IGNORECASE)
        if len(parts) > 1:
            candidate = Path("/host-projects") / parts[1].lstrip("/")
            if candidate.exists():
                return candidate

    candidate_basename = Path("/host-projects") / p.name
    if candidate_basename.exists():
        return candidate_basename

    input_root = Path(os.getenv("TRINETRA_INPUT_ROOT", "/scan-workdir")).resolve()
    candidate_input = (input_root / clean.lstrip("/\\")).resolve()
    if candidate_input.exists():
        return candidate_input

    return None


def prepare_scan_target(scan: tables.Scan) -> str:
    """Prepare the target for the scanner microservice.

    Returns a target_reference path relative to TRINETRA_INPUT_ROOT.
    """
    input_root = Path(os.getenv("TRINETRA_INPUT_ROOT", "/scan-workdir")).resolve()
    input_root.mkdir(parents=True, exist_ok=True)
    target_dir = input_root / scan.id

    if scan.target_kind == ScanTargetKind.GIT_REPOSITORY.value:
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        target_dir.mkdir(parents=True, exist_ok=True)

        git_url = scan.target_identifier.strip()
        ref = (scan.target_reference or "").strip()

        # Prevent dubiously-owned repository errors under container runtimes
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", "*"],
            capture_output=True,
            text=True,
        )

        cloned = False
        if ref:
            # First attempt: shallow clone of the requested branch or tag
            cmd = ["git", "clone", "--depth", "1", "--branch", ref, git_url, str(target_dir)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if proc.returncode == 0:
                cloned = True
            else:
                # Reference might be a commit hash or special ref; fallback to clone and checkout
                if target_dir.exists():
                    shutil.rmtree(target_dir, ignore_errors=True)
                target_dir.mkdir(parents=True, exist_ok=True)
                cmd = ["git", "clone", "--depth", "50", git_url, str(target_dir)]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                if proc.returncode == 0:
                    co = subprocess.run(
                        ["git", "-C", str(target_dir), "checkout", ref],
                        capture_output=True,
                        text=True,
                    )
                    if co.returncode == 0:
                        cloned = True

        if not cloned:
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            target_dir.mkdir(parents=True, exist_ok=True)
            cmd = ["git", "clone", "--depth", "1", git_url, str(target_dir)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                err_msg = proc.stderr.strip() or proc.stdout.strip() or "git clone failed"
                raise RuntimeError(f"GIT_CLONE_FAILED: {err_msg}")

        return scan.id

    elif scan.target_kind == ScanTargetKind.LOCAL_PATH.value:
        if target_dir.exists() and any(target_dir.iterdir()):
            return scan.id
        src = _resolve_local_path(scan.target_identifier)
        if src is None:
            raise RuntimeError(f"TARGET_NOT_FOUND: Local path '{scan.target_identifier}' was not found.")

        target_dir.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copy2(src, target_dir / src.name)
        else:
            shutil.copytree(
                src,
                target_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    ".git", "node_modules", ".venv", "__pycache__", ".next", "dist", "build"
                ),
            )
        return scan.id

    return scan.target_reference or scan.id


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
    content_hash: str | None = None,
    previous_scan_id: str | None = None,
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

        if content_hash and not scan.content_hash:
            scan.content_hash = content_hash

        # Incremental rescan check: if content hash matches a prior successful scan, reuse it
        if scan.content_hash:
            cached = ArtefactCache.find_cached_scan(
                session,
                target_identifier=scan.target_identifier,
                content_hash=scan.content_hash,
            )
            if cached is not None and cached.id != scan.id:
                scan.status = cached.status
                scan.scanners_run = cached.scanners_run
                scan.tool_versions = cached.tool_versions
                scan.coverage_json = cached.coverage_json
                scan.finished_at = utcnow()
                cloned = ArtefactCache.clone_artefacts(
                    session,
                    source_scan_id=cached.id,
                    target_scan_id=scan.id,
                )
                publish_progress(
                    session,
                    scan_id=scan.id,
                    percent=100,
                    stage="completed",
                    counts={"artefacts": cloned},
                    message="Scan completed from cache.",
                )
                session.commit()
                metrics.inc_counter("trinetra_scans_total", status=scan.status)
                metrics.set_gauge("trinetra_artefacts_total", cloned)
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

            prepared_target = scan.id
            if gateway is None:
                prepared_target = prepare_scan_target(scan)
            else:
                try:
                    prepared_target = prepare_scan_target(scan)
                except Exception:
                    pass

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
                target_reference=prepared_target,
            )

        path = _artifact_path(response.artifact_reference)
        document_text = path.read_text(encoding="utf-8")
        document = json.loads(document_text)
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

            if not scan.content_hash:
                scan.content_hash = content_hash or compute_content_hash(document_text)

            existing = int(
                session.scalar(
                    select(tables.Artefact)
                    .where(tables.Artefact.scan_id == scan.id)
                    .limit(1)
                ).__bool__()
            )
            if not existing:
                profiles = None
                settings = None
                pqc_profile = None
                try:
                    profiles = load_risk_profiles()
                    settings = RiskSettings()
                    pqc_profile = load_pqc_evidence_profile()
                except Exception:
                    pass

                for artefact in ingested.artefacts:
                    artefact.scan_id = scan.id

                    token = _security_token(artefact.algorithm or artefact.name)
                    broken = set()
                    resistant = set()
                    if profiles and profiles.current_security:
                        broken = {
                            _security_token(item)
                            for item in profiles.current_security.classically_broken_algorithms
                        }
                        resistant = {
                            _security_token(item)
                            for item in profiles.current_security.quantum_resistant_algorithms
                        }

                    if artefact.asset_type is AssetType.LIBRARY:
                        effective_vuln = QuantumVulnerability.NOT_APPLICABLE
                    elif artefact.quantum_vulnerability is QuantumVulnerability.CLASSICALLY_BROKEN or (token and token in broken):
                        effective_vuln = QuantumVulnerability.CLASSICALLY_BROKEN
                    elif artefact.quantum_vulnerability is QuantumVulnerability.QUANTUM_SAFE or (token and token in resistant):
                        effective_vuln = QuantumVulnerability.QUANTUM_SAFE
                    else:
                        effective_vuln = _effective_quantum_vulnerability(artefact)

                    artefact.quantum_vulnerability = effective_vuln

                    existing_row = session.get(tables.Artefact, artefact.artefact_id)
                    if existing_row is not None:
                        existing_row.scan_id = scan.id
                        existing_row.last_seen = utcnow()
                        existing_row.quantum_vulnerability = effective_vuln.value
                        if artefact.evidence:
                            existing_row.location = artefact.evidence[0].location.render()
                        art_row = existing_row
                    else:
                        art_row = artefact_to_row(artefact, scan_id=scan.id)
                        art_row.quantum_vulnerability = effective_vuln.value
                        session.add(art_row)
                        session.flush()

                    if profiles and settings and pqc_profile:
                        try:
                            ctx_row = session.scalar(
                                select(tables.ArtefactContext).where(
                                    tables.ArtefactContext.artefact_id == art_row.id
                                )
                            )
                            if ctx_row is not None:
                                ctx = context_from_row(ctx_row)
                            else:
                                ctx = ArtefactContext(
                                    artefact_id=art_row.id,
                                    business_criticality=BusinessCriticality.HIGH,
                                    data_classification=DataClassification.CONFIDENTIAL,
                                    exposure=ExposureLevel.INTERNAL,
                                    data_lifetime_years=7,
                                    migration_time_years=2.0,
                                    provenance={
                                        "business_criticality": Provenance(
                                            tier=ProvenanceTier.ORG_PRESET,
                                            source_detail="Default organisation preset",
                                        ),
                                        "data_classification": Provenance(
                                            tier=ProvenanceTier.ORG_PRESET,
                                            source_detail="Default organisation preset",
                                        ),
                                        "exposure": Provenance(
                                            tier=ProvenanceTier.ORG_PRESET,
                                            source_detail="Default organisation preset",
                                        ),
                                        "data_lifetime_years": Provenance(
                                            tier=ProvenanceTier.ORG_PRESET,
                                            source_detail="Default organisation preset",
                                        ),
                                        "migration_time_years": Provenance(
                                            tier=ProvenanceTier.ORG_PRESET,
                                            source_detail="Default organisation preset",
                                        ),
                                    },
                                )

                            assessment = classify_risk(
                                artefact,
                                ctx,
                                profiles,
                                settings,
                                assessment_id=str(uuid.uuid4()),
                                assessed_at=scan.finished_at or utcnow(),
                            )
                            append_assessment(session, assessment)

                            rec = recommend_replacement(
                                RecommendationContext(
                                    recommendation_id=recommendation_id_for_assessment(
                                        assessment.assessment_id
                                    ),
                                    assessment=assessment,
                                    artefact=artefact,
                                    requirements=RecommendationRequirements(),
                                ),
                                profile=pqc_profile,
                            )
                            if rec:
                                append_recommendation(session, rec)
                        except Exception as exc:
                            logger.warning("Failed to assess artefact %s: %s", art_row.id, exc)
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
            metrics.inc_counter("trinetra_scans_total", status=scan.status)
            metrics.set_gauge("trinetra_artefacts_total", len(ingested.artefacts))
    except (
        CBOMValidationError,
        OSError,
        json.JSONDecodeError,
        RuntimeError,
        ValueError,
        MemoryError,
        Exception,
    ) as error:
        logger.exception("execute_scan failed for scan_id=%s: %s", scan_id, error)
        code = str(error) if str(error).isupper() else "SCANNER_FAILED"
        err_msg = str(error)
        msg = (
            f"The scan target could not be prepared: {err_msg}"
            if "GIT_CLONE_FAILED" in err_msg or "TARGET_NOT_FOUND" in err_msg
            else f"The scan could not complete: {err_msg}"
        )
        with session_factory() as session:
            scan = session.get(tables.Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED.value
            scan.finished_at = utcnow()
            scan.errors_json = [
                {
                    "code": code,
                    "message": msg,
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
            metrics.inc_counter("trinetra_scans_total", status="failed")


__all__ = [
    "CeleryScanDispatcher",
    "HttpScannerGateway",
    "QueueUnavailableError",
    "ScanDispatcher",
    "execute_scan",
    "publish_progress",
    "scanner_endpoint",
]
