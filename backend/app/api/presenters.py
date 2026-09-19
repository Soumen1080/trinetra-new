"""Read-only conversion from ORM rows to deliberately small API views."""

from __future__ import annotations

from app.api.schemas import ArtefactListItem, ScanProgressResponse, ScanResponse
from app.models import tables
from app.models.enums import ScannerKind, ScanStatus, ScanTargetKind
from app.schemas.mapping import artefact_from_row
from app.schemas.scan import CoverageStats, ScanError, ScanResult, ScanTarget, ToolVersion


def scan_response(row: tables.Scan, *, artefact_count: int | None = None) -> ScanResponse:
    return ScanResponse(
        id=row.id,
        project_id=row.project_id,
        target_kind=ScanTargetKind(row.target_kind),
        target_identifier=row.target_identifier,
        target_reference=row.target_reference,
        display_name=row.display_name,
        status=ScanStatus(row.status),
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        artefact_count=artefact_count
        if artefact_count is not None
        else len(row.artefacts),
        errors=list(row.errors_json or []),
    )


def progress_response(row: tables.ScanProgressEvent) -> ScanProgressResponse:
    return ScanProgressResponse(
        sequence=row.sequence,
        percent=row.percent,
        stage=row.stage,
        counts=dict(row.counts_json or {}),
        message=row.message,
        created_at=row.created_at,
    )


def artefact_item(row: tables.Artefact) -> ArtefactListItem:
    assessment = row.latest_assessment
    recommendation = assessment.recommendation if assessment else None
    return ArtefactListItem(
        id=row.id,
        scan_id=row.scan_id,
        application_id=row.application_id,
        name=row.name,
        type=row.type,
        algorithm=row.algorithm,
        key_size_bits=row.key_size_bits,
        location=row.location,
        discovered_by=row.discovered_by,
        quantum_vulnerability=row.quantum_vulnerability,
        risk_score=assessment.final_score if assessment else None,
        priority=assessment.priority if assessment else "none",
        assessment_status=assessment.status if assessment else None,
        recommendation=(recommendation.recommended_algorithm if recommendation else None),
    )


def scan_result_from_rows(
    scan: tables.Scan, artefacts: list[tables.Artefact]
) -> ScanResult:
    """Rebuild a full domain envelope for pure Phase-7 exporters."""
    return ScanResult(
        scan_id=scan.id,
        target=ScanTarget(
            kind=ScanTargetKind(scan.target_kind),
            identifier=scan.target_identifier,
            reference=scan.target_reference,
            display_name=scan.display_name,
        ),
        status=ScanStatus(scan.status),
        started_at=scan.started_at or scan.created_at,
        finished_at=scan.finished_at,
        scanners_run=[ScannerKind(item) for item in (scan.scanners_run or [])],
        tool_versions=[
            ToolVersion.model_validate(item) for item in (scan.tool_versions or [])
        ],
        schema_version=scan.schema_version,
        artefacts=[artefact_from_row(row) for row in artefacts],
        coverage=CoverageStats.model_validate(scan.coverage_json or {}),
        errors=[ScanError.model_validate(item) for item in (scan.errors_json or [])],
        requested_by=scan.requested_by,
        idempotency_key=scan.idempotency_key,
    )


__all__ = [
    "artefact_item",
    "progress_response",
    "scan_response",
    "scan_result_from_rows",
]
