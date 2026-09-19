"""The deliberately small database boundary for risk-assessment persistence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from app.models import tables
from app.schemas.mapping import assessment_to_row, recommendation_to_row
from app.schemas.recommendation import PqcRecommendation
from app.schemas.risk import RiskAssessment


def activate_setting_version(
    session: Session, setting: tables.OrgSettingVersion
) -> tables.OrgSettingVersion:
    """Make one new immutable risk-setting version active.

    Previous versions remain rows for audit and replay; only their active flag
    changes.  The caller owns the transaction so version activation and newly
    appended assessments succeed or fail together.
    """
    session.execute(
        update(tables.OrgSettingVersion)
        .where(tables.OrgSettingVersion.is_active.is_(True))
        .values(is_active=False)
    )
    session.add(setting)
    return setting


def artefacts_for_rescore(
    session: Session, *, project_id: str | None = None
) -> list[tables.Artefact]:
    """Return every artefact with its current context in a bounded query shape."""
    statement = select(tables.Artefact).options(selectinload(tables.Artefact.context))
    if project_id is not None:
        statement = statement.join(tables.Scan).where(
            tables.Scan.project_id == project_id
        )
    return list(session.scalars(statement))


# ---------------------------------------------------------------------------
# Phase 8 API persistence boundary
# ---------------------------------------------------------------------------


def project_for_user(
    session: Session, *, project_id: str, user_id: str
) -> tables.Project | None:
    """Return a project only when the user has explicit membership.

    Keeping this predicate in the repository makes accidental unscoped reads
    much harder to write in routers.  A global ``admin`` role grants actions
    within a project, not visibility into another tenant's project.
    """
    statement = (
        select(tables.Project)
        .join(tables.ProjectMembership)
        .where(
            tables.Project.id == project_id,
            tables.ProjectMembership.user_id == user_id,
        )
    )
    return session.scalar(statement)


def projects_for_user(session: Session, *, user_id: str) -> list[tables.Project]:
    statement = (
        select(tables.Project)
        .join(tables.ProjectMembership)
        .where(tables.ProjectMembership.user_id == user_id)
        .order_by(tables.Project.name)
    )
    return list(session.scalars(statement))


def scan_for_project(
    session: Session, *, scan_id: str, project_id: str
) -> tables.Scan | None:
    return session.scalar(
        select(tables.Scan).where(
            tables.Scan.id == scan_id, tables.Scan.project_id == project_id
        )
    )


def scans_for_project(
    session: Session, *, project_id: str, offset: int, limit: int
) -> tuple[list[tables.Scan], int]:
    where = tables.Scan.project_id == project_id
    total = int(
        session.scalar(select(func.count()).select_from(tables.Scan).where(where)) or 0
    )
    rows = list(
        session.scalars(
            select(tables.Scan)
            .where(where)
            .order_by(tables.Scan.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return rows, total


def artefact_for_project(
    session: Session, *, artefact_id: str, project_id: str
) -> tables.Artefact | None:
    statement = (
        select(tables.Artefact)
        .join(tables.Scan)
        .options(
            selectinload(tables.Artefact.assessments).selectinload(
                tables.RiskAssessment.recommendation
            ),
            selectinload(tables.Artefact.context),
        )
        .where(
            tables.Artefact.id == artefact_id,
            tables.Scan.project_id == project_id,
        )
    )
    return session.scalar(statement)


def artefacts_for_scan(session: Session, *, scan_id: str) -> list[tables.Artefact]:
    statement = (
        select(tables.Artefact)
        .where(tables.Artefact.scan_id == scan_id)
        .options(
            selectinload(tables.Artefact.assessments).selectinload(
                tables.RiskAssessment.recommendation
            ),
            selectinload(tables.Artefact.context),
        )
    )
    return list(session.scalars(statement))


def applications_for_project(
    session: Session, *, project_id: str
) -> list[tables.Application]:
    return list(
        session.scalars(
            select(tables.Application)
            .where(tables.Application.project_id == project_id)
            .order_by(tables.Application.name)
        )
    )


def application_for_project(
    session: Session, *, application_id: str, project_id: str
) -> tables.Application | None:
    return session.scalar(
        select(tables.Application).where(
            tables.Application.id == application_id,
            tables.Application.project_id == project_id,
        )
    )


def record_progress(
    session: Session,
    *,
    event_id: str,
    scan_id: str,
    percent: float,
    stage: str,
    counts: dict[str, int] | None,
    message: str | None,
    created_at: datetime,
) -> tables.ScanProgressEvent:
    """Append a monotonic, durable progress event for reconnecting clients."""
    sequence = (
        int(
            session.scalar(
                select(
                    func.coalesce(func.max(tables.ScanProgressEvent.sequence), 0)
                ).where(tables.ScanProgressEvent.scan_id == scan_id)
            )
            or 0
        )
        + 1
    )
    row = tables.ScanProgressEvent(
        id=event_id,
        scan_id=scan_id,
        sequence=sequence,
        percent=percent,
        stage=stage,
        counts_json=counts,
        message=message,
        created_at=created_at,
    )
    session.add(row)
    return row


def progress_since(
    session: Session, *, scan_id: str, after: int = 0
) -> list[tables.ScanProgressEvent]:
    return list(
        session.scalars(
            select(tables.ScanProgressEvent)
            .where(
                tables.ScanProgressEvent.scan_id == scan_id,
                tables.ScanProgressEvent.sequence > after,
            )
            .order_by(tables.ScanProgressEvent.sequence)
        )
    )


def write_audit_log(
    session: Session,
    *,
    entry_id: str,
    project_id: str | None,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    request_id: str | None,
    details: dict[str, object] | None,
    occurred_at: datetime,
) -> tables.AuditLog:
    row = tables.AuditLog(
        id=entry_id,
        project_id=project_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id,
        details_json=details,
        occurred_at=occurred_at,
    )
    session.add(row)
    return row


def append_assessment(
    session: Session, assessment: RiskAssessment
) -> tables.RiskAssessment:
    """Insert one new assessment history row; no update path exists here."""
    row = assessment_to_row(assessment)
    session.add(row)
    return row


def append_recommendation(
    session: Session, recommendation: PqcRecommendation
) -> tables.Recommendation:
    """Insert the single evidence-backed recommendation for one assessment."""
    row = recommendation_to_row(recommendation)
    session.add(row)
    return row


__all__ = [
    "activate_setting_version",
    "append_assessment",
    "append_recommendation",
    "application_for_project",
    "applications_for_project",
    "artefact_for_project",
    "artefacts_for_rescore",
    "artefacts_for_scan",
    "progress_since",
    "project_for_user",
    "projects_for_user",
    "record_progress",
    "scan_for_project",
    "scans_for_project",
    "write_audit_log",
]
