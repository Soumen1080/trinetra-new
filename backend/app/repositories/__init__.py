"""The deliberately small database boundary for risk-assessment persistence."""

from __future__ import annotations

from sqlalchemy import select, update
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


def artefacts_for_rescore(session: Session) -> list[tables.Artefact]:
    """Return every artefact with its current context in a bounded query shape."""
    statement = select(tables.Artefact).options(selectinload(tables.Artefact.context))
    return list(session.scalars(statement))


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
    "artefacts_for_rescore",
]
