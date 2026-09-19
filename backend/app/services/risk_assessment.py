"""Transactional orchestration around the Phase-5 pure risk engines."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.engines.final_risk_engine import RiskSettings, classify_risk
from app.engines.profiles.loader import (
    PqcEvidenceProfile,
    RiskProfiles,
    load_pqc_evidence_profile,
)
from app.engines.recommendation_engine import (
    recommend_replacement,
    recommendation_id_for_assessment,
)
from app.models import tables
from app.repositories import (
    activate_setting_version,
    append_assessment,
    append_recommendation,
    artefacts_for_rescore,
)
from app.schemas.artefact import CryptoArtefact
from app.schemas.context import ArtefactContext
from app.schemas.mapping import artefact_from_row, context_from_row
from app.schemas.recommendation import RecommendationContext, RecommendationRequirements
from app.schemas.risk import RiskAssessment


@dataclass(frozen=True)
class RescoreResult:
    """The audit-friendly result returned after recomputing stored artefacts."""

    artefacts_rescored: int
    recommendations_created: int
    setting_version: str


def apply_risk_settings_and_rescore(
    session: Session,
    *,
    setting_id: str,
    setting_version: str,
    project_id: str | None = None,
    profiles: RiskProfiles,
    settings: RiskSettings,
    assessment_id_for: Callable[[str], str],
    assessed_at: datetime,
    created_by: str | None = None,
    recommendation_profile: PqcEvidenceProfile | None = None,
    recommendation_requirements_for: Callable[
        [CryptoArtefact, ArtefactContext, RiskAssessment], RecommendationRequirements
    ]
    | None = None,
) -> RescoreResult:
    """Activate settings then append a newly calculated verdict for every asset.

    The function intentionally does not commit.  The API or worker invokes it
    inside one transaction, making activation and all history rows atomic.  Its
    calculation path rebuilds Pydantic inputs from stored artefact/context
    provenance, instead of relabelling old scores.
    """
    setting = tables.OrgSettingVersion(
        id=setting_id,
        project_id=project_id,
        version=setting_version,
        is_active=True,
        settings_json={
            "planning_horizon_years": settings.planning_horizon_years,
            "scenario": settings.scenario.value,
        },
        policy_version=profiles.current_security.version,
        weights_version=profiles.weights.version,
        quantum_forecast_profile_version=profiles.quantum.version,
        created_by=created_by,
    )
    activate_setting_version(session, setting)
    pqc_profile = recommendation_profile or load_pqc_evidence_profile()

    count = 0
    recommendations_created = 0
    for artefact_row in artefacts_for_rescore(session, project_id=project_id):
        artefact = artefact_from_row(artefact_row)
        context = (
            context_from_row(artefact_row.context)
            if artefact_row.context is not None
            else ArtefactContext(artefact_id=artefact.artefact_id)
        )
        assessment = classify_risk(
            artefact,
            context,
            profiles,
            settings,
            assessment_id=assessment_id_for(artefact.artefact_id),
            assessed_at=assessed_at,
        )
        append_assessment(session, assessment)
        requirements = (
            recommendation_requirements_for(artefact, context, assessment)
            if recommendation_requirements_for is not None
            else RecommendationRequirements()
        )
        recommendation = recommend_replacement(
            RecommendationContext(
                recommendation_id=recommendation_id_for_assessment(
                    assessment.assessment_id
                ),
                artefact=artefact,
                assessment=assessment,
                requirements=requirements,
            ),
            pqc_profile,
        )
        if recommendation is not None:
            append_recommendation(session, recommendation)
            recommendations_created += 1
        count += 1

    return RescoreResult(
        artefacts_rescored=count,
        recommendations_created=recommendations_created,
        setting_version=setting.version,
    )


__all__ = ["RescoreResult", "apply_risk_settings_and_rescore"]
