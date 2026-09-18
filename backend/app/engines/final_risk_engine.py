"""Combine the two independent risk tracks into an auditable verdict."""

# ruff: noqa: E501

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.engines.mosca_engine import evaluate_mosca
from app.engines.profiles.loader import RiskProfiles
from app.engines.resource_engine import evaluate_resources
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    BusinessCriticality,
    Confidence,
    DataClassification,
    ExposureLevel,
    KeyManagementKind,
    Primitive,
    Purpose,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
)
from app.schemas.artefact import CryptoArtefact
from app.schemas.common import TrinetraModel
from app.schemas.context import ArtefactContext
from app.schemas.risk import RiskAssessment, ScoreContribution, band_for_score


class RiskSettings(TrinetraModel):
    """Explicit per-run settings; values are inputs, never ambient state."""

    planning_horizon_years: float | None = None
    scenario: ResourceScenario = ResourceScenario.BASELINE


@dataclass(frozen=True)
class HNDLResult:
    """Whether sensitive traffic is exposed to retrospective decryption risk."""

    state: str
    reason: str


def _security_token(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"[^a-z0-9+]", "", value.lower()) or None


def _policy_reason(
    artefact: CryptoArtefact, profiles: RiskProfiles
) -> tuple[AssessmentStatus, str] | None:
    if artefact.asset_type is AssetType.LIBRARY:
        return (
            AssessmentStatus.DEPENDENCY_ONLY,
            "Dependency-only library finding: an installed implementation does not prove an algorithm is in use.",
        )

    token = _security_token(artefact.algorithm or artefact.name)
    broken = {
        _security_token(item)
        for item in profiles.current_security.classically_broken_algorithms
    }
    resistant = {
        _security_token(item)
        for item in profiles.current_security.quantum_resistant_algorithms
    }
    if (
        artefact.quantum_vulnerability is QuantumVulnerability.CLASSICALLY_BROKEN
        or token in broken
    ):
        return (
            AssessmentStatus.POLICY_DECIDED,
            "Current-security policy classifies this algorithm as already classically broken; it receives no quantum-risk score.",
        )
    if (
        artefact.quantum_vulnerability is QuantumVulnerability.QUANTUM_SAFE
        or token in resistant
    ):
        return (
            AssessmentStatus.NOT_APPLICABLE,
            "Current-security policy recognises this algorithm as quantum-resistant; it receives no quantum-risk score.",
        )
    return None


def _effective_quantum_vulnerability(artefact: CryptoArtefact) -> QuantumVulnerability:
    """Classify a known primitive when scanner output omitted its derived label.

    The scanner has already supplied the primitive at this point.  Track B
    derives the quantum attack class from that canonical observation rather
    than guessing from a package name or unrecognised algorithm spelling.
    Explicit scanner classifications still take precedence, including an
    explicit ``unknown`` only when the primitive itself is absent or other.
    """
    if artefact.quantum_vulnerability is not QuantumVulnerability.UNKNOWN:
        return artefact.quantum_vulnerability
    if artefact.primitive in {
        Primitive.PKE,
        Primitive.SIGNATURE,
        Primitive.KEY_AGREEMENT,
        Primitive.KEM,
    }:
        return QuantumVulnerability.SHOR_BROKEN
    if artefact.primitive in {
        Primitive.BLOCK_CIPHER,
        Primitive.STREAM_CIPHER,
        Primitive.HASH,
        Primitive.MAC,
        Primitive.AEAD,
    }:
        return QuantumVulnerability.GROVER_WEAKENED
    return QuantumVulnerability.UNKNOWN


def hndl_status(
    artefact: CryptoArtefact,
    context: ArtefactContext,
    *,
    x_years: int | None,
    resource_years: float | None,
) -> HNDLResult:
    """Separate retrospective confidentiality risk from later signature risk."""
    signature_only = bool(artefact.purposes) and all(
        purpose in {Purpose.DIGITAL_SIGNATURE, Purpose.VERIFY}
        for purpose in artefact.purposes
    )
    if signature_only:
        return HNDLResult(
            "authenticity_at_crqc",
            "This is a signature/authenticity risk. It matters when a CRQC exists, rather than enabling decryption of traffic recorded today.",
        )

    protects_transit = any(
        purpose in {Purpose.KEY_AGREEMENT, Purpose.KEY_ENCAPSULATION}
        for purpose in artefact.purposes
    )
    sensitive = context.data_classification in {
        DataClassification.RESTRICTED,
        DataClassification.CONFIDENTIAL,
    }
    if not protects_transit or not sensitive:
        return HNDLResult(
            "not_demonstrated",
            "HNDL requires sensitive data in transit under a classical key exchange.",
        )
    if _effective_quantum_vulnerability(artefact) is not QuantumVulnerability.SHOR_BROKEN:
        return HNDLResult(
            "not_demonstrated",
            "The observed key exchange is not confirmed Shor-vulnerable.",
        )
    if x_years is None or resource_years is None:
        return HNDLResult(
            "needs_context",
            "Sensitive transit is present, but its confidentiality lifetime or resource horizon is not evidenced.",
        )
    if x_years > resource_years:
        return HNDLResult(
            "harvest_now_decrypt_later",
            "Sensitive transit can outlive the projected quantum attack horizon, so recorded traffic may be decryptable later.",
        )
    return HNDLResult(
        "not_long_lived",
        "The stated confidentiality lifetime does not extend beyond the projected attack horizon.",
    )


def _scoring(profiles: RiskProfiles, group: str) -> dict[str, Any]:
    value = profiles.weights.scoring.get(group)
    if not isinstance(
        value, dict
    ):  # profile validation keeps this defensive branch unreachable
        raise ValueError(f"risk profile has no scoring table for {group!r}")
    return value


def _contribution(
    factor: str,
    points: float,
    profiles: RiskProfiles,
    has_evidence: bool,
    reason: str,
) -> ScoreContribution:
    return ScoreContribution(
        factor=factor,
        points=points,
        max_points=profiles.weights.weights[factor],
        has_evidence=has_evidence,
        reason=reason,
    )


def _algorithm_contribution(
    artefact: CryptoArtefact, profiles: RiskProfiles
) -> ScoreContribution:
    maximum = profiles.weights.weights["algorithm_quantum_vulnerability"]
    vulnerability = _effective_quantum_vulnerability(artefact)
    if vulnerability is QuantumVulnerability.SHOR_BROKEN:
        return _contribution(
            "algorithm_quantum_vulnerability",
            maximum,
            profiles,
            True,
            "The observed public-key algorithm is Shor-breakable.",
        )
    if vulnerability is QuantumVulnerability.GROVER_WEAKENED:
        return _contribution(
            "algorithm_quantum_vulnerability",
            maximum / 2,
            profiles,
            True,
            "The observed symmetric or hash algorithm is quantum-weakened by Grover's algorithm.",
        )
    return _contribution(
        "algorithm_quantum_vulnerability",
        0,
        profiles,
        False,
        "No confirmed quantum-vulnerability classification was observed.",
    )


def _mosca_contribution(
    mosca_shortfall: float | None, profiles: RiskProfiles
) -> ScoreContribution:
    maximum = profiles.weights.weights["mosca_timing_risk"]
    if mosca_shortfall is None:
        return _contribution(
            "mosca_timing_risk", 0, profiles, False, "Mosca timing could not be resolved."
        )
    points_per_year = profiles.weights.scoring["mosca_points_per_shortfall_year"]
    if not isinstance(points_per_year, int | float):
        raise ValueError("mosca_points_per_shortfall_year must be numeric")
    points = min(maximum, max(0.0, mosca_shortfall) * points_per_year)
    if points == 0:
        reason = "Migration finishes by the Mosca horizon; there is no timing shortfall."
    else:
        reason = f"Migration is {mosca_shortfall:g} years beyond the Mosca horizon."
    return _contribution("mosca_timing_risk", points, profiles, True, reason)


def _resource_contribution(
    status: QuantumProjectionStatus,
    m_years: float | None,
    profiles: RiskProfiles,
) -> ScoreContribution:
    maximum = profiles.weights.weights["resource_feasibility"]
    if status is QuantumProjectionStatus.MODEL_UNAVAILABLE:
        return _contribution(
            "resource_feasibility",
            0,
            profiles,
            False,
            "No comparable two-dimensional resource model was available.",
        )
    if status is QuantumProjectionStatus.BEYOND_HORIZON:
        return _contribution(
            "resource_feasibility",
            0,
            profiles,
            True,
            "A cited model was available, but neither resource dimension crossed within its horizon.",
        )
    if m_years is None:
        return _contribution(
            "resource_feasibility",
            0,
            profiles,
            False,
            "Resource timing was not resolved.",
        )
    table = _scoring(profiles, "resource_feasibility")
    if m_years <= 5:
        points = table["within_5_years"]
    elif m_years <= 10:
        points = table["within_10_years"]
    elif m_years <= 15:
        points = table["within_15_years"]
    else:
        points = table["later_within_horizon"]
    if not isinstance(points, int | float):
        raise ValueError("resource-feasibility points must be numeric")
    return _contribution(
        "resource_feasibility",
        min(maximum, points),
        profiles,
        True,
        f"Both projected resource dimensions first meet Q in {m_years:g} years.",
    )


def _data_contribution(
    context: ArtefactContext, profiles: RiskProfiles
) -> ScoreContribution:
    classification = context.data_classification
    source = "business context"
    if classification is DataClassification.UNKNOWN and context.data_category:
        category = profiles.retention.categories.get(context.data_category)
        if category is not None:
            classification = DataClassification(category.sensitivity)
            source = f"retention profile category {context.data_category!r}"
    if classification is DataClassification.UNKNOWN:
        return _contribution(
            "data_sensitivity",
            0,
            profiles,
            False,
            "No data-classification evidence was supplied.",
        )
    table = _scoring(profiles, "data_classification")
    points = table[classification.value]
    if not isinstance(points, int | float):
        raise ValueError("data-classification points must be numeric")
    return _contribution(
        "data_sensitivity",
        points,
        profiles,
        True,
        f"Data classification is {classification.value} ({source}).",
    )


def _context_enum_contribution(
    *,
    factor: str,
    value: BusinessCriticality | ExposureLevel,
    unknown: BusinessCriticality | ExposureLevel,
    scoring_group: str,
    profiles: RiskProfiles,
) -> ScoreContribution:
    if value is unknown:
        return _contribution(
            factor,
            0,
            profiles,
            False,
            f"No {factor.replace('_', ' ')} evidence was supplied.",
        )
    points = _scoring(profiles, scoring_group)[value.value]
    if not isinstance(points, int | float):
        raise ValueError(f"{factor} points must be numeric")
    return _contribution(
        factor,
        points,
        profiles,
        True,
        f"{factor.replace('_', ' ').capitalize()} is {value.value}.",
    )


def _migration_contribution(
    artefact: CryptoArtefact, profiles: RiskProfiles
) -> ScoreContribution:
    table = _scoring(profiles, "migration_complexity")
    detail = artefact.detail
    key = None
    reason = None
    if (
        artefact.asset_type is AssetType.HARDWARE_MODULE
        and getattr(detail, "supports_pqc", None) is False
    ):
        key = "non_pqc_hsm"
        reason = (
            "The HSM firmware is not PQC-capable, making migration a hardware purchase."
        )
    elif (
        artefact.asset_type is AssetType.HARDWARE_MODULE
        and getattr(detail, "supports_pqc", None) is True
    ):
        key = "pqc_capable_hsm"
        reason = "The HSM reports PQC-capable firmware."
    elif getattr(detail, "key_management", None) is KeyManagementKind.PROVIDER_MANAGED:
        key = "provider_managed_key"
        reason = "Provider-managed key material requires provider coordination."
    elif artefact.asset_type is AssetType.ALGORITHM:
        key = "source_algorithm"
        reason = "A detected algorithm use requires an application code or configuration change."
    if key is None or reason is None:
        return _contribution(
            "migration_complexity",
            0,
            profiles,
            False,
            "No migration-complexity evidence was observed.",
        )
    points = table[key]
    if not isinstance(points, int | float):
        raise ValueError("migration-complexity points must be numeric")
    return _contribution("migration_complexity", points, profiles, True, reason)


def _missing_track_fields(assessment: RiskAssessment) -> list[str]:
    missing: list[str] = []
    if assessment.mosca.x_years is None:
        missing.append("data_lifetime_years")
    if assessment.mosca.y_years is None:
        missing.append("migration_time_years")
    if assessment.mosca.z_years is None:
        missing.append("threat_horizon_years")
    if assessment.resource.status is QuantumProjectionStatus.MODEL_UNAVAILABLE:
        missing.append("quantum_resource_model")
    return missing


def classify_risk(
    artefact: CryptoArtefact,
    context: ArtefactContext,
    profiles: RiskProfiles,
    settings: RiskSettings,
    *,
    assessment_id: str,
    assessed_at: datetime,
) -> RiskAssessment:
    """Produce an immutable, deterministic risk verdict from explicit inputs.

    ``assessment_id`` and ``assessed_at`` are supplied by orchestration rather
    than generated here.  That keeps this function pure and makes replaying an
    old profile/context combination byte-for-byte reproducible.
    """
    policy = _policy_reason(artefact, profiles)
    common = {
        "assessment_id": assessment_id,
        "artefact_id": artefact.artefact_id,
        "scan_id": artefact.scan_id,
        "policy_version": profiles.current_security.version,
        "weights_version": profiles.weights.version,
        "quantum_forecast_profile_version": profiles.quantum.version,
        "assessed_at": assessed_at,
        "input_provenance": {
            key: value.tier.value for key, value in sorted(context.provenance.items())
        },
    }
    if policy is not None:
        status, rationale = policy
        return RiskAssessment(
            **common,
            status=status,
            rationale=rationale,
        )

    resource = evaluate_resources(artefact, profiles.quantum, scenario=settings.scenario)
    mosca = evaluate_mosca(
        context,
        profiles.retention,
        planning_horizon_years=settings.planning_horizon_years,
        resource=resource,
    )
    contributions = [
        _algorithm_contribution(artefact, profiles),
        _mosca_contribution(mosca.shortfall_years, profiles),
        _resource_contribution(resource.status, resource.m_years, profiles),
        _data_contribution(context, profiles),
        _context_enum_contribution(
            factor="business_criticality",
            value=context.business_criticality,
            unknown=BusinessCriticality.UNKNOWN,
            scoring_group="business_criticality",
            profiles=profiles,
        ),
        _context_enum_contribution(
            factor="exposure",
            value=context.exposure,
            unknown=ExposureLevel.UNKNOWN,
            scoring_group="exposure",
            profiles=profiles,
        ),
        _migration_contribution(artefact, profiles),
    ]
    draft = RiskAssessment(
        **common,
        status=AssessmentStatus.NEEDS_CONTEXT,
        mosca=mosca,
        resource=resource,
        contributions=contributions,
        missing_fields=["pending_track_resolution"],
    )
    missing = _missing_track_fields(draft)
    if missing:
        return draft.model_copy(
            update={
                "missing_fields": missing,
                "rationale": "A comparable score needs both the Mosca and quantum-resource tracks; supply the listed evidence.",
            }
        )

    final_score = sum(item.points for item in contributions)
    track_confidences = [
        value for value in (mosca.confidence, resource.confidence) if value
    ]
    final_confidence = Confidence.weaker(*track_confidences)
    if any(not contribution.has_evidence for contribution in contributions):
        final_confidence = final_confidence.downgrade()
    hndl = hndl_status(
        artefact,
        context,
        x_years=mosca.x_years,
        resource_years=resource.m_years,
    )
    return RiskAssessment(
        **common,
        status=AssessmentStatus.SCORED,
        final_score=final_score,
        final_confidence=final_confidence,
        priority=band_for_score(final_score),
        mosca=mosca,
        resource=resource,
        contributions=contributions,
        rationale=(f"Two-track score {final_score:g}/100. {hndl.reason}"),
    )


def rescore_all(
    items: Iterable[tuple[CryptoArtefact, ArtefactContext, str]],
    profiles: RiskProfiles,
    settings: RiskSettings,
    *,
    assessed_at: datetime,
) -> list[RiskAssessment]:
    """Recalculate a batch from stored artefact/context provenance.

    Persistence owns the append-only insert and creates the immutable settings
    version.  This deliberately side-effect-free half guarantees that every
    changed profile or horizon is a genuine re-evaluation rather than a priority
    relabel.
    """
    return [
        classify_risk(
            artefact,
            context,
            profiles,
            settings,
            assessment_id=assessment_id,
            assessed_at=assessed_at,
        )
        for artefact, context, assessment_id in items
    ]


__all__ = [
    "HNDLResult",
    "RiskSettings",
    "classify_risk",
    "hndl_status",
    "rescore_all",
]
