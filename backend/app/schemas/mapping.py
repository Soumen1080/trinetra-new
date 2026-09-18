"""Conversion between Pydantic schemas and SQLAlchemy rows.

Kept in one module so the object <-> row translation is auditable in a single
place, mirroring the repository layer's role for SQL. The round-trip property
(object -> row -> object is the identity) is asserted in
``tests/models/test_roundtrip.py``.
"""

from __future__ import annotations

from typing import Any

from app.models import tables
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    BusinessCriticality,
    Confidence,
    DataClassification,
    DetectionMethod,
    ExposureLevel,
    MoscaZBasis,
    NistSecurityLevel,
    Primitive,
    Priority,
    Purpose,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
    ScannerKind,
)
from app.schemas.artefact import (
    AlgorithmDetail,
    ArtefactDetail,
    CertificateDetail,
    CloudServiceDetail,
    CryptoArtefact,
    HardwareModuleDetail,
    KeyDetail,
    LibraryDetail,
    ProtocolDetail,
    RelatedMaterialDetail,
)
from app.schemas.common import Evidence, Provenance, SourceLocation
from app.schemas.context import ArtefactContext, RetentionEvidence
from app.schemas.recommendation import (
    DeploymentDimension,
    PqcRecommendation,
    PublishedPqcFacts,
)
from app.schemas.risk import MoscaTrack, ResourceTrack, RiskAssessment, ScoreContribution

_DETAIL_MODELS: dict[AssetType, type] = {
    AssetType.ALGORITHM: AlgorithmDetail,
    AssetType.KEY: KeyDetail,
    AssetType.CERTIFICATE: CertificateDetail,
    AssetType.PROTOCOL: ProtocolDetail,
    AssetType.LIBRARY: LibraryDetail,
    AssetType.HARDWARE_MODULE: HardwareModuleDetail,
    AssetType.CLOUD_SERVICE: CloudServiceDetail,
    AssetType.RELATED_MATERIAL: RelatedMaterialDetail,
}


def _dump(model: Any) -> Any:
    """Serialise a Pydantic model to JSON-safe primitives."""
    return model.model_dump(mode="json") if model is not None else None


# ---------------------------------------------------------------------------
# Artefact
# ---------------------------------------------------------------------------


def artefact_to_row(artefact: CryptoArtefact, *, scan_id: str) -> tables.Artefact:
    """Build a row from an artefact.

    Flattens the R19 fields (mode, padding, key size, curve) out of ``detail``
    into dedicated columns so they are queryable and indexable, while the full
    typed detail is preserved in ``detail_json``.
    """
    detail = artefact.detail
    algorithm_detail = detail if isinstance(detail, AlgorithmDetail) else None

    key_size = getattr(detail, "key_size_bits", None) or getattr(
        detail, "size_bits", None
    )
    if key_size is None and isinstance(detail, CertificateDetail):
        key_size = detail.public_key_size_bits

    curve = getattr(detail, "curve", None)
    if curve is None and isinstance(detail, CertificateDetail):
        curve = detail.public_key_curve

    primary = artefact.evidence[0]

    return tables.Artefact(
        id=artefact.artefact_id,
        scan_id=scan_id,
        type=artefact.asset_type.value,
        name=artefact.name,
        algorithm=artefact.algorithm,
        oid=artefact.oid,
        primitive=artefact.primitive.value if artefact.primitive else None,
        purpose=[p.value for p in artefact.purposes] or None,
        key_size_bits=key_size,
        size_or_version=(
            algorithm_detail.parameter_set if algorithm_detail else None
        ),
        mode=(
            algorithm_detail.mode.value
            if algorithm_detail and algorithm_detail.mode
            else None
        ),
        padding=(
            algorithm_detail.padding.value
            if algorithm_detail and algorithm_detail.padding
            else None
        ),
        curve=curve,
        quantum_vulnerability=artefact.quantum_vulnerability.value,
        nist_security_level=artefact.nist_security_level.value,
        location=primary.location.render(),
        used_for=primary.additional_context,
        discovered_by=artefact.discovered_by.value,
        detail_json=_dump(detail),
        evidence_json=[_dump(e) for e in artefact.evidence],
        raw_cbom=artefact.raw_cbom,
        first_seen=artefact.first_seen,
        last_seen=artefact.last_seen,
    )


def artefact_from_row(row: tables.Artefact) -> CryptoArtefact:
    """Rebuild an artefact from its row.

    Reads structured state back from ``detail_json`` and ``evidence_json``
    rather than from the flattened columns, so the reconstruction is exact.
    """
    asset_type = AssetType(row.type)

    detail: ArtefactDetail | None = None
    if row.detail_json:
        detail = _DETAIL_MODELS[asset_type].model_validate(row.detail_json)

    evidence = [Evidence.model_validate(item) for item in (row.evidence_json or [])]
    if not evidence:
        # Defensive: a persisted artefact always has evidence, but rebuilding
        # must not crash on legacy rows -- surface the gap instead.
        evidence = [
            Evidence(
                location=SourceLocation(path=row.location or "unknown"),
                detection_method=DetectionMethod.OTHER,
                confidence=Confidence.LOW,
                additional_context="evidence missing from storage",
            )
        ]

    return CryptoArtefact(
        artefact_id=row.id,
        scan_id=row.scan_id,
        asset_type=asset_type,
        name=row.name,
        algorithm=row.algorithm,
        oid=row.oid,
        primitive=Primitive(row.primitive) if row.primitive else None,
        purposes=[Purpose(p) for p in (row.purpose or [])],
        quantum_vulnerability=QuantumVulnerability(row.quantum_vulnerability),
        nist_security_level=NistSecurityLevel(row.nist_security_level),
        detail=detail,
        evidence=evidence,
        discovered_by=ScannerKind(row.discovered_by),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        raw_cbom=row.raw_cbom,
    )


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def context_to_row(context: ArtefactContext, *, row_id: str) -> tables.ArtefactContext:
    return tables.ArtefactContext(
        id=row_id,
        artefact_id=context.artefact_id,
        application_id=context.application_id,
        business_criticality=context.business_criticality.value,
        data_classification=context.data_classification.value,
        exposure=context.exposure.value,
        data_category=context.data_category,
        data_lifetime_years=context.data_lifetime_years,
        migration_time_years=context.migration_time_years,
        retention_evidence_json=[_dump(e) for e in context.retention_evidence] or None,
        provenance_json={k: _dump(v) for k, v in context.provenance.items()} or None,
        updated_by=context.updated_by,
    )


def context_from_row(row: tables.ArtefactContext) -> ArtefactContext:
    return ArtefactContext(
        artefact_id=row.artefact_id,
        application_id=row.application_id,
        business_criticality=BusinessCriticality(row.business_criticality),
        data_classification=DataClassification(row.data_classification),
        exposure=ExposureLevel(row.exposure),
        data_category=row.data_category,
        data_lifetime_years=row.data_lifetime_years,
        migration_time_years=row.migration_time_years,
        retention_evidence=[
            RetentionEvidence.model_validate(e)
            for e in (row.retention_evidence_json or [])
        ],
        provenance={
            k: Provenance.model_validate(v)
            for k, v in (row.provenance_json or {}).items()
        },
        updated_at=row.updated_at,
        updated_by=row.updated_by,
    )


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------


def assessment_to_row(assessment: RiskAssessment) -> tables.RiskAssessment:
    """Flatten both tracks into their dedicated columns.

    Storing the tracks in full is what makes a verdict re-derivable rather than
    merely re-displayable.
    """
    mosca = assessment.mosca
    resource = assessment.resource

    return tables.RiskAssessment(
        id=assessment.assessment_id,
        artefact_id=assessment.artefact_id,
        scan_id=assessment.scan_id,
        status=assessment.status.value,
        final_score=assessment.final_score,
        final_confidence=(
            assessment.final_confidence.value if assessment.final_confidence else None
        ),
        priority=assessment.priority.value,
        mosca_x_years=mosca.x_years,
        mosca_y_years=mosca.y_years,
        mosca_z_years=mosca.z_years,
        mosca_z_basis=mosca.z_basis.value,
        mosca_is_urgent=mosca.is_urgent,
        mosca_shortfall_years=mosca.shortfall_years,
        mosca_evidence_json=list(mosca.evidence) or None,
        resource_m_years=resource.m_years,
        resource_scenario=resource.scenario.value,
        resource_assumptions_json=dict(resource.assumptions) or None,
        attack_threshold_json=(
            {
                "logical_qubits_required": resource.logical_qubits_required,
                "gate_count_required": resource.gate_count_required,
                "caveats": resource.caveats,
                "confidence": (
                    resource.confidence.value if resource.confidence else None
                ),
            }
            if resource.logical_qubits_required is not None
            or resource.gate_count_required is not None
            or resource.caveats
            or resource.confidence is not None
            else None
        ),
        forecast_capability_json=dict(resource.forecast_capability) or None,
        projected_break_year=resource.projected_break_year,
        migration_deadline_year=resource.migration_deadline_year,
        quantum_projection_status=resource.status.value,
        score_contributions_json=[_dump(c) for c in assessment.contributions] or None,
        missing_fields_json=list(assessment.missing_fields) or None,
        input_provenance_json=dict(assessment.input_provenance) or None,
        rationale=assessment.rationale,
        policy_version=assessment.policy_version,
        weights_version=assessment.weights_version,
        quantum_forecast_profile_version=assessment.quantum_forecast_profile_version,
        assessed_at=assessment.assessed_at,
    )


def assessment_from_row(row: tables.RiskAssessment) -> RiskAssessment:
    threshold = row.attack_threshold_json or {}
    mosca_confidence = None
    if row.final_confidence:
        mosca_confidence = Confidence(row.final_confidence)

    return RiskAssessment(
        assessment_id=row.id,
        artefact_id=row.artefact_id,
        scan_id=row.scan_id,
        status=AssessmentStatus(row.status),
        final_score=row.final_score,
        final_confidence=(
            Confidence(row.final_confidence) if row.final_confidence else None
        ),
        priority=Priority(row.priority),
        mosca=MoscaTrack(
            x_years=row.mosca_x_years,
            y_years=row.mosca_y_years,
            z_years=row.mosca_z_years,
            z_basis=MoscaZBasis(row.mosca_z_basis),
            is_urgent=row.mosca_is_urgent,
            shortfall_years=row.mosca_shortfall_years,
            confidence=mosca_confidence,
            evidence=list(row.mosca_evidence_json or []),
        ),
        resource=ResourceTrack(
            m_years=row.resource_m_years,
            scenario=ResourceScenario(row.resource_scenario),
            status=QuantumProjectionStatus(row.quantum_projection_status),
            projected_break_year=row.projected_break_year,
            migration_deadline_year=row.migration_deadline_year,
            logical_qubits_required=threshold.get("logical_qubits_required"),
            gate_count_required=threshold.get("gate_count_required"),
            assumptions=dict(row.resource_assumptions_json or {}),
            caveats=list(threshold.get("caveats") or []),
            confidence=(
                Confidence(threshold["confidence"])
                if threshold.get("confidence")
                else None
            ),
            forecast_capability=dict(row.forecast_capability_json or {}),
        ),
        contributions=[
            ScoreContribution.model_validate(c)
            for c in (row.score_contributions_json or [])
        ],
        missing_fields=list(row.missing_fields_json or []),
        input_provenance=dict(row.input_provenance_json or {}),
        rationale=row.rationale,
        policy_version=row.policy_version,
        weights_version=row.weights_version,
        quantum_forecast_profile_version=row.quantum_forecast_profile_version,
        assessed_at=row.assessed_at,
    )


# ---------------------------------------------------------------------------
# Recommendation
# ---------------------------------------------------------------------------


def recommendation_to_row(recommendation: PqcRecommendation) -> tables.Recommendation:
    """Store the complete evidence shape while retaining queryable core fields."""
    dimensions = {
        dimension.name: _dump(dimension)
        for dimension in recommendation.deployment_dimensions
    }
    return tables.Recommendation(
        id=recommendation.recommendation_id,
        assessment_id=recommendation.assessment_id,
        recommended_algorithm=recommendation.recommended_algorithm,
        recommended_parameter_set=recommendation.recommended_parameter_set,
        security_category=recommendation.security_category,
        classical_partner=recommendation.classical_partner,
        is_hybrid=recommendation.is_hybrid,
        requires_manual_review=recommendation.requires_manual_review,
        rationale=recommendation.rationale,
        fit_score=None,
        fit_breakdown_json={
            "fit_score": None,
            "published_facts": _dump(recommendation.published_facts),
            "deployment_dimensions": dimensions,
        },
        latency_impact_json=dimensions.get("latency"),
        cost_estimate_json=dimensions.get("cost"),
        profile_version=recommendation.profile_version,
    )


def recommendation_from_row(row: tables.Recommendation) -> PqcRecommendation:
    """Rebuild a Phase-6 recommendation without synthesising a fit score."""
    breakdown = row.fit_breakdown_json or {}
    facts_payload = breakdown.get("published_facts")
    dimension_payloads = breakdown.get("deployment_dimensions") or {}
    return PqcRecommendation(
        recommendation_id=row.id,
        assessment_id=row.assessment_id,
        recommended_algorithm=row.recommended_algorithm,
        recommended_parameter_set=row.recommended_parameter_set,
        security_category=row.security_category,
        classical_partner=row.classical_partner,
        is_hybrid=row.is_hybrid,
        requires_manual_review=row.requires_manual_review,
        rationale=row.rationale or "Recommendation rationale was not persisted.",
        published_facts=(
            PublishedPqcFacts.model_validate(facts_payload)
            if facts_payload is not None
            else None
        ),
        deployment_dimensions=[
            DeploymentDimension.model_validate(payload)
            for payload in dimension_payloads.values()
        ],
        fit_score=row.fit_score,
        profile_version=row.profile_version or "legacy-unknown",
    )


__all__ = [
    "artefact_from_row",
    "artefact_to_row",
    "assessment_from_row",
    "assessment_to_row",
    "context_from_row",
    "context_to_row",
    "recommendation_from_row",
    "recommendation_to_row",
]
