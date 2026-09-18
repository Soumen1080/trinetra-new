"""Track A: resolve Mosca's X + Y > Z without inventing business context."""

from __future__ import annotations

from dataclasses import dataclass

from app.engines.profiles.loader import RetentionCategory, RetentionProfile
from app.models.enums import (
    Confidence,
    EvidenceSource,
    MoscaZBasis,
    ProvenanceTier,
    QuantumProjectionStatus,
    RetentionBasis,
)
from app.schemas.context import ArtefactContext, RetentionEvidence
from app.schemas.risk import MoscaTrack, ResourceTrack

_SOURCE_RANK = {
    EvidenceSource.USER: 0,
    EvidenceSource.SCANNER: 1,
    EvidenceSource.ORG_POLICY: 2,
    EvidenceSource.LEGAL_PROFILE: 3,
}
_SOURCE_CONFIDENCE = {
    EvidenceSource.USER: Confidence.HIGH,
    EvidenceSource.SCANNER: Confidence.MEDIUM,
    EvidenceSource.ORG_POLICY: Confidence.HIGH,
    EvidenceSource.LEGAL_PROFILE: Confidence.LOW,
}


@dataclass(frozen=True)
class _Candidate:
    evidence: RetentionEvidence
    confidence: Confidence


def _source_for_tier(tier: ProvenanceTier) -> EvidenceSource:
    return {
        ProvenanceTier.USER: EvidenceSource.USER,
        ProvenanceTier.SCANNER_EVIDENCE: EvidenceSource.SCANNER,
        ProvenanceTier.ORG_PRESET: EvidenceSource.ORG_POLICY,
    }.get(tier, EvidenceSource.LEGAL_PROFILE)


def _category_evidence(
    context: ArtefactContext, profile: RetentionProfile
) -> RetentionEvidence | None:
    if context.data_category is None:
        return None
    category: RetentionCategory | None = profile.categories.get(context.data_category)
    if category is None:
        return None
    source = _source_for_tier(context.provenance_of("data_category").tier)
    return RetentionEvidence(
        source=source,
        data_category=context.data_category,
        lifetime_years=category.lifetime_years,
        basis=RetentionBasis(category.basis),
        citation=category.source_id,
        caveat=category.caveat,
    )


def _direct_lifetime_evidence(context: ArtefactContext) -> RetentionEvidence | None:
    if context.data_lifetime_years is None:
        return None
    tier = context.provenance_of("data_lifetime_years").tier
    if tier not in {ProvenanceTier.USER, ProvenanceTier.ORG_PRESET}:
        # Older rows with a bare number are not evidence.  The data remains
        # visible, but risk scoring must not promote it to an asserted fact.
        return None
    source = _source_for_tier(tier)
    return RetentionEvidence(
        source=source,
        data_category=context.data_category or "explicit_lifetime",
        lifetime_years=context.data_lifetime_years,
        basis=RetentionBasis.ASSUMPTION,
        citation=context.provenance_of("data_lifetime_years").source_detail,
        caveat="Explicit organisation or user-supplied confidentiality lifetime.",
    )


def _resolve_x(
    context: ArtefactContext, profile: RetentionProfile
) -> tuple[int | None, Confidence | None, list[str]]:
    raw = [*context.retention_evidence]
    direct = _direct_lifetime_evidence(context)
    if direct is not None:
        raw.append(direct)
    profile_entry = _category_evidence(context, profile)
    if profile_entry is not None:
        raw.append(profile_entry)
    if not raw:
        return None, None, []

    candidates = [_Candidate(item, _SOURCE_CONFIDENCE[item.source]) for item in raw]
    strongest_rank = min(_SOURCE_RANK[item.evidence.source] for item in candidates)
    strongest = [
        item
        for item in candidates
        if _SOURCE_RANK[item.evidence.source] == strongest_rank
    ]
    governing = max(strongest, key=lambda item: item.evidence.lifetime_years)
    descriptions = [
        f"{item.evidence.source.value}:{item.evidence.data_category}="
        f"{item.evidence.lifetime_years}y"
        + (f" ({item.evidence.citation})" if item.evidence.citation else "")
        for item in sorted(
            strongest,
            key=lambda item: (item.evidence.data_category, item.evidence.lifetime_years),
        )
    ]
    return governing.evidence.lifetime_years, governing.confidence, descriptions


def _confidence_for_context_value(context: ArtefactContext, field: str) -> Confidence:
    tier = context.provenance_of(field).tier
    if tier in {ProvenanceTier.USER, ProvenanceTier.ORG_PRESET}:
        return Confidence.HIGH
    return Confidence.LOW


def evaluate_mosca(
    context: ArtefactContext,
    profile: RetentionProfile,
    *,
    planning_horizon_years: float | None,
    resource: ResourceTrack,
) -> MoscaTrack:
    """Resolve the ordered evidence chain and evaluate ``X + Y > Z``.

    There are no default X or Y values.  The resource-model horizon is offered
    only when an explicit organisational planning horizon was not supplied.
    """
    x_years, x_confidence, evidence = _resolve_x(context, profile)
    y_years = context.migration_time_years

    z_years: float | None = None
    z_basis = MoscaZBasis.UNAVAILABLE
    z_confidence: Confidence | None = None
    if planning_horizon_years is not None:
        z_years = planning_horizon_years
        z_basis = MoscaZBasis.ORG_HORIZON
        z_confidence = Confidence.HIGH
    elif (
        resource.status is QuantumProjectionStatus.CALCULATED
        and resource.m_years is not None
    ):
        z_years = resource.m_years
        z_basis = MoscaZBasis.RESOURCE_MODEL
        z_confidence = resource.confidence

    if None in (x_years, y_years, z_years):
        return MoscaTrack(
            x_years=x_years,
            y_years=y_years,
            z_years=z_years,
            z_basis=z_basis,
            confidence=None,
            evidence=evidence,
        )

    shortfall = float(x_years + y_years - z_years)
    confidence_values = [
        value
        for value in (
            x_confidence,
            _confidence_for_context_value(context, "migration_time_years"),
            z_confidence,
        )
        if value is not None
    ]
    return MoscaTrack(
        x_years=x_years,
        y_years=y_years,
        z_years=z_years,
        z_basis=z_basis,
        is_urgent=shortfall > 0,
        shortfall_years=shortfall,
        confidence=Confidence.weaker(*confidence_values),
        evidence=evidence,
    )


__all__ = ["evaluate_mosca"]
