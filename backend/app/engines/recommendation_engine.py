"""Pure, cited PQC recommendations for actionable risk assessments only."""

from __future__ import annotations

from hashlib import sha256

from app.engines.profiles.loader import (
    PqcEvidenceProfile,
    PqcParameterSet,
    PqcRecommendationRule,
)
from app.engines.resource_engine import key_size_bits, normalise_algorithm
from app.models.enums import AssessmentStatus, Priority
from app.schemas.recommendation import (
    DeploymentDimension,
    PqcRecommendation,
    PublishedPqcFacts,
    RecommendationContext,
)

DEFAULT_CLASSICAL_PARTNER = "X25519"
_ACTIONABLE_PRIORITIES = frozenset({Priority.P0, Priority.P1})
_UNMEASURED_DIMENSIONS = (
    "latency",
    "protocol_compatibility",
    "mtu_impact",
    "cost",
)


def recommendation_id_for_assessment(assessment_id: str) -> str:
    """Create a deterministic, database-safe ID for the assessment's one row."""
    return sha256(f"recommendation:{assessment_id}".encode()).hexdigest()


def _manual_review(
    context: RecommendationContext, reason: str, version: str
) -> PqcRecommendation:
    return PqcRecommendation(
        recommendation_id=context.recommendation_id,
        assessment_id=context.assessment.assessment_id,
        requires_manual_review=True,
        rationale=f"MANUAL_REVIEW: {reason}",
        profile_version=version,
    )


def _rule_matches(
    rule: PqcRecommendationRule,
    context: RecommendationContext,
    algorithm: str,
) -> bool:
    if algorithm not in rule.current_algorithms:
        return False

    purposes = {purpose.value for purpose in context.artefact.purposes}
    if not purposes.intersection(rule.purposes):
        return False

    if (
        rule.requires_key_size_bits is not None
        and key_size_bits(context.artefact) != rule.requires_key_size_bits
    ):
        return False

    return (
        rule.requires_stateless is None
        or rule.requires_stateless == context.requirements.stateless_required
    )


def _parameter_set(
    profile: PqcEvidenceProfile,
    *,
    algorithm: str,
    security_category: int | None,
) -> PqcParameterSet | None:
    matches = [
        entry
        for entry in profile.parameter_sets
        if entry.algorithm == algorithm
        and (
            entry.security_category == security_category
            if security_category is not None
            else entry.security_category is None
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _facts(entry: PqcParameterSet, profile: PqcEvidenceProfile) -> PublishedPqcFacts:
    source = next(
        source for source in profile.sources if source.source_id == entry.source_id
    )
    return PublishedPqcFacts(
        source_id=source.source_id,
        source_url=source.url,
        public_key_bytes=entry.public_key_bytes,
        private_key_bytes=entry.private_key_bytes,
        ciphertext_bytes=entry.ciphertext_bytes,
        signature_bytes=entry.signature_bytes,
        symmetric_key_bytes=entry.symmetric_key_bytes,
    )


def _unmeasured_dimensions() -> list[DeploymentDimension]:
    return [
        DeploymentDimension(name=name, status="unmeasured")
        for name in _UNMEASURED_DIMENSIONS
    ]


def recommend_replacement(
    context: RecommendationContext,
    profile: PqcEvidenceProfile,
) -> PqcRecommendation | None:
    """Return one category-gated recommendation, or no result for P2/unscored.

    The function consumes only the supplied context and profile.  It deliberately
    emits no deployment fit score: FIPS object sizes are citable facts, while
    latency, protocol compatibility, MTU impact and cost remain unmeasured until
    the deployment owner tests them.
    """
    assessment = context.assessment
    if (
        assessment.status is not AssessmentStatus.SCORED
        or assessment.priority not in _ACTIONABLE_PRIORITIES
    ):
        return None

    algorithm = normalise_algorithm(
        context.artefact.algorithm or context.artefact.name
    )
    if algorithm is None:
        return _manual_review(
            context,
            "the scanner did not identify a current algorithm",
            profile.version,
        )

    matching_rules = [
        rule
        for rule in profile.recommendation_rules
        if _rule_matches(rule, context, algorithm)
    ]
    choices = {rule.recommended_algorithm for rule in matching_rules}
    if len(choices) != 1:
        reason = (
            f"no profile rule matches {algorithm!r} and its observed purpose"
            if not choices
            else "multiple replacement families match the observed use"
        )
        return _manual_review(context, reason, profile.version)

    recommended_algorithm = choices.pop()
    security_category = (
        context.requirements.required_security_category
        or profile.selection_policy.required_security_category
    )
    parameter_set = _parameter_set(
        profile,
        algorithm=recommended_algorithm,
        security_category=(
            None if recommended_algorithm == "aes" else security_category
        ),
    )
    if parameter_set is None:
        return _manual_review(
            context,
            "the named selection policy has no unique cited parameter set",
            profile.version,
        )

    if context.requirements.hybrid_required and recommended_algorithm != "ml-kem":
        return _manual_review(
            context,
            "hybrid mode was requested for a replacement that is not a KEM",
            profile.version,
        )

    is_hybrid = context.requirements.hybrid_required
    source = next(
        source
        for source in profile.sources
        if source.source_id == parameter_set.source_id
    )
    category_text = (
        f" at security category {security_category}"
        if recommended_algorithm != "aes"
        else ""
    )
    hybrid_text = (
        f" Pair it with {DEFAULT_CLASSICAL_PARTNER} in hybrid mode."
        if is_hybrid
        else ""
    )
    return PqcRecommendation(
        recommendation_id=context.recommendation_id,
        assessment_id=assessment.assessment_id,
        recommended_algorithm=recommended_algorithm,
        recommended_parameter_set=parameter_set.parameter_set,
        security_category=(
            None if recommended_algorithm == "aes" else security_category
        ),
        classical_partner=DEFAULT_CLASSICAL_PARTNER if is_hybrid else None,
        is_hybrid=is_hybrid,
        rationale=(
            f"{algorithm.upper()} matches profile rule {matching_rules[0].rule_id!r}; "
            f"use {parameter_set.parameter_set}{category_text}. Published object "
            f"sizes are cited to {source.title}.{hybrid_text}"
        ),
        published_facts=_facts(parameter_set, profile),
        deployment_dimensions=_unmeasured_dimensions(),
        profile_version=profile.version,
    )


__all__ = [
    "DEFAULT_CLASSICAL_PARTNER",
    "recommend_replacement",
    "recommendation_id_for_assessment",
]
