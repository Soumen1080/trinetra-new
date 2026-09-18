"""Phase 6: cited PQC replacement choices without fabricated fit scores."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.engines.migration_planner import plan_migration_waves
from app.engines.profiles import ProfileError, load_pqc_evidence_profile, load_profile
from app.engines.recommendation_engine import (
    DEFAULT_CLASSICAL_PARTNER,
    recommend_replacement,
)
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    Confidence,
    DependencyRelation,
    DetectionMethod,
    MoscaZBasis,
    Primitive,
    Priority,
    Purpose,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
    ScannerKind,
)
from app.models.tables import Recommendation as RecommendationRow
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact, HardwareModuleDetail
from app.schemas.common import Evidence, SourceLocation
from app.schemas.context import DependencyEdge
from app.schemas.mapping import recommendation_from_row, recommendation_to_row
from app.schemas.recommendation import (
    CryptoAgilityObservation,
    MigrationCandidate,
    RecommendationContext,
    RecommendationRequirements,
)
from app.schemas.risk import MoscaTrack, ResourceTrack, RiskAssessment

ASSESSED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _artefact(
    algorithm: str,
    purpose: Purpose,
    *,
    key_size_bits: int | None = None,
    hardware: bool = False,
) -> CryptoArtefact:
    asset_type = AssetType.HARDWARE_MODULE if hardware else AssetType.ALGORITHM
    detail = (
        HardwareModuleDetail(supports_pqc=False)
        if hardware
        else AlgorithmDetail(key_size_bits=key_size_bits)
    )
    primitive = (
        Primitive.SIGNATURE
        if purpose in {Purpose.DIGITAL_SIGNATURE, Purpose.VERIFY}
        else Primitive.BLOCK_CIPHER if algorithm == "aes" else Primitive.PKE
    )
    return CryptoArtefact.from_evidence(
        scan_target="repo://phase6",
        asset_type=asset_type,
        name=f"{algorithm}-{purpose.value}",
        algorithm=algorithm,
        primitive=primitive,
        purposes=[purpose],
        quantum_vulnerability=(
            QuantumVulnerability.GROVER_WEAKENED
            if algorithm == "aes"
            else QuantumVulnerability.SHOR_BROKEN
        ),
        detail=detail,
        evidence=[
            Evidence(
                location=SourceLocation(path=f"crypto/{algorithm}.py", line=12),
                detection_method=DetectionMethod.SEMGREP_PATTERN,
                confidence=Confidence.HIGH,
            )
        ],
        discovered_by=ScannerKind.SOURCE,
        observed_at=ASSESSED_AT,
    )


def _assessment(
    artefact: CryptoArtefact,
    *,
    assessment_id: str = "assessment-phase6",
    priority: Priority = Priority.P1,
    z_years: float = 8,
) -> RiskAssessment:
    score = {Priority.P0: 80, Priority.P1: 60, Priority.P2: 40}[priority]
    return RiskAssessment(
        assessment_id=assessment_id,
        artefact_id=artefact.artefact_id,
        status=AssessmentStatus.SCORED,
        final_score=score,
        priority=priority,
        mosca=MoscaTrack(
            x_years=20,
            y_years=3,
            z_years=z_years,
            z_basis=MoscaZBasis.ORG_HORIZON,
            is_urgent=True,
            shortfall_years=15,
        ),
        resource=ResourceTrack(
            m_years=4,
            scenario=ResourceScenario.BASELINE,
            status=QuantumProjectionStatus.CALCULATED,
        ),
        policy_version="current-security-2026.1",
        weights_version="risk-weights-2026.1",
        quantum_forecast_profile_version="quantum-capability-2026.2",
        assessed_at=ASSESSED_AT,
    )


def _recommendation(
    artefact: CryptoArtefact,
    *,
    assessment_id: str = "assessment-phase6",
    priority: Priority = Priority.P1,
    requirements: RecommendationRequirements | None = None,
):
    result = recommend_replacement(
        RecommendationContext(
            recommendation_id=f"recommendation-{assessment_id}",
            artefact=artefact,
            assessment=_assessment(
                artefact, assessment_id=assessment_id, priority=priority
            ),
            requirements=requirements or RecommendationRequirements(),
        ),
        load_pqc_evidence_profile(),
    )
    return result


@pytest.mark.parametrize(
    ("algorithm", "purpose", "key_size_bits", "expected", "source_id"),
    [
        ("rsa", Purpose.KEY_AGREEMENT, None, "ML-KEM-768", "fips-203"),
        ("ecc", Purpose.KEY_AGREEMENT, None, "ML-KEM-768", "fips-203"),
        ("ecdh", Purpose.KEY_AGREEMENT, None, "ML-KEM-768", "fips-203"),
        ("dh", Purpose.KEY_AGREEMENT, None, "ML-KEM-768", "fips-203"),
        ("x25519", Purpose.KEY_AGREEMENT, None, "ML-KEM-768", "fips-203"),
        ("rsa", Purpose.DIGITAL_SIGNATURE, None, "ML-DSA-65", "fips-204"),
        ("ecc", Purpose.DIGITAL_SIGNATURE, None, "ML-DSA-65", "fips-204"),
        ("ecdsa", Purpose.DIGITAL_SIGNATURE, None, "ML-DSA-65", "fips-204"),
        ("dsa", Purpose.DIGITAL_SIGNATURE, None, "ML-DSA-65", "fips-204"),
        ("ed25519", Purpose.DIGITAL_SIGNATURE, None, "ML-DSA-65", "fips-204"),
        ("aes", Purpose.ENCRYPTION, 128, "AES-256", "fips-197"),
    ],
)
def test_profile_classical_families_return_cited_recommendations(
    algorithm: str,
    purpose: Purpose,
    key_size_bits: int | None,
    expected: str,
    source_id: str,
) -> None:
    recommendation = _recommendation(
        _artefact(algorithm, purpose, key_size_bits=key_size_bits)
    )

    assert recommendation is not None
    assert recommendation.recommended_parameter_set == expected
    assert recommendation.published_facts is not None
    assert recommendation.published_facts.source_id == source_id
    assert recommendation.fit_score is None
    assert {item.name for item in recommendation.deployment_dimensions} == {
        "latency",
        "protocol_compatibility",
        "mtu_impact",
        "cost",
    }
    assert {item.status for item in recommendation.deployment_dimensions} == {
        "unmeasured"
    }


@pytest.mark.parametrize(
    ("category", "expected"),
    [(1, "ML-KEM-512"), (5, "ML-KEM-1024")],
)
def test_security_category_selects_the_matching_ml_kem_parameter_set(
    category: int, expected: str
) -> None:
    recommendation = _recommendation(
        _artefact("rsa", Purpose.KEY_AGREEMENT),
        requirements=RecommendationRequirements(required_security_category=category),
    )

    assert recommendation is not None
    assert recommendation.recommended_parameter_set == expected
    assert recommendation.security_category == category


def test_stateless_signing_uses_slh_dsa_and_hybrid_kem_uses_x25519() -> None:
    stateless = _recommendation(
        _artefact("ed25519", Purpose.DIGITAL_SIGNATURE),
        requirements=RecommendationRequirements(stateless_required=True),
    )
    hybrid = _recommendation(
        _artefact("x25519", Purpose.KEY_AGREEMENT),
        assessment_id="assessment-hybrid",
        requirements=RecommendationRequirements(hybrid_required=True),
    )

    assert stateless is not None
    assert stateless.recommended_parameter_set == "SLH-DSA-SHA2-192s"
    assert hybrid is not None
    assert hybrid.is_hybrid is True
    assert hybrid.classical_partner == DEFAULT_CLASSICAL_PARTNER


def test_unknown_algorithm_routes_to_manual_review_without_a_score() -> None:
    recommendation = _recommendation(_artefact("twofish", Purpose.ENCRYPTION))

    assert recommendation is not None
    assert recommendation.requires_manual_review is True
    assert recommendation.recommended_algorithm is None
    assert recommendation.fit_score is None
    assert recommendation.rationale.startswith("MANUAL_REVIEW:")


def test_p2_findings_do_not_receive_recommendations() -> None:
    recommendation = _recommendation(
        _artefact("rsa", Purpose.KEY_AGREEMENT), priority=Priority.P2
    )

    assert recommendation is None


def test_legacy_weighted_profile_is_readable_but_cannot_create_recommendations() -> None:
    assert load_profile("nist-pqc-fit-2026.1").version == "nist-pqc-fit-2026.1"
    with pytest.raises(ProfileError, match="read-compatible only"):
        load_pqc_evidence_profile("nist-pqc-fit-2026.1")


def test_published_fips_sizes_are_kept_as_cited_facts() -> None:
    profile = load_pqc_evidence_profile()
    facts = {entry.parameter_set: entry for entry in profile.parameter_sets}

    assert facts["ML-KEM-768"].public_key_bytes == 1184
    assert facts["ML-KEM-768"].ciphertext_bytes == 1088
    assert facts["ML-DSA-65"].signature_bytes == 3309
    assert facts["SLH-DSA-SHA2-192s"].signature_bytes == 16224
    assert facts["AES-256"].symmetric_key_bytes == 32
    assert all(entry.implementation_source_id == "liboqs" for entry in facts.values())


def test_recommendation_row_round_trip_preserves_null_fit_score() -> None:
    recommendation = _recommendation(_artefact("rsa", Purpose.KEY_AGREEMENT))
    assert recommendation is not None

    row = recommendation_to_row(recommendation)
    restored = recommendation_from_row(row)

    assert row.fit_score is None
    assert row.fit_breakdown_json is not None
    assert row.fit_breakdown_json["fit_score"] is None
    assert restored == recommendation


def test_migration_waves_respect_dependencies_and_surface_hsm_purchase() -> None:
    provider = _artefact("rsa", Purpose.KEY_AGREEMENT)
    consumer = _artefact("ecdh", Purpose.KEY_AGREEMENT)
    hsm = _artefact("rsa", Purpose.KEY_AGREEMENT, hardware=True)
    provider_recommendation = _recommendation(
        provider, assessment_id="assessment-provider"
    )
    consumer_recommendation = _recommendation(
        consumer, assessment_id="assessment-consumer"
    )
    hsm_recommendation = _recommendation(hsm, assessment_id="assessment-hsm")
    assert (
        provider_recommendation is not None
        and consumer_recommendation is not None
        and hsm_recommendation is not None
    )

    plan = plan_migration_waves(
        [
            MigrationCandidate(
                artefact=provider,
                assessment=_assessment(provider, assessment_id="assessment-provider"),
                recommendation=provider_recommendation,
            ),
            MigrationCandidate(
                artefact=consumer,
                assessment=_assessment(consumer, assessment_id="assessment-consumer"),
                recommendation=consumer_recommendation,
                crypto_agility=CryptoAgilityObservation(
                    status="hardcoded", evidence="algorithm constant in tls.py"
                ),
            ),
            MigrationCandidate(
                artefact=hsm,
                assessment=_assessment(hsm, assessment_id="assessment-hsm"),
                recommendation=hsm_recommendation,
            ),
        ],
        [
            DependencyEdge(
                source_id=consumer.artefact_id,
                target_id=provider.artefact_id,
                relation=DependencyRelation.DEPENDS_ON,
                source_kind="artefact",
                target_kind="artefact",
            )
        ],
    )
    items = {item.artefact_id: item for item in plan.items}

    assert items[provider.artefact_id].migration_wave == 1
    assert items[consumer.artefact_id].migration_wave == 2
    assert items[consumer.artefact_id].dependency_ids == [provider.artefact_id]
    assert items[hsm.artefact_id].hardware_action == "hardware_purchase"
    assert any("hardware purchase" in note for note in items[hsm.artefact_id].notes)
    assert any("hardcoded" in note for note in items[consumer.artefact_id].notes)


def test_manual_recommendation_row_is_a_valid_database_shape() -> None:
    recommendation = _recommendation(_artefact("twofish", Purpose.ENCRYPTION))
    assert recommendation is not None
    row = recommendation_to_row(recommendation)

    assert isinstance(row, RecommendationRow)
    assert row.fit_score is None
