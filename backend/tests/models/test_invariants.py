"""Tests for the guarantees that keep the platform honest.

These correspond to the architecture's "what must be tested" list. Each one
catches a failure that would make Trinetra *dishonest* rather than merely
broken -- a number where there was no measurement, a default masquerading as
evidence, an unassessed artefact ranked as though it were safe.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.enums import (
    AssessmentStatus,
    AssetType,
    Confidence,
    Priority,
    ProvenanceTier,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ScannerKind,
    ScanStatus,
    ScanTargetKind,
)
from app.models.tables import Artefact as ArtefactRow
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact, LibraryDetail
from app.schemas.common import Evidence, Provenance, SourceLocation
from app.schemas.context import ArtefactContext, RetentionEvidence
from app.schemas.risk import (
    MoscaTrack,
    ResourceTrack,
    RiskAssessment,
    ScoreContribution,
    band_for_score,
)
from app.schemas.scan import CoverageStats, ScanError, ScanResult, ScanTarget
from tests.conftest import OBSERVED_AT, SCAN_TARGET

POLICY = {"policy_version": "p-1", "weights_version": "w-1"}


def _assessment(**overrides) -> dict:
    base = {
        "assessment_id": "ra-1",
        "artefact_id": "art-1",
        "status": AssessmentStatus.NEEDS_CONTEXT,
        "missing_fields": ["data_lifetime_years"],
        "assessed_at": OBSERVED_AT,
        **POLICY,
    }
    base.update(overrides)
    return base


class TestP3MissingEvidenceProducesNoNumber:
    """P3 -- the single most important guarantee in the platform."""

    def test_factor_without_evidence_cannot_contribute_points(self) -> None:
        with pytest.raises(ValidationError, match="must contribute zero"):
            ScoreContribution(
                factor="business_criticality",
                points=5,
                max_points=10,
                has_evidence=False,
                reason="assumed medium",
            )

    def test_factor_without_evidence_may_contribute_zero(self) -> None:
        contribution = ScoreContribution(
            factor="business_criticality",
            points=0,
            max_points=10,
            has_evidence=False,
            reason="no business context supplied",
        )
        assert contribution.points == 0
        assert not contribution.has_evidence

    def test_contribution_cannot_exceed_its_weight(self) -> None:
        with pytest.raises(ValidationError, match="exceeding its maximum"):
            ScoreContribution(
                factor="exposure",
                points=99,
                max_points=10,
                has_evidence=True,
                reason="internet facing",
            )

    def test_unobserved_key_size_stays_none(self) -> None:
        """AES.new(key, MODE_GCM) does not state 128 or 256, and must not claim to."""
        detail = AlgorithmDetail(mode="gcm")
        assert detail.key_size_bits is None

    def test_certificate_expiry_unknown_is_not_valid(self) -> None:
        """'We did not read an expiry' is not 'it has not expired'."""
        from app.schemas.artefact import CertificateDetail

        detail = CertificateDetail(subject="CN=example.org")
        assert detail.is_expired_at(datetime(2030, 1, 1, tzinfo=UTC)) is None


class TestScoreRequiresBothTracks:
    def test_score_rejected_when_mosca_unresolved(self) -> None:
        with pytest.raises(ValidationError, match="requires both tracks"):
            RiskAssessment(
                **_assessment(
                    status=AssessmentStatus.SCORED,
                    final_score=80.0,
                    priority=Priority.P0,
                    mosca=MoscaTrack(x_years=30),  # y and z missing
                    resource=ResourceTrack(
                        m_years=9.0, status=QuantumProjectionStatus.CALCULATED
                    ),
                )
            )

    def test_score_rejected_when_resource_unresolved(self) -> None:
        with pytest.raises(ValidationError, match="requires both tracks"):
            RiskAssessment(
                **_assessment(
                    status=AssessmentStatus.SCORED,
                    final_score=80.0,
                    priority=Priority.P0,
                    mosca=MoscaTrack(
                        x_years=30, y_years=2.0, z_years=9.0, is_urgent=True
                    ),
                    resource=ResourceTrack(
                        status=QuantumProjectionStatus.MODEL_UNAVAILABLE
                    ),
                )
            )

    def test_score_accepted_when_both_tracks_resolved(self) -> None:
        assessment = RiskAssessment(
            **_assessment(
                status=AssessmentStatus.SCORED,
                final_score=80.0,
                priority=Priority.P0,
                missing_fields=[],
                mosca=MoscaTrack(x_years=30, y_years=2.0, z_years=9.0, is_urgent=True),
                resource=ResourceTrack(
                    m_years=9.0, status=QuantumProjectionStatus.CALCULATED
                ),
            )
        )
        assert assessment.has_score


class TestMoscaVerdictRequiresAllInputs:
    def test_verdict_without_all_three_terms_is_rejected(self) -> None:
        """Absent X must not silently become zero, turning urgent into 'safe'."""
        with pytest.raises(ValidationError, match="requires x, y and z"):
            MoscaTrack(y_years=2.0, z_years=9.0, is_urgent=False)

    def test_unresolved_track_reports_none_not_false(self) -> None:
        track = MoscaTrack(y_years=2.0, z_years=9.0)
        assert track.is_urgent is None
        assert not track.is_resolved


class TestPolicyDecidedArtefactsCarryNoScore:
    def test_policy_decided_cannot_carry_a_score(self) -> None:
        """Scoring MD5 implies a measurement that was never made.

        Both tracks are resolved here deliberately, so the rejection can only
        come from the status rule rather than from the both-tracks guard.
        """
        with pytest.raises(ValidationError, match="must not carry a score"):
            RiskAssessment(
                **_assessment(
                    status=AssessmentStatus.POLICY_DECIDED,
                    final_score=100.0,
                    priority=Priority.P0,
                    mosca=MoscaTrack(
                        x_years=30, y_years=2.0, z_years=9.0, is_urgent=True
                    ),
                    resource=ResourceTrack(
                        m_years=9.0, status=QuantumProjectionStatus.CALCULATED
                    ),
                )
            )

    def test_scored_status_requires_a_score(self) -> None:
        with pytest.raises(ValidationError, match="requires a final_score"):
            RiskAssessment(**_assessment(status=AssessmentStatus.SCORED))

    def test_needs_context_must_name_missing_fields(self) -> None:
        """Otherwise the user gets a dead end instead of an action."""
        with pytest.raises(ValidationError, match="must name the missing fields"):
            RiskAssessment(
                **_assessment(
                    status=AssessmentStatus.NEEDS_CONTEXT, missing_fields=[]
                )
            )


class TestUnassessedIsNotLowRisk:
    def test_unscored_assessment_cannot_carry_a_priority(self) -> None:
        """NEEDS_CONTEXT sorted as P2 tells the user they are safer than they are."""
        with pytest.raises(ValidationError, match="cannot carry a priority band"):
            RiskAssessment(**_assessment(priority=Priority.P2))

    @pytest.mark.parametrize(
        ("score", "expected"),
        [(100.0, Priority.P0), (75.0, Priority.P0), (74.9, Priority.P1),
         (50.0, Priority.P1), (49.9, Priority.P2), (0.0, Priority.P2)],
    )
    def test_band_boundaries(self, score: float, expected: Priority) -> None:
        assert band_for_score(score) is expected

    def test_priority_must_match_score(self) -> None:
        with pytest.raises(ValidationError, match="does not match score"):
            RiskAssessment(
                **_assessment(
                    status=AssessmentStatus.SCORED,
                    final_score=80.0,
                    priority=Priority.P2,
                    missing_fields=[],
                    mosca=MoscaTrack(
                        x_years=30, y_years=2.0, z_years=9.0, is_urgent=True
                    ),
                    resource=ResourceTrack(
                        m_years=9.0, status=QuantumProjectionStatus.CALCULATED
                    ),
                )
            )


class TestLibraryFindingsCarryNoAlgorithm:
    """OpenSSL being installed proves an implementation exists, not that any
    particular algorithm is used."""

    def test_library_with_algorithm_is_rejected(self, evidence: Evidence) -> None:
        with pytest.raises(ValidationError, match="must not carry an algorithm"):
            CryptoArtefact.from_evidence(
                scan_target=SCAN_TARGET,
                asset_type=AssetType.LIBRARY,
                name="OpenSSL",
                evidence=[evidence],
                discovered_by=ScannerKind.CONTAINER,
                observed_at=OBSERVED_AT,
                algorithm="rsa",
                detail=LibraryDetail(package_name="openssl", version="1.1.1w"),
            )

    def test_database_rejects_library_with_algorithm(
        self, session: Session, scan_row
    ) -> None:
        """Enforced at the storage layer too, not only in Pydantic."""
        session.add(
            ArtefactRow(
                id="art-lib",
                scan_id=scan_row.id,
                type=AssetType.LIBRARY.value,
                name="OpenSSL",
                algorithm="rsa",
                discovered_by=ScannerKind.CONTAINER.value,
                quantum_vulnerability=QuantumVulnerability.UNKNOWN.value,
                nist_security_level="unknown",
                first_seen=OBSERVED_AT,
                last_seen=OBSERVED_AT,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


class TestEvidenceIsMandatory:
    def test_artefact_without_evidence_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CryptoArtefact(
                artefact_id="x",
                asset_type=AssetType.ALGORITHM,
                name="AES",
                evidence=[],
                discovered_by=ScannerKind.SOURCE,
                first_seen=OBSERVED_AT,
                last_seen=OBSERVED_AT,
            )

    def test_from_evidence_rejects_empty_evidence(self) -> None:
        with pytest.raises(ValueError, match="at least one piece of evidence"):
            CryptoArtefact.from_evidence(
                scan_target=SCAN_TARGET,
                asset_type=AssetType.ALGORITHM,
                name="AES",
                evidence=[],
                discovered_by=ScannerKind.SOURCE,
                observed_at=OBSERVED_AT,
            )

    def test_absolute_paths_are_rejected(self) -> None:
        """A host path would leak the scanner's filesystem layout into evidence."""
        with pytest.raises(ValidationError, match="must be relative"):
            SourceLocation(path="/home/runner/work/repo/svc/auth.py", line=3)


class TestScannerTierIsNarrowed:
    """A scanner must not become a back-channel for facts no scanner can know."""

    def test_scanner_may_supply_data_category(self) -> None:
        context = ArtefactContext(
            artefact_id="art-1",
            data_category="aadhaar_pii",
            provenance={
                "data_category": Provenance(tier=ProvenanceTier.SCANNER_EVIDENCE)
            },
        )
        assert context.data_category == "aadhaar_pii"

    def test_scanner_may_not_supply_business_criticality(self) -> None:
        with pytest.raises(ValidationError, match="cannot carry scanner_evidence"):
            ArtefactContext(
                artefact_id="art-1",
                provenance={
                    "business_criticality": Provenance(
                        tier=ProvenanceTier.SCANNER_EVIDENCE
                    )
                },
            )

    def test_unresolved_field_reports_unknown_provenance(self) -> None:
        context = ArtefactContext(artefact_id="art-1")
        assert context.provenance_of("exposure").tier is ProvenanceTier.UNKNOWN

    def test_missing_fields_are_enumerated(self) -> None:
        """NEEDS_CONTEXT must name what it needs."""
        context = ArtefactContext(artefact_id="art-1")
        assert "data_lifetime_years" in context.missing_fields
        assert "migration_time_years" in context.missing_fields


class TestRetentionCaveats:
    def test_regulatory_minimum_requires_a_caveat(self) -> None:
        """A retention minimum is not a confidentiality lifetime."""
        with pytest.raises(ValidationError, match="not a confidentiality lifetime"):
            RetentionEvidence(
                source="legal_profile",
                data_category="financial_record",
                lifetime_years=7,
                basis="regulatory_minimum",
            )

    def test_regulatory_minimum_with_caveat_is_accepted(self) -> None:
        evidence = RetentionEvidence(
            source="legal_profile",
            data_category="financial_record",
            lifetime_years=7,
            basis="regulatory_minimum",
            caveat="Statute mandates a retention minimum, not a confidentiality "
            "lifetime.",
        )
        assert evidence.caveat


class TestConfidence:
    def test_weaker_of_two_tracks_governs(self) -> None:
        assert Confidence.weaker(Confidence.HIGH, Confidence.LOW) is Confidence.LOW

    def test_downgrade_floors_at_low(self) -> None:
        assert Confidence.LOW.downgrade() is Confidence.LOW
        assert Confidence.HIGH.downgrade(2) is Confidence.LOW

    def test_artefact_confidence_is_its_strongest_evidence(
        self, artefact: CryptoArtefact, evidence: Evidence
    ) -> None:
        weak = evidence.model_copy(update={"confidence": Confidence.LOW})
        updated = artefact.model_copy(update={"evidence": [weak, evidence]})
        assert updated.confidence is Confidence.HIGH


class TestQuantumResourceDiscipline:
    def test_calculated_estimate_must_carry_assumptions(self) -> None:
        """An unqualified qubit count is a number nobody can check (P4)."""
        with pytest.raises(ValidationError, match="must record its assumptions"):
            ResourceTrack(
                m_years=9.0,
                status=QuantumProjectionStatus.CALCULATED,
                logical_qubits_required=4099,
            )

    def test_unknown_vulnerability_is_not_reported_as_vulnerable(
        self, evidence: Evidence
    ) -> None:
        artefact = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="CustomCipher",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
            quantum_vulnerability=QuantumVulnerability.UNKNOWN,
        )
        assert not artefact.is_quantum_vulnerable


class TestScanHonesty:
    def test_failed_scan_must_record_an_error(self) -> None:
        """A red badge with no cause is the hang with no user-visible end."""
        with pytest.raises(ValidationError, match="must record at least one error"):
            ScanResult(
                scan_id="s1",
                target=ScanTarget(
                    kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
                ),
                status=ScanStatus.FAILED,
                started_at=OBSERVED_AT,
                finished_at=OBSERVED_AT,
            )

    def test_terminal_scan_must_record_finished_at(self) -> None:
        with pytest.raises(ValidationError, match="must record finished_at"):
            ScanResult(
                scan_id="s1",
                target=ScanTarget(
                    kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
                ),
                status=ScanStatus.SUCCEEDED,
                started_at=OBSERVED_AT,
            )

    def test_failed_scan_with_an_error_is_valid(self) -> None:
        result = ScanResult(
            scan_id="s1",
            target=ScanTarget(
                kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
            ),
            status=ScanStatus.FAILED,
            started_at=OBSERVED_AT,
            finished_at=OBSERVED_AT,
            errors=[
                ScanError(
                    code="clone_failed",
                    message="authentication failed",
                    is_retryable=False,
                )
            ],
        )
        assert result.status.is_terminal

    def test_empty_scan_is_valid_not_an_error(self) -> None:
        """A repository genuinely free of cryptography is a valid result."""
        result = ScanResult(
            scan_id="s1",
            target=ScanTarget(
                kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
            ),
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=OBSERVED_AT,
        )
        assert result.artefact_count == 0

    def test_zero_discovered_files_is_not_full_coverage(self) -> None:
        """0/0 must not render as 100%: that claims a complete inventory of nothing."""
        assert CoverageStats().coverage_ratio is None

    def test_coverage_ratio_is_reported(self) -> None:
        stats = CoverageStats(files_discovered=10, files_scanned=8)
        assert stats.coverage_ratio == 0.8
        assert not stats.is_complete

    def test_scanned_cannot_exceed_discovered(self) -> None:
        with pytest.raises(ValidationError, match="exceeds files_discovered"):
            CoverageStats(files_discovered=5, files_scanned=9)

    def test_deduplication_merges_by_identity(
        self, artefact: CryptoArtefact, evidence: Evidence
    ) -> None:
        second = artefact.model_copy(
            update={
                "evidence": [
                    evidence.model_copy(update={"rule_id": "trinetra.ast.aes"})
                ]
            }
        )
        result = ScanResult(
            scan_id="s1",
            target=ScanTarget(
                kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
            ),
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=OBSERVED_AT,
            artefacts=[artefact, second],
        )
        deduplicated = result.deduplicated()
        assert len(deduplicated) == 1
        assert len(deduplicated[0].evidence) == 2


class TestStructuralValidation:
    def test_detail_must_match_asset_type(self, evidence: Evidence) -> None:
        with pytest.raises(ValidationError, match="does not match asset_type"):
            CryptoArtefact.from_evidence(
                scan_target=SCAN_TARGET,
                asset_type=AssetType.CERTIFICATE,
                name="cert",
                evidence=[evidence],
                discovered_by=ScannerKind.SOURCE,
                observed_at=OBSERVED_AT,
                detail=AlgorithmDetail(mode="cbc"),
            )

    def test_unknown_fields_are_rejected(self) -> None:
        """Contract drift from a scanner must fail at the boundary, not silently."""
        with pytest.raises(ValidationError):
            SourceLocation(path="a.py", line=1, unexpected_field="x")

    def test_certificate_validity_window_must_be_ordered(self) -> None:
        from app.schemas.artefact import CertificateDetail

        with pytest.raises(ValidationError, match="precedes not_before"):
            CertificateDetail(
                not_before=datetime(2027, 1, 1, tzinfo=UTC),
                not_after=datetime(2026, 1, 1, tzinfo=UTC),
            )

    def test_dependency_edge_cannot_be_self_referential(self) -> None:
        from app.schemas.context import DependencyEdge

        with pytest.raises(ValidationError, match="cannot point at itself"):
            DependencyEdge(
                source_id="a",
                target_id="a",
                relation="depends_on",
                source_kind="artefact",
                target_kind="artefact",
            )
