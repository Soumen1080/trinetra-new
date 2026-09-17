"""Round-trip tests (plan task 1.13): object -> JSON -> DB -> JSON -> object.

If these fail, data is being lost somewhere in the stack, which would show up
much later as an artefact that silently changes between a scan and its report.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from app.models.enums import (
    AssessmentStatus,
    AssetType,
    BusinessCriticality,
    CloudProvider,
    CloudServiceKind,
    Confidence,
    DataClassification,
    DetectionMethod,
    ExposureLevel,
    FipsStatus,
    KeyManagementKind,
    KeyStorageLocation,
    MoscaZBasis,
    Priority,
    ProtocolName,
    ProvenanceTier,
    QuantumProjectionStatus,
    ResourceScenario,
    ScannerKind,
    ScanStatus,
    ScanTargetKind,
)
from app.models.tables import Artefact as ArtefactRow
from app.schemas.artefact import (
    CertificateDetail,
    CloudServiceDetail,
    CryptoArtefact,
    HardwareModuleDetail,
    KeyDetail,
    LibraryDetail,
    ProtocolDetail,
)
from app.schemas.common import Evidence, Provenance, SourceLocation
from app.schemas.context import ArtefactContext, RetentionEvidence
from app.schemas.mapping import (
    artefact_from_row,
    artefact_to_row,
    assessment_from_row,
    assessment_to_row,
    context_from_row,
    context_to_row,
)
from app.schemas.risk import MoscaTrack, ResourceTrack, RiskAssessment, ScoreContribution
from app.schemas.scan import CoverageGap, CoverageStats, ScanResult, ScanTarget
from tests.conftest import OBSERVED_AT, SCAN_TARGET


class TestJsonRoundTrip:
    def test_artefact_survives_json(self, artefact: CryptoArtefact) -> None:
        restored = CryptoArtefact.model_validate_json(artefact.model_dump_json())
        assert restored == artefact

    def test_r19_fields_survive_json(self, artefact: CryptoArtefact) -> None:
        """Mode and key size are the whole point of R19 -- they must not be lost."""
        restored = CryptoArtefact.model_validate_json(artefact.model_dump_json())
        assert restored.detail is not None
        assert restored.detail.mode.value == "cbc"
        assert restored.detail.key_size_bits == 128

    def test_scan_result_survives_json(self, artefact: CryptoArtefact) -> None:
        result = ScanResult(
            scan_id="scan-001",
            target=ScanTarget(
                kind=ScanTargetKind.GIT_REPOSITORY, identifier=SCAN_TARGET
            ),
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=OBSERVED_AT,
            artefacts=[artefact],
            coverage=CoverageStats(
                files_discovered=10,
                files_scanned=9,
                files_skipped=1,
                gaps=[CoverageGap(reason="binary is stripped", kind="unparseable")],
            ),
        )
        restored = ScanResult.model_validate_json(result.model_dump_json())
        assert restored == result
        assert restored.coverage.gaps[0].reason == "binary is stripped"


class TestDatabaseRoundTrip:
    def test_artefact_survives_database(
        self, session: Session, scan_row, artefact: CryptoArtefact
    ) -> None:
        session.add(artefact_to_row(artefact, scan_id=scan_row.id))
        session.commit()

        row = session.get(ArtefactRow, artefact.artefact_id)
        restored = artefact_from_row(row)

        assert restored.artefact_id == artefact.artefact_id
        assert restored.name == artefact.name
        assert restored.asset_type == artefact.asset_type
        assert restored.detail == artefact.detail
        assert restored.evidence == artefact.evidence

    def test_flattened_columns_match_detail(
        self, session: Session, scan_row, artefact: CryptoArtefact
    ) -> None:
        """The queryable columns must agree with the structured detail.

        They are written from the same source, but a divergence here would mean
        a filter on 'mode = ecb' silently disagreeing with the artefact drawer.
        """
        row = artefact_to_row(artefact, scan_id=scan_row.id)
        session.add(row)
        session.commit()

        assert row.mode == "cbc"
        assert row.key_size_bits == 128
        assert row.location == "svc/auth.py, line 20"

    @pytest.mark.parametrize(
        ("asset_type", "name", "detail", "algorithm"),
        [
            (
                AssetType.KEY,
                "rsa-private-key",
                KeyDetail(
                    key_type="rsa",
                    size_bits=2048,
                    storage_location=KeyStorageLocation.SOURCE_CODE,
                    is_hardcoded=True,
                ),
                "rsa",
            ),
            (
                AssetType.CERTIFICATE,
                "CN=payments.example.org",
                CertificateDetail(
                    subject="CN=payments.example.org",
                    issuer="CN=Example CA",
                    signature_algorithm="sha256WithRSAEncryption",
                    public_key_algorithm="rsa",
                    public_key_size_bits=2048,
                    not_before=datetime(2026, 1, 1, tzinfo=UTC),
                    not_after=datetime(2027, 1, 1, tzinfo=UTC),
                    is_self_signed=False,
                ),
                None,
            ),
            (
                AssetType.PROTOCOL,
                "TLS 1.2",
                ProtocolDetail(
                    protocol=ProtocolName.TLS,
                    version="1.2",
                    cipher_suites=["TLS_RSA_WITH_AES_128_CBC_SHA"],
                    is_observed=True,
                ),
                None,
            ),
            (
                AssetType.LIBRARY,
                "OpenSSL",
                LibraryDetail(
                    package_name="openssl",
                    version="1.1.1w",
                    purl="pkg:generic/openssl@1.1.1w",
                    fips_status=FipsStatus.NON_FIPS,
                ),
                None,  # libraries must never carry an algorithm
            ),
            (
                AssetType.HARDWARE_MODULE,
                "Luna HSM",
                HardwareModuleDetail(
                    vendor="Thales",
                    model="Luna K7",
                    pkcs11_slot_id=0,
                    fips_status=FipsStatus.FIPS_140_2,
                    supports_pqc=False,
                ),
                None,
            ),
            (
                AssetType.CLOUD_SERVICE,
                "aws-kms-key",
                CloudServiceDetail(
                    provider=CloudProvider.AWS,
                    service=CloudServiceKind.KMS,
                    region="ap-south-1",
                    key_spec="RSA_2048",
                    key_management=KeyManagementKind.CUSTOMER_MANAGED,
                ),
                None,
            ),
        ],
    )
    def test_every_asset_type_survives_database(
        self,
        session: Session,
        scan_row,
        evidence: Evidence,
        asset_type: AssetType,
        name: str,
        detail,
        algorithm: str | None,
    ) -> None:
        """All seven typed details must persist and reconstruct exactly."""
        artefact = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=asset_type,
            name=name,
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
            detail=detail,
            algorithm=algorithm,
        )
        row = artefact_to_row(artefact, scan_id=scan_row.id)
        session.add(row)
        session.commit()
        session.expire_all()

        restored = artefact_from_row(row)
        assert restored.detail == detail
        assert restored.asset_type == asset_type
        assert restored.algorithm == algorithm

    def test_context_survives_database(
        self, session: Session, scan_row, artefact
    ) -> None:
        session.add(artefact_to_row(artefact, scan_id=scan_row.id))
        session.commit()

        context = ArtefactContext(
            artefact_id=artefact.artefact_id,
            business_criticality=BusinessCriticality.CRITICAL,
            data_classification=DataClassification.RESTRICTED,
            exposure=ExposureLevel.INTERNET,
            data_category="aadhaar_pii",
            data_lifetime_years=30,
            migration_time_years=2.5,
            retention_evidence=[
                RetentionEvidence(
                    source="user",
                    data_category="aadhaar_pii",
                    lifetime_years=30,
                    basis="assumption",
                    citation="Trinetra planning assumption",
                )
            ],
            provenance={
                "business_criticality": Provenance(
                    tier=ProvenanceTier.USER, source_detail="analyst@example.org"
                ),
                "data_category": Provenance(
                    tier=ProvenanceTier.SCANNER_EVIDENCE, source_detail="taint-rule-7"
                ),
            },
        )
        row = context_to_row(context, row_id="ctx-001")
        session.add(row)
        session.commit()
        session.expire_all()

        restored = context_from_row(row)
        assert restored.data_lifetime_years == 30
        assert (
            restored.provenance["data_category"].tier
            is ProvenanceTier.SCANNER_EVIDENCE
        )
        assert restored.retention_evidence[0].lifetime_years == 30

    def test_assessment_survives_database(
        self, session: Session, scan_row, artefact
    ) -> None:
        """Both tracks must be re-derivable from storage, not merely displayable."""
        session.add(artefact_to_row(artefact, scan_id=scan_row.id))
        session.commit()

        assessment = RiskAssessment(
            assessment_id="ra-001",
            artefact_id=artefact.artefact_id,
            scan_id=scan_row.id,
            status=AssessmentStatus.SCORED,
            final_score=82.0,
            final_confidence=Confidence.MEDIUM,
            priority=Priority.P0,
            mosca=MoscaTrack(
                x_years=30,
                y_years=2.5,
                z_years=9.0,
                z_basis=MoscaZBasis.RESOURCE_MODEL,
                is_urgent=True,
                shortfall_years=23.5,
                confidence=Confidence.MEDIUM,
                evidence=["aadhaar_pii: 30y (Trinetra planning assumption)"],
            ),
            resource=ResourceTrack(
                m_years=9.0,
                scenario=ResourceScenario.BASELINE,
                status=QuantumProjectionStatus.CALCULATED,
                projected_break_year=2035,
                logical_qubits_required=4099,
                gate_count_required=2.7e12,
                assumptions={
                    "error_correction": "surface_code",
                    "physical_error_rate": "1e-3",
                },
                caveats=["extrapolated tail beyond 2040"],
                confidence=Confidence.MEDIUM,
            ),
            contributions=[
                ScoreContribution(
                    factor="algorithm_quantum_vulnerability",
                    points=25,
                    max_points=25,
                    has_evidence=True,
                    reason="RSA-2048 is broken by Shor's algorithm",
                ),
                ScoreContribution(
                    factor="migration_complexity",
                    points=0,
                    max_points=8,
                    has_evidence=False,
                    reason="no migration complexity evidence available",
                ),
            ],
            policy_version="policy-2026.1",
            weights_version="weights-2026.1",
            quantum_forecast_profile_version="forecast-2026.1",
            assessed_at=OBSERVED_AT,
        )

        row = assessment_to_row(assessment)
        session.add(row)
        session.commit()
        session.expire_all()

        restored = assessment_from_row(row)
        assert restored.final_score == 82.0
        assert restored.mosca.x_years == 30
        assert restored.mosca.shortfall_years == 23.5
        assert restored.resource.logical_qubits_required == 4099
        assert restored.resource.assumptions["error_correction"] == "surface_code"
        assert restored.unmeasured_factors == ["migration_complexity"]

    def test_full_cycle_json_db_json(
        self, session: Session, scan_row, artefact: CryptoArtefact
    ) -> None:
        """The complete path named in plan task 1.13."""
        as_json = artefact.model_dump_json()
        from_json = CryptoArtefact.model_validate_json(as_json)

        row = artefact_to_row(from_json, scan_id=scan_row.id)
        session.add(row)
        session.commit()
        session.expire_all()

        from_db = artefact_from_row(row)
        final = CryptoArtefact.model_validate_json(from_db.model_dump_json())

        assert final.artefact_id == artefact.artefact_id
        assert final.detail == artefact.detail
        assert final.evidence == artefact.evidence
        assert final.name == artefact.name


class TestDeterministicIdentity:
    def test_same_finding_yields_same_id(self, evidence: Evidence) -> None:
        """Identity must survive a rescan, or 'is it fixed?' is unanswerable."""
        first = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        later = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=datetime(2026, 9, 1, tzinfo=UTC),
        )
        assert first.artefact_id == later.artefact_id

    def test_different_line_yields_different_id(self, evidence: Evidence) -> None:
        """Two uses of AES in one file are two findings, remediated separately."""
        other = evidence.model_copy(
            update={"location": SourceLocation(path="svc/auth.py", line=88)}
        )
        first = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        second = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[other],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        assert first.artefact_id != second.artefact_id

    def test_different_target_yields_different_id(self, evidence: Evidence) -> None:
        """The same code in two repositories is two artefacts with two owners."""
        first = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        second = CryptoArtefact.from_evidence(
            scan_target="https://git.example.org/other-api",
            asset_type=AssetType.ALGORITHM,
            name="AES-128-CBC",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        assert first.artefact_id != second.artefact_id

    def test_merge_unions_evidence_and_widens_window(
        self, artefact: CryptoArtefact, evidence: Evidence
    ) -> None:
        """Two scanners finding one asset is corroboration, not duplication."""
        later_evidence = evidence.model_copy(
            update={
                "detection_method": DetectionMethod.TREE_SITTER_AST,
                "rule_id": "trinetra.ast.aes",
            }
        )
        rediscovered = artefact.model_copy(
            update={
                "evidence": [later_evidence],
                "first_seen": datetime(2026, 9, 1, tzinfo=UTC),
                "last_seen": datetime(2026, 9, 1, tzinfo=UTC),
            }
        )

        merged = artefact.merged_with(rediscovered)

        assert len(merged.evidence) == 2
        assert merged.first_seen == OBSERVED_AT
        assert merged.last_seen == datetime(2026, 9, 1, tzinfo=UTC)

    def test_merging_different_artefacts_is_rejected(
        self, artefact: CryptoArtefact, evidence: Evidence
    ) -> None:
        other = CryptoArtefact.from_evidence(
            scan_target=SCAN_TARGET,
            asset_type=AssetType.ALGORITHM,
            name="RSA-2048",
            evidence=[evidence],
            discovered_by=ScannerKind.SOURCE,
            observed_at=OBSERVED_AT,
        )
        with pytest.raises(ValueError, match="different identities"):
            artefact.merged_with(other)
