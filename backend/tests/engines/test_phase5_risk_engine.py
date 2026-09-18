"""Phase 5's method contract: pure inputs produce auditable risk verdicts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.engines import (
    RiskSettings,
    classify_risk,
    evaluate_mosca,
    evaluate_resources,
    inherit_dependency_criticality,
)
from app.engines.__main__ import main
from app.engines.final_risk_engine import hndl_status, rescore_all
from app.engines.profiles import load_profile, load_risk_profiles
from app.engines.profiles.loader import CapabilityPoint
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    BusinessCriticality,
    Confidence,
    DataClassification,
    DetectionMethod,
    EvidenceSource,
    ExposureLevel,
    Primitive,
    ProvenanceTier,
    Purpose,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
    RetentionBasis,
    ScannerKind,
)
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact
from app.schemas.common import Evidence, Provenance, SourceLocation
from app.schemas.context import ArtefactContext, DependencyEdge, RetentionEvidence
from app.schemas.mapping import artefact_to_row, context_to_row
from app.services.cbom_ingest import ingest_document
from app.services.risk_assessment import apply_risk_settings_and_rescore

ASSESSMENT_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _rsa() -> CryptoArtefact:
    return CryptoArtefact.from_evidence(
        scan_target="https://git.example.org/patients",
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        algorithm="rsa",
        primitive=Primitive.PKE,
        purposes=[Purpose.KEY_AGREEMENT],
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        detail=AlgorithmDetail(key_size_bits=2048),
        evidence=[
            Evidence(
                location=SourceLocation(path="patient.py", line=20),
                detection_method=DetectionMethod.SEMGREP_TAINT,
                confidence=Confidence.HIGH,
                rule_id="trinetra.patient-rsa",
            )
        ],
        discovered_by=ScannerKind.SOURCE,
        observed_at=ASSESSMENT_TIME,
    )


def _worked_context(**updates: object) -> ArtefactContext:
    values: dict[str, object] = {
        "artefact_id": _rsa().artefact_id,
        "data_category": "aadhaar_pii",
        "data_classification": DataClassification.INTERNAL,
        "business_criticality": BusinessCriticality.CRITICAL,
        "exposure": ExposureLevel.INTERNET,
        "migration_time_years": 4,
        "provenance": {
            "data_category": Provenance(tier=ProvenanceTier.SCANNER_EVIDENCE),
            "migration_time_years": Provenance(tier=ProvenanceTier.USER),
            "data_classification": Provenance(tier=ProvenanceTier.USER),
            "business_criticality": Provenance(tier=ProvenanceTier.USER),
            "exposure": Provenance(tier=ProvenanceTier.USER),
        },
    }
    values.update(updates)
    return ArtefactContext(**values)


def _assess(
    artefact: CryptoArtefact | None = None,
    context: ArtefactContext | None = None,
    **settings: object,
):
    asset = artefact or _rsa()
    return classify_risk(
        asset,
        context or _worked_context(artefact_id=asset.artefact_id),
        load_risk_profiles(),
        RiskSettings(planning_horizon_years=12, **settings),
        assessment_id="assessment-1",
        assessed_at=ASSESSMENT_TIME,
    )


def test_profiles_are_validated_and_legacy_versions_load() -> None:
    profiles = load_risk_profiles()
    assert len(profiles.retention.categories) == 10
    assert len(profiles.quantum.attack_models) == 20
    assert sum(profiles.weights.weights.values()) == 100
    legacy_quantum = load_profile("quantum-capability-2026.1")
    assert legacy_quantum.version == "quantum-capability-2026.2"
    assert load_profile("builtin-0.1.0").version == "current-security-2026.1"
    assert load_profile("nist-pqc-fit-2026.1").version == "current-security-2026.1"


def test_missing_x_yields_no_score_not_a_default() -> None:
    context = _worked_context(data_category=None)
    context.provenance.pop("data_category")
    result = _assess(context=context)
    assert result.status is AssessmentStatus.NEEDS_CONTEXT
    assert result.final_score is None
    assert result.mosca.x_years is None
    assert "data_lifetime_years" in result.missing_fields


def test_unmeasured_factor_is_zero_and_labelled() -> None:
    context = _worked_context(
        business_criticality=BusinessCriticality.UNKNOWN,
        exposure=ExposureLevel.UNKNOWN,
    )
    context.provenance.pop("business_criticality")
    context.provenance.pop("exposure")
    result = _assess(context=context)
    contributions = {item.factor: item for item in result.contributions}
    assert result.status is AssessmentStatus.SCORED
    assert contributions["business_criticality"].points == 0
    assert not contributions["business_criticality"].has_evidence
    criticality = contributions["business_criticality"]
    assert "No business criticality evidence" in criticality.reason


def test_no_score_when_resource_model_is_unavailable() -> None:
    asset = _rsa().model_copy(update={"algorithm": "unknown-public-key"})
    result = _assess(artefact=asset)
    assert result.status is AssessmentStatus.NEEDS_CONTEXT
    assert result.final_score is None
    assert result.resource.status is QuantumProjectionStatus.MODEL_UNAVAILABLE


def test_policy_short_circuits_run_before_scoring() -> None:
    asset = _rsa().model_copy(
        update={
            "name": "MD5",
            "algorithm": "md5",
            "quantum_vulnerability": QuantumVulnerability.CLASSICALLY_BROKEN,
        }
    )
    result = _assess(artefact=asset)
    assert result.status is AssessmentStatus.POLICY_DECIDED
    assert result.final_score is None
    assert not result.contributions


def test_identical_explicit_inputs_produce_identical_outputs() -> None:
    first = _assess()
    second = _assess()
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_curve_point_needs_both_dimensions_to_cross() -> None:
    profiles = load_risk_profiles()
    incomplete = CapabilityPoint(
        year=2026,
        logical_qubits=10_000,
        logical_gates=None,
        confidence="roadmap",
        basis="test point missing comparable gate count",
    )
    quantum = profiles.quantum.model_copy(update={"capability_curve": [incomplete]})
    resource = evaluate_resources(_rsa(), quantum)
    assert resource.status is QuantumProjectionStatus.BEYOND_HORIZON
    assert resource.projected_break_year is None


def test_scenario_scales_capability_never_attack_requirement() -> None:
    profiles = load_risk_profiles()
    conservative = evaluate_resources(
        _rsa(), profiles.quantum, scenario=ResourceScenario.CONSERVATIVE
    )
    aggressive = evaluate_resources(
        _rsa(), profiles.quantum, scenario=ResourceScenario.AGGRESSIVE
    )
    assert conservative.logical_qubits_required == 6190
    assert aggressive.logical_qubits_required == 6190
    assert conservative.gate_count_required == aggressive.gate_count_required
    assert aggressive.projected_break_year is not None
    assert conservative.projected_break_year is not None
    assert aggressive.projected_break_year < conservative.projected_break_year


def test_strongest_x_evidence_tier_then_longest_lifetime_governs() -> None:
    context = _worked_context(
        retention_evidence=[
            RetentionEvidence(
                source=EvidenceSource.SCANNER,
                data_category="session_token",
                lifetime_years=1,
                basis=RetentionBasis.ASSUMPTION,
            ),
            RetentionEvidence(
                source=EvidenceSource.SCANNER,
                data_category="health_record",
                lifetime_years=10,
                basis=RetentionBasis.ASSUMPTION,
            ),
            RetentionEvidence(
                source=EvidenceSource.ORG_POLICY,
                data_category="archive",
                lifetime_years=30,
                basis=RetentionBasis.ASSUMPTION,
            ),
        ]
    )
    context.data_category = None
    context.provenance.pop("data_category")
    track = evaluate_mosca(
        context,
        load_risk_profiles().retention,
        planning_horizon_years=12,
        resource=evaluate_resources(_rsa(), load_risk_profiles().quantum),
    )
    assert track.x_years == 10
    assert track.confidence is Confidence.MEDIUM


def test_mosca_marks_a_positive_shortfall_urgent() -> None:
    result = _assess(context=_worked_context(migration_time_years=6))
    assert result.mosca.is_urgent is True
    assert result.mosca.shortfall_years == 2


def test_missing_factor_downgrades_weaker_track_confidence() -> None:
    profiles = load_risk_profiles()
    high_capability = CapabilityPoint(
        year=2026,
        logical_qubits=10_000,
        logical_gates=10_000_000_000,
        confidence="roadmap",
        basis="test roadmap point",
    )
    quantum = profiles.quantum.model_copy(update={"capability_curve": [high_capability]})
    test_profiles = profiles.model_copy(update={"quantum": quantum})
    context = _worked_context(
        business_criticality=BusinessCriticality.UNKNOWN,
        exposure=ExposureLevel.UNKNOWN,
    )
    context.provenance.pop("business_criticality")
    context.provenance.pop("exposure")

    result = classify_risk(
        _rsa(),
        context,
        test_profiles,
        RiskSettings(planning_horizon_years=12),
        assessment_id="confidence-test",
        assessed_at=ASSESSMENT_TIME,
    )

    assert result.mosca.confidence is Confidence.MEDIUM
    assert result.resource.confidence is Confidence.MEDIUM
    assert result.final_confidence is Confidence.LOW


def test_worked_example_reproduces_exactly() -> None:
    result = _assess()
    assert result.mosca.x_years == 8
    assert result.mosca.y_years == 4
    assert result.mosca.z_years == 12
    assert result.mosca.shortfall_years == 0
    assert result.resource.logical_qubits_required == 6190
    assert result.resource.gate_count_required == 2_624_225_018
    assert result.resource.projected_break_year == 2036
    assert result.resource.m_years == 10
    assert result.final_score == 58
    assert result.final_confidence is Confidence.LOW
    assert result.priority.value == "p1"


def test_hndl_and_signature_authenticity_are_distinct() -> None:
    context = _worked_context(data_classification=DataClassification.RESTRICTED)
    result = hndl_status(_rsa(), context, x_years=12, resource_years=10)
    assert result.state == "harvest_now_decrypt_later"
    signature = _rsa().model_copy(update={"purposes": [Purpose.DIGITAL_SIGNATURE]})
    signature_result = hndl_status(signature, context, x_years=12, resource_years=10)
    assert signature_result.state == "authenticity_at_crqc"


def test_rescore_all_recalculates_every_explicit_item() -> None:
    asset = _rsa()
    context = _worked_context(artefact_id=asset.artefact_id)
    results = rescore_all(
        [(asset, context, "assessment-rescored")],
        load_risk_profiles(),
        RiskSettings(planning_horizon_years=12),
        assessed_at=ASSESSMENT_TIME,
    )
    assert [item.assessment_id for item in results] == ["assessment-rescored"]
    assert results[0].final_score == 58


def test_criticality_inherits_down_dependency_graph_without_overwriting_context() -> None:
    contexts = [
        ArtefactContext(artefact_id="library"),
        ArtefactContext(artefact_id="algorithm"),
        ArtefactContext(
            artefact_id="explicit-low",
            business_criticality=BusinessCriticality.LOW,
            provenance={
                "business_criticality": Provenance(tier=ProvenanceTier.USER)
            },
        ),
    ]
    edges = [
        DependencyEdge(
            source_id="payments-api",
            target_id="library",
            source_kind="application",
            target_kind="artefact",
            relation="depends_on",
        ),
        DependencyEdge(
            source_id="library",
            target_id="algorithm",
            source_kind="artefact",
            target_kind="artefact",
            relation="provides",
        ),
        DependencyEdge(
            source_id="payments-api",
            target_id="explicit-low",
            source_kind="application",
            target_kind="artefact",
            relation="depends_on",
        ),
    ]

    resolved = inherit_dependency_criticality(
        contexts,
        edges,
        application_criticalities={"payments-api": BusinessCriticality.CRITICAL},
    )

    assert resolved["algorithm"].business_criticality is BusinessCriticality.CRITICAL
    provenance = resolved["algorithm"].provenance["business_criticality"]
    assert provenance.tier is ProvenanceTier.ORG_PRESET
    assert provenance.source_detail == "inherited from dependency root payments-api"
    assert resolved["explicit-low"].business_criticality is BusinessCriticality.LOW


def test_setting_change_appends_assessments_and_preserves_settings_history(
    session, scan_row
) -> None:
    asset = _rsa()
    session.add(artefact_to_row(asset, scan_id=scan_row.id))
    context = _worked_context(artefact_id=asset.artefact_id)
    session.add(context_to_row(context, row_id="ctx-1"))
    session.commit()

    profiles = load_risk_profiles()
    first = apply_risk_settings_and_rescore(
        session,
        setting_id="settings-1",
        setting_version="risk-settings-1",
        profiles=profiles,
        settings=RiskSettings(planning_horizon_years=12),
        assessment_id_for=lambda artefact_id: f"first-{artefact_id}",
        assessed_at=ASSESSMENT_TIME,
    )
    session.commit()

    second = apply_risk_settings_and_rescore(
        session,
        setting_id="settings-2",
        setting_version="risk-settings-2",
        profiles=profiles,
        settings=RiskSettings(planning_horizon_years=10),
        assessment_id_for=lambda artefact_id: f"second-{artefact_id}",
        assessed_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    session.commit()

    assert first.artefacts_rescored == second.artefacts_rescored == 1
    from app.models.tables import OrgSettingVersion, RiskAssessment

    settings_rows = session.query(OrgSettingVersion).order_by(OrgSettingVersion.id).all()
    assert [row.is_active for row in settings_rows] == [False, True]
    assessment_rows = session.query(RiskAssessment).all()
    assert len(assessment_rows) == 2
    assert {row.id for row in assessment_rows} == {
        f"first-{asset.artefact_id}",
        f"second-{asset.artefact_id}",
    }


def test_cbom_cli_produces_end_to_end_verdicts(tmp_path: Path, capsys) -> None:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "tests"
        / "golden"
        / "positive-fixtures.cbom.json"
    )
    document = json.loads(fixture.read_text(encoding="utf-8"))
    scan_target = "https://git.example.org/patients"
    artefacts = ingest_document(document, scan_target=scan_target).artefacts
    contexts = {
        artefact.artefact_id: {
            "data_category": "aadhaar_pii",
            "data_classification": "internal",
            "business_criticality": "critical",
            "exposure": "internet",
            "migration_time_years": 4,
            "provenance": {
                "data_category": {"tier": "scanner_evidence"},
                "migration_time_years": {"tier": "user"},
            },
        }
        for artefact in artefacts
    }
    cbom_path = tmp_path / "scan.cbom.json"
    context_path = tmp_path / "contexts.json"
    cbom_path.write_text(json.dumps(document), encoding="utf-8")
    context_path.write_text(json.dumps(contexts), encoding="utf-8")

    result = main(
        [
            "--cbom",
            str(cbom_path),
            "--scan-target",
            scan_target,
            "--contexts",
            str(context_path),
            "--planning-horizon",
            "12",
            "--assessed-at",
            "2026-01-01T00:00:00+00:00",
        ]
    )

    verdicts = json.loads(capsys.readouterr().out)
    assert result == 0
    assert any(
        item["final_score"] == 58 and item["priority"] == "p1"
        for item in verdicts
    )
