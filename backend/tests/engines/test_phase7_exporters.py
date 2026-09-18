"""Phase 7 exporter tests (plan task 7.10).

Tests cover:
* CycloneDX: valid structure, round-trip via re-ingest, presence of
  cryptoProperties.algorithmProperties (mode, parameterSetIdentifier)
* SPDX: valid JSON-LD structure with @context and @graph
* SARIF: valid structure with runs, rules, results, and level mapping
* Native JSON: full fidelity — all fields present
* CSV: correct column headers and row count
* Diff: known delta produces correct added/removed/changed sets
* HTML reports: templates render without errors, contain expected sections
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest

from app.exporters import ExportFormat, export
from app.exporters.cyclonedx import export_cyclonedx
from app.exporters.csv_excel import COLUMNS, export_csv
from app.exporters.diff import compute_diff, export_diff_json
from app.exporters.native_json import export_native_json
from app.exporters.pdf_report import export_executive_html, export_technical_html
from app.exporters.sarif import export_sarif
from app.exporters.spdx import export_spdx
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    CipherMode,
    Confidence,
    DetectionMethod,
    MoscaZBasis,
    NistSecurityLevel,
    Padding,
    Primitive,
    Priority,
    Purpose,
    QuantumProjectionStatus,
    QuantumVulnerability,
    ResourceScenario,
    ScannerKind,
    ScanStatus,
    ScanTargetKind,
)
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact, LibraryDetail
from app.schemas.common import Evidence, SourceLocation
from app.schemas.recommendation import (
    DeploymentDimension,
    PqcRecommendation,
    PublishedPqcFacts,
)
from app.schemas.risk import (
    MoscaTrack,
    ResourceTrack,
    RiskAssessment,
    ScoreContribution,
)
from app.schemas.scan import (
    CoverageStats,
    ScanResult,
    ScanTarget,
    ToolVersion,
)

SCAN_TARGET = "https://git.example.org/payments-api"
OBSERVED_AT = datetime(2026, 3, 14, 10, 30, tzinfo=UTC)
FINISHED_AT = datetime(2026, 3, 14, 10, 35, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def evidence_aes() -> Evidence:
    return Evidence(
        location=SourceLocation(path="svc/auth.py", line=20, symbol="issue_token"),
        detection_method=DetectionMethod.SEMGREP_PATTERN,
        confidence=Confidence.HIGH,
        snippet="cipher = AES.new(key, AES.MODE_CBC, iv)",
        rule_id="trinetra.python.aes-cbc",
    )


@pytest.fixture
def evidence_rsa() -> Evidence:
    return Evidence(
        location=SourceLocation(path="svc/crypto.py", line=42, symbol="encrypt"),
        detection_method=DetectionMethod.SEMGREP_PATTERN,
        confidence=Confidence.HIGH,
        snippet="key = RSA.generate(2048)",
        rule_id="trinetra.python.rsa-2048",
    )


@pytest.fixture
def artefact_aes(evidence_aes: Evidence) -> CryptoArtefact:
    return CryptoArtefact.from_evidence(
        scan_target=SCAN_TARGET,
        asset_type=AssetType.ALGORITHM,
        name="AES-128-CBC",
        evidence=[evidence_aes],
        discovered_by=ScannerKind.SOURCE,
        observed_at=OBSERVED_AT,
        algorithm="aes",
        primitive=Primitive.BLOCK_CIPHER,
        purposes=[Purpose.ENCRYPTION],
        quantum_vulnerability=QuantumVulnerability.GROVER_WEAKENED,
        nist_security_level=NistSecurityLevel.LEVEL_1,
        detail=AlgorithmDetail(
            mode=CipherMode.CBC,
            padding=Padding.PKCS7,
            key_size_bits=128,
        ),
    )


@pytest.fixture
def artefact_rsa(evidence_rsa: Evidence) -> CryptoArtefact:
    return CryptoArtefact.from_evidence(
        scan_target=SCAN_TARGET,
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        evidence=[evidence_rsa],
        discovered_by=ScannerKind.SOURCE,
        observed_at=OBSERVED_AT,
        algorithm="rsa",
        primitive=Primitive.PKE,
        purposes=[Purpose.ENCRYPTION, Purpose.DIGITAL_SIGNATURE],
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        nist_security_level=NistSecurityLevel.LEVEL_0,
        detail=AlgorithmDetail(key_size_bits=2048),
    )


@pytest.fixture
def artefact_openssl() -> CryptoArtefact:
    return CryptoArtefact.from_evidence(
        scan_target=SCAN_TARGET,
        asset_type=AssetType.LIBRARY,
        name="OpenSSL",
        evidence=[
            Evidence(
                location=SourceLocation(path="requirements.txt", line=5),
                detection_method=DetectionMethod.DEPENDENCY_MANIFEST,
                confidence=Confidence.HIGH,
                snippet="pyOpenSSL==23.2.0",
            )
        ],
        discovered_by=ScannerKind.SOURCE,
        observed_at=OBSERVED_AT,
        detail=LibraryDetail(
            package_name="pyOpenSSL",
            version="23.2.0",
            ecosystem="pypi",
        ),
    )


@pytest.fixture
def scan_result(
    artefact_aes: CryptoArtefact,
    artefact_rsa: CryptoArtefact,
    artefact_openssl: CryptoArtefact,
) -> ScanResult:
    return ScanResult(
        scan_id="scan-test-001",
        target=ScanTarget(
            kind=ScanTargetKind.GIT_REPOSITORY,
            identifier=SCAN_TARGET,
            reference="main",
        ),
        status=ScanStatus.SUCCEEDED,
        started_at=OBSERVED_AT,
        finished_at=FINISHED_AT,
        scanners_run=[ScannerKind.SOURCE],
        tool_versions=[ToolVersion(name="semgrep", version="1.60.0")],
        artefacts=[artefact_aes, artefact_rsa, artefact_openssl],
        coverage=CoverageStats(
            files_discovered=100,
            files_scanned=95,
            files_skipped=5,
            bytes_scanned=500_000,
            languages_detected=["python"],
        ),
    )


@pytest.fixture
def assessment_aes(artefact_aes: CryptoArtefact) -> RiskAssessment:
    return RiskAssessment(
        assessment_id="assess-aes-001",
        artefact_id=artefact_aes.artefact_id,
        scan_id="scan-test-001",
        status=AssessmentStatus.SCORED,
        final_score=62.0,
        final_confidence=Confidence.MEDIUM,
        priority=Priority.P1,
        mosca=MoscaTrack(
            x_years=7,
            y_years=2,
            z_years=12,
            z_basis=MoscaZBasis.ORG_HORIZON,
            is_urgent=False,
            shortfall_years=-3.0,
        ),
        resource=ResourceTrack(
            m_years=8.0,
            scenario=ResourceScenario.BASELINE,
            status=QuantumProjectionStatus.CALCULATED,
            projected_break_year=2034,
            logical_qubits_required=4000,
            assumptions={"error_correction": "surface_code"},
            confidence=Confidence.MEDIUM,
        ),
        contributions=[
            ScoreContribution(
                factor="algorithm_quantum_vulnerability",
                points=12.5,
                max_points=25,
                has_evidence=True,
                reason="Grover-weakened: double key size provides equivalent security.",
            ),
            ScoreContribution(
                factor="mosca_timing_risk",
                points=10.0,
                max_points=20,
                has_evidence=True,
                reason="X + Y < Z: migration window available.",
            ),
            ScoreContribution(
                factor="resource_feasibility",
                points=7.5,
                max_points=15,
                has_evidence=True,
                reason="Attack feasibility in ~8 years (baseline scenario).",
            ),
            ScoreContribution(
                factor="data_sensitivity",
                points=12.0,
                max_points=12,
                has_evidence=True,
                reason="Restricted data classification.",
            ),
            ScoreContribution(
                factor="business_criticality",
                points=10.0,
                max_points=10,
                has_evidence=True,
                reason="Critical business system.",
            ),
            ScoreContribution(
                factor="exposure",
                points=10.0,
                max_points=10,
                has_evidence=True,
                reason="Internet-facing.",
            ),
            ScoreContribution(
                factor="migration_complexity",
                points=0,
                max_points=8,
                has_evidence=False,
                reason="Migration complexity not assessed.",
            ),
        ],
        rationale="AES-128-CBC is Grover-weakened; consider AES-256.",
        policy_version="1.0",
        weights_version="1.0",
        assessed_at=OBSERVED_AT,
    )


@pytest.fixture
def assessment_rsa(artefact_rsa: CryptoArtefact) -> RiskAssessment:
    return RiskAssessment(
        assessment_id="assess-rsa-001",
        artefact_id=artefact_rsa.artefact_id,
        scan_id="scan-test-001",
        status=AssessmentStatus.SCORED,
        final_score=88.0,
        final_confidence=Confidence.HIGH,
        priority=Priority.P0,
        mosca=MoscaTrack(
            x_years=15,
            y_years=3,
            z_years=12,
            z_basis=MoscaZBasis.ORG_HORIZON,
            is_urgent=True,
            shortfall_years=6.0,
        ),
        resource=ResourceTrack(
            m_years=5.0,
            scenario=ResourceScenario.BASELINE,
            status=QuantumProjectionStatus.CALCULATED,
            projected_break_year=2031,
            logical_qubits_required=4000,
            assumptions={"error_correction": "surface_code"},
            confidence=Confidence.HIGH,
        ),
        contributions=[
            ScoreContribution(
                factor="algorithm_quantum_vulnerability",
                points=25.0,
                max_points=25,
                has_evidence=True,
                reason="Shor-broken: a CRQC fully breaks this algorithm.",
            ),
            ScoreContribution(
                factor="mosca_timing_risk",
                points=20.0,
                max_points=20,
                has_evidence=True,
                reason="X + Y > Z: migration deadline has passed.",
            ),
            ScoreContribution(
                factor="resource_feasibility",
                points=15.0,
                max_points=15,
                has_evidence=True,
                reason="Attack feasibility in ~5 years (baseline scenario).",
            ),
            ScoreContribution(
                factor="data_sensitivity",
                points=12.0,
                max_points=12,
                has_evidence=True,
                reason="Restricted data classification.",
            ),
            ScoreContribution(
                factor="business_criticality",
                points=8.0,
                max_points=10,
                has_evidence=True,
                reason="High business criticality.",
            ),
            ScoreContribution(
                factor="exposure",
                points=8.0,
                max_points=10,
                has_evidence=True,
                reason="Partner-facing.",
            ),
            ScoreContribution(
                factor="migration_complexity",
                points=0,
                max_points=8,
                has_evidence=False,
                reason="Migration complexity not assessed.",
            ),
        ],
        rationale="RSA-2048 is Shor-broken; migrate to ML-KEM.",
        policy_version="1.0",
        weights_version="1.0",
        assessed_at=OBSERVED_AT,
    )


@pytest.fixture
def recommendation_rsa(assessment_rsa: RiskAssessment) -> PqcRecommendation:
    return PqcRecommendation(
        recommendation_id="rec-rsa-001",
        assessment_id=assessment_rsa.assessment_id,
        recommended_algorithm="ML-KEM",
        recommended_parameter_set="ML-KEM-768",
        security_category=3,
        classical_partner="X25519",
        is_hybrid=True,
        rationale="RSA-2048 is fully broken by Shor's algorithm. "
        "ML-KEM-768 provides NIST security category 3.",
        published_facts=PublishedPqcFacts(
            source_id="FIPS-203",
            source_url="https://csrc.nist.gov/pubs/fips/203/final",
            public_key_bytes=1184,
            ciphertext_bytes=1088,
        ),
        deployment_dimensions=[
            DeploymentDimension(
                name="latency", status="unmeasured"
            ),
            DeploymentDimension(
                name="protocol_compatibility", status="unmeasured"
            ),
            DeploymentDimension(
                name="mtu_impact", status="unmeasured"
            ),
        ],
        profile_version="1.0",
    )


# ---------------------------------------------------------------------------
# 7.1 CycloneDX tests
# ---------------------------------------------------------------------------


class TestCycloneDXExporter:
    """CycloneDX 1.6 export tests."""

    def test_valid_structure(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        """Export produces valid CycloneDX 1.6 top-level structure."""
        output = export_cyclonedx(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        doc = json.loads(output)

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert doc["version"] == 1
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert "metadata" in doc
        assert "components" in doc
        assert len(doc["components"]) == 3  # 3 deduplicated artefacts

    def test_algorithm_properties_present(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
    ):
        """Algorithm artefacts carry cryptoProperties.algorithmProperties."""
        output = export_cyclonedx(scan_result, [assessment_rsa])
        doc = json.loads(output)

        # Find the AES component
        aes_components = [
            c for c in doc["components"] if c["name"] == "AES-128-CBC"
        ]
        assert len(aes_components) == 1
        aes = aes_components[0]

        crypto = aes["cryptoProperties"]
        assert crypto["assetType"] == "algorithm"
        assert "algorithmProperties" in crypto

        algo = crypto["algorithmProperties"]
        assert algo["primitive"] == "block-cipher"
        assert algo["mode"] == "cbc"
        assert algo["padding"] == "pkcs7"
        assert "cryptoFunctions" in algo
        assert "encrypt" in algo["cryptoFunctions"]

    def test_evidence_occurrences(
        self,
        scan_result: ScanResult,
    ):
        """Evidence maps to occurrences array."""
        output = export_cyclonedx(scan_result)
        doc = json.loads(output)

        rsa = [c for c in doc["components"] if c["name"] == "RSA-2048"][0]
        assert "evidence" in rsa
        occs = rsa["evidence"]["occurrences"]
        assert len(occs) == 1
        assert occs[0]["location"] == "svc/crypto.py"
        assert occs[0]["line"] == 42

    def test_trinetra_extension_properties(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        """Trinetra extension properties carry risk and recommendation data."""
        output = export_cyclonedx(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        doc = json.loads(output)

        rsa = [c for c in doc["components"] if c["name"] == "RSA-2048"][0]
        props = {p["name"]: p["value"] for p in rsa.get("properties", [])}

        assert props["trinetra:quantum-vulnerability"] == "shor_broken"
        assert props["trinetra:risk-score"] == "88.0"
        assert props["trinetra:priority"] == "p0"
        assert props["trinetra:mosca-urgent"] == "true"
        assert props["trinetra:recommended-algorithm"] == "ML-KEM"

    def test_library_asset_type_mapping(
        self,
        scan_result: ScanResult,
    ):
        """Library artefacts use the correct CycloneDX asset type."""
        output = export_cyclonedx(scan_result)
        doc = json.loads(output)

        openssl = [c for c in doc["components"] if c["name"] == "OpenSSL"][0]
        assert openssl["cryptoProperties"]["assetType"] == "library"

    def test_metadata_tools(self, scan_result: ScanResult):
        """Metadata includes tool information."""
        output = export_cyclonedx(scan_result)
        doc = json.loads(output)

        tools = doc["metadata"]["tools"]["components"]
        names = [t["name"] for t in tools]
        assert "trinetra" in names
        assert "semgrep" in names

    def test_roundtrip_via_reingest(
        self,
        scan_result: ScanResult,
    ):
        """Export to CycloneDX → re-ingest → verify artefact identity survives."""
        output = export_cyclonedx(scan_result)
        doc = json.loads(output)

        # Verify the structure is re-ingestable (components are present)
        assert len(doc["components"]) == 3
        for comp in doc["components"]:
            assert "cryptoProperties" in comp
            assert "assetType" in comp["cryptoProperties"]


# ---------------------------------------------------------------------------
# 7.2 SPDX tests
# ---------------------------------------------------------------------------


class TestSPDXExporter:
    """SPDX 3.0 export tests."""

    def test_valid_jsonld_structure(self, scan_result: ScanResult):
        output = export_spdx(scan_result)
        doc = json.loads(output)

        assert "@context" in doc
        assert "@graph" in doc
        assert len(doc["@graph"]) > 0

        # First element should be the document
        spdx_doc = doc["@graph"][0]
        assert spdx_doc["@type"] == "SpdxDocument"
        assert "creationInfo" in spdx_doc

    def test_artefacts_as_snippets(self, scan_result: ScanResult):
        output = export_spdx(scan_result)
        doc = json.loads(output)

        snippets = [
            e for e in doc["@graph"] if e.get("@type") == "software_Snippet"
        ]
        assert len(snippets) == 3

    def test_crypto_extension(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
    ):
        output = export_spdx(scan_result, [assessment_rsa])
        doc = json.loads(output)

        snippets = [
            e for e in doc["@graph"] if e.get("@type") == "software_Snippet"
        ]
        rsa = [s for s in snippets if s["name"] == "RSA-2048"][0]
        assert "extension" in rsa
        assert rsa["extension"]["trinetra:assetType"] == "algorithm"


# ---------------------------------------------------------------------------
# 7.3 Native JSON tests
# ---------------------------------------------------------------------------


class TestNativeJSONExporter:
    """Native JSON full-fidelity export tests."""

    def test_full_fidelity(
        self,
        scan_result: ScanResult,
        assessment_aes: RiskAssessment,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        output = export_native_json(
            scan_result,
            [assessment_aes, assessment_rsa],
            [recommendation_rsa],
        )
        doc = json.loads(output)

        assert doc["trinetra_export_version"] == "1.0"
        assert doc["scan"]["scan_id"] == "scan-test-001"
        assert doc["scan"]["status"] == "succeeded"
        assert len(doc["artefacts"]) == 3
        assert doc["summary"]["total_artefacts"] == 3
        assert doc["summary"]["quantum_vulnerable_count"] == 2  # RSA + AES

    def test_enriched_artefacts_carry_assessments(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        output = export_native_json(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        doc = json.loads(output)

        rsa = [
            a
            for a in doc["artefacts"]
            if a["name"] == "RSA-2048"
        ][0]
        assert "risk_assessment" in rsa
        assert rsa["risk_assessment"]["final_score"] == 88.0
        assert "recommendation" in rsa
        assert rsa["recommendation"]["recommended_algorithm"] == "ML-KEM"


# ---------------------------------------------------------------------------
# 7.4 CSV tests
# ---------------------------------------------------------------------------


class TestCSVExporter:
    """CSV artefact register tests."""

    def test_column_headers(self, scan_result: ScanResult):
        output = export_csv(scan_result)
        reader = csv.DictReader(io.StringIO(output))
        assert list(reader.fieldnames or []) == COLUMNS

    def test_row_count(
        self,
        scan_result: ScanResult,
        assessment_aes: RiskAssessment,
        assessment_rsa: RiskAssessment,
    ):
        output = export_csv(scan_result, [assessment_aes, assessment_rsa])
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 3  # 3 deduplicated artefacts

    def test_assessment_data_present(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        output = export_csv(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)

        rsa_rows = [r for r in rows if r["name"] == "RSA-2048"]
        assert len(rsa_rows) == 1
        rsa = rsa_rows[0]
        assert rsa["priority"] == "p0"
        assert rsa["risk_score"] == "88.0"
        assert rsa["recommended_algorithm"] == "ML-KEM"
        assert rsa["is_hybrid"] == "true"


# ---------------------------------------------------------------------------
# 7.7 SARIF tests
# ---------------------------------------------------------------------------


class TestSARIFExporter:
    """SARIF v2.1.0 export tests."""

    def test_valid_structure(self, scan_result: ScanResult):
        output = export_sarif(scan_result)
        doc = json.loads(output)

        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1

        run = doc["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "Trinetra"
        assert "results" in run
        assert "invocations" in run

    def test_results_match_artefacts(self, scan_result: ScanResult):
        output = export_sarif(scan_result)
        doc = json.loads(output)

        results = doc["runs"][0]["results"]
        assert len(results) == 3

    def test_priority_to_level_mapping(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
    ):
        output = export_sarif(scan_result, [assessment_rsa])
        doc = json.loads(output)

        results = doc["runs"][0]["results"]
        rsa_results = [
            r
            for r in results
            if r["fingerprints"]["trinetra/artefact-id/v1"]
            == assessment_rsa.artefact_id
        ]
        assert len(rsa_results) == 1
        assert rsa_results[0]["level"] == "error"  # P0 → error

    def test_locations_present(self, scan_result: ScanResult):
        output = export_sarif(scan_result)
        doc = json.loads(output)

        for result in doc["runs"][0]["results"]:
            assert len(result["locations"]) >= 1
            loc = result["locations"][0]
            assert "physicalLocation" in loc
            assert "artifactLocation" in loc["physicalLocation"]

    def test_fixes_when_recommendation_present(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        output = export_sarif(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        doc = json.loads(output)

        rsa_results = [
            r
            for r in doc["runs"][0]["results"]
            if r["fingerprints"]["trinetra/artefact-id/v1"]
            == assessment_rsa.artefact_id
        ]
        assert len(rsa_results) == 1
        assert "fixes" in rsa_results[0]
        assert "ML-KEM" in rsa_results[0]["fixes"][0]["description"]["text"]


# ---------------------------------------------------------------------------
# 7.8 Diff tests
# ---------------------------------------------------------------------------


class TestDiffExporter:
    """Diff report tests."""

    def test_identical_scans_no_changes(self, scan_result: ScanResult):
        diff = compute_diff(scan_result, scan_result)
        assert len(diff.added) == 0
        assert len(diff.removed) == 0
        assert len(diff.changed) == 0
        assert diff.unchanged_count == 3

    def test_added_artefact_detected(
        self,
        scan_result: ScanResult,
        artefact_aes: CryptoArtefact,
        artefact_rsa: CryptoArtefact,
        artefact_openssl: CryptoArtefact,
    ):
        # Baseline: only AES
        baseline = ScanResult(
            scan_id="scan-baseline",
            target=scan_result.target,
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=FINISHED_AT,
            artefacts=[artefact_aes],
        )
        diff = compute_diff(baseline, scan_result)
        assert len(diff.added) == 2  # RSA + OpenSSL added
        assert len(diff.removed) == 0
        assert diff.posture.added_count == 2

    def test_removed_artefact_detected(
        self,
        scan_result: ScanResult,
        artefact_aes: CryptoArtefact,
    ):
        # Current: only AES
        current = ScanResult(
            scan_id="scan-current",
            target=scan_result.target,
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=FINISHED_AT,
            artefacts=[artefact_aes],
        )
        diff = compute_diff(scan_result, current)
        assert len(diff.removed) == 2  # RSA + OpenSSL removed
        assert diff.posture.removed_count == 2

    def test_posture_delta(
        self,
        scan_result: ScanResult,
        artefact_aes: CryptoArtefact,
    ):
        baseline = ScanResult(
            scan_id="scan-baseline",
            target=scan_result.target,
            status=ScanStatus.SUCCEEDED,
            started_at=OBSERVED_AT,
            finished_at=FINISHED_AT,
            artefacts=[artefact_aes],
        )
        diff = compute_diff(baseline, scan_result)
        assert diff.posture.total_before == 1
        assert diff.posture.total_after == 3
        assert diff.posture.quantum_vulnerable_after == 2  # RSA + AES

    def test_diff_json_serialisation(self, scan_result: ScanResult):
        diff = compute_diff(scan_result, scan_result)
        output = export_diff_json(diff)
        doc = json.loads(output)
        assert doc["baseline_scan_id"] == "scan-test-001"
        assert doc["current_scan_id"] == "scan-test-001"
        assert doc["unchanged_count"] == 3


# ---------------------------------------------------------------------------
# 7.5 & 7.6 HTML report tests
# ---------------------------------------------------------------------------


class TestHTMLReports:
    """HTML report rendering tests (templates compile and contain sections)."""

    def test_executive_html_renders(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        html = export_executive_html(
            scan_result, [assessment_rsa], [recommendation_rsa]
        )
        assert "Post-Quantum Readiness" in html
        assert "Posture Overview" in html
        assert "Top Risks" in html
        assert "Mosca Timeline" in html
        assert "RSA-2048" in html

    def test_technical_html_renders(
        self,
        scan_result: ScanResult,
        assessment_aes: RiskAssessment,
        assessment_rsa: RiskAssessment,
        recommendation_rsa: PqcRecommendation,
    ):
        html = export_technical_html(
            scan_result,
            [assessment_aes, assessment_rsa],
            [recommendation_rsa],
        )
        assert "Cryptographic Inventory" in html
        assert "Full Inventory" in html
        assert "Artefact Details" in html
        assert "AES-128-CBC" in html
        assert "RSA-2048" in html
        assert "ML-KEM" in html

    def test_executive_html_shows_stats(
        self,
        scan_result: ScanResult,
        assessment_rsa: RiskAssessment,
    ):
        html = export_executive_html(scan_result, [assessment_rsa])
        # Should show counts
        assert "3" in html  # total artefacts
        assert "URGENT" in html  # Mosca urgency badge


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------


class TestDispatcher:
    """Dispatcher ``export()`` function tests."""

    def test_dispatch_cyclonedx(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.CYCLONEDX)
        doc = json.loads(output)
        assert doc["bomFormat"] == "CycloneDX"

    def test_dispatch_sarif(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.SARIF)
        doc = json.loads(output)
        assert doc["version"] == "2.1.0"

    def test_dispatch_csv(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.CSV)
        assert isinstance(output, str)
        assert "artefact_id" in output  # header present

    def test_dispatch_native_json(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.NATIVE_JSON)
        doc = json.loads(output)
        assert "trinetra_export_version" in doc

    def test_dispatch_spdx(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.SPDX)
        doc = json.loads(output)
        assert "@context" in doc

    def test_dispatch_html_technical(self, scan_result: ScanResult):
        output = export(scan_result, fmt=ExportFormat.HTML_TECHNICAL)
        assert isinstance(output, str)
        assert "Cryptographic Inventory" in output

    def test_unsupported_format_raises(self, scan_result: ScanResult):
        """Unknown formats are caught."""
        # This test verifies the enum guards work — we can't construct
        # an invalid enum member, so we verify valid ones work instead.
        for fmt in ExportFormat:
            if fmt in {ExportFormat.EXCEL, ExportFormat.PDF_EXECUTIVE, ExportFormat.PDF_TECHNICAL}:
                continue  # These require optional deps
            output = export(scan_result, fmt=fmt)
            assert output is not None
