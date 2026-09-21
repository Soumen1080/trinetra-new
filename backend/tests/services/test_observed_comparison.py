from dataclasses import dataclass
from typing import Any
from app.models.enums import AssetType, Confidence, ProtocolName
from app.services.observed_comparison import (
    compare_observed_vs_declared,
    generate_comparison_report,
)


@dataclass
class CryptoArtefact:
    id: str
    scan_id: str
    application_id: str
    name: str
    asset_type: AssetType
    confidence: Confidence = Confidence.HIGH
    detail: dict[str, Any] | None = None


def test_matched_protocol():
    """When a protocol is both declared and observed, it matches."""
    declared = CryptoArtefact(
        id="art-1",
        scan_id="scan-1",
        application_id="app-1",
        name="TLS 1.2",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.2",
            "is_observed": False,
        },
    )

    observed = CryptoArtefact(
        id="art-2",
        scan_id="scan-2",
        application_id="app-1",
        name="TLS 1.2",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.2",
            "is_observed": True,
        },
    )

    result = compare_observed_vs_declared([declared, observed])

    assert result.total_protocols == 1
    assert result.matched == 1
    assert result.mismatched == 0
    assert result.observed_only == 0
    assert result.declared_only == 0
    assert len(result.critical_issues) == 0


def test_observed_but_not_declared():
    """When a protocol is observed but not declared, it's critical."""
    observed = CryptoArtefact(
        id="art-1",
        scan_id="scan-1",
        application_id="app-1",
        name="TLS 1.0",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.0",
            "is_observed": True,
        },
    )

    result = compare_observed_vs_declared([observed])

    assert result.total_protocols == 1
    assert result.matched == 0
    assert result.observed_only == 1
    assert len(result.critical_issues) == 1
    assert "NOT declared in configuration" in result.critical_issues[0]


def test_declared_but_not_observed():
    """When a protocol is declared but not observed, it's informational."""
    declared = CryptoArtefact(
        id="art-1",
        scan_id="scan-1",
        application_id="app-1",
        name="TLS 1.3",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.3",
            "is_observed": False,
        },
    )

    result = compare_observed_vs_declared([declared])

    assert result.total_protocols == 1
    assert result.declared_only == 1
    assert len(result.critical_issues) == 0


def test_weak_protocol_flagged():
    """Weak protocols observed but not declared get extra warning."""
    observed = CryptoArtefact(
        id="art-1",
        scan_id="scan-1",
        application_id="app-1",
        name="TLS 1.0",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.0",
            "is_observed": True,
        },
    )

    result = compare_observed_vs_declared([observed])

    assert result.total_protocols == 1
    assert len(result.critical_issues) == 1
    assert "cryptographically weak" in result.critical_issues[0]


def test_multiple_protocols():
    """Compare multiple protocols at once."""
    artefacts = [
        # TLS 1.3: matched
        CryptoArtefact(
            id="art-1",
            scan_id="scan-1",
            application_id="app-1",
            name="TLS 1.3",
            asset_type=AssetType.PROTOCOL,
            confidence=Confidence.HIGH,
            detail={
                "detail_type": "protocol",
                "protocol": "tls",
                "version": "1.3",
                "is_observed": False,
            },
        ),
        CryptoArtefact(
            id="art-2",
            scan_id="scan-2",
            application_id="app-1",
            name="TLS 1.3",
            asset_type=AssetType.PROTOCOL,
            confidence=Confidence.HIGH,
            detail={
                "detail_type": "protocol",
                "protocol": "tls",
                "version": "1.3",
                "is_observed": True,
            },
        ),
        # TLS 1.0: observed only (critical)
        CryptoArtefact(
            id="art-3",
            scan_id="scan-2",
            application_id="app-1",
            name="TLS 1.0",
            asset_type=AssetType.PROTOCOL,
            confidence=Confidence.HIGH,
            detail={
                "detail_type": "protocol",
                "protocol": "tls",
                "version": "1.0",
                "is_observed": True,
            },
        ),
        # SSH-2.0: declared only
        CryptoArtefact(
            id="art-4",
            scan_id="scan-1",
            application_id="app-1",
            name="SSH",
            asset_type=AssetType.PROTOCOL,
            confidence=Confidence.HIGH,
            detail={
                "detail_type": "protocol",
                "protocol": "ssh",
                "version": "2.0",
                "is_observed": False,
            },
        ),
    ]

    result = compare_observed_vs_declared(artefacts)

    assert result.total_protocols == 3
    assert result.matched == 1
    assert result.observed_only == 1
    assert result.declared_only == 1
    assert len(result.critical_issues) == 1


def test_report_generation():
    """Generate a comparison report for API consumption."""
    observed = CryptoArtefact(
        id="art-1",
        scan_id="scan-1",
        application_id="app-1",
        name="TLS 1.0",
        asset_type=AssetType.PROTOCOL,
        confidence=Confidence.HIGH,
        detail={
            "detail_type": "protocol",
            "protocol": "tls",
            "version": "1.0",
            "is_observed": True,
        },
    )

    summary = compare_observed_vs_declared([observed])
    summary.application_id = "app-1"
    report = generate_comparison_report(summary)

    assert report["application_id"] == "app-1"
    assert report["summary"]["total_protocols"] == 1
    assert report["summary"]["observed_only"] == 1
    assert len(report["critical_issues"]) == 1
    assert len(report["comparisons"]) == 1
    assert report["comparisons"][0]["protocol"] == "tls"
    assert report["comparisons"][0]["version"] == "1.0"
    assert report["comparisons"][0]["severity"] == "critical"


def test_non_protocol_artefacts_ignored():
    """Only protocol artefacts are compared."""
    artefacts = [
        CryptoArtefact(
            id="art-1",
            scan_id="scan-1",
            application_id="app-1",
            name="AES",
            asset_type=AssetType.ALGORITHM,
            confidence=Confidence.HIGH,
            detail=None,
        ),
        CryptoArtefact(
            id="art-2",
            scan_id="scan-1",
            application_id="app-1",
            name="RSA Key",
            asset_type=AssetType.KEY,
            confidence=Confidence.HIGH,
            detail={"detail_type": "key", "size_bits": 2048},
        ),
    ]

    result = compare_observed_vs_declared(artefacts)

    assert result.total_protocols == 0
    assert result.matched == 0
