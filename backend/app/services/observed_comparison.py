"""Observed vs Declared comparison logic (Phase 11A).

This module provides the capability to compare protocol findings from live
observation (egress scanner) against declared configuration (container/source
scanners). The comparison reveals whether what is negotiated on the wire matches
what the configuration states, which is the widest coverage gain in Phase 11A.

A load balancer can accept TLS 1.0 even when the backend forbids it, and only
live observation detects this.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.models.artefact import CryptoArtefact
from app.models.enums import AssetType
from app.schemas.artefact import ProtocolDetail


@dataclass
class ProtocolComparison:
    """Comparison of one protocol between observed and declared findings."""

    protocol: str
    version: str | None
    declared_count: int
    observed_count: int
    matched: bool
    severity: str  # "info", "warning", "critical"
    message: str


@dataclass
class ComparisonSummary:
    """Summary of observed vs declared comparison for an application."""

    application_id: str
    total_protocols: int
    matched: int
    mismatched: int
    observed_only: int
    declared_only: int
    comparisons: list[ProtocolComparison]
    critical_issues: list[str]


def compare_observed_vs_declared(
    artefacts: list[CryptoArtefact],
) -> ComparisonSummary:
    """Compare observed protocol findings against declared ones.

    Args:
        artefacts: All artefacts for an application (both observed and declared)

    Returns:
        ComparisonSummary with matched/mismatched protocols and issues
    """
    # Separate observed from declared protocol artefacts
    declared: dict[str, list[CryptoArtefact]] = defaultdict(list)
    observed: dict[str, list[CryptoArtefact]] = defaultdict(list)

    for art in artefacts:
        if art.asset_type != AssetType.PROTOCOL or not art.detail:
            continue

        detail = art.detail
        if not isinstance(detail, dict):
            continue

        protocol_detail = detail
        key = _protocol_key(protocol_detail)

        if protocol_detail.get("is_observed", False):
            observed[key].append(art)
        else:
            declared[key].append(art)

    # Compare each protocol
    comparisons: list[ProtocolComparison] = []
    critical_issues: list[str] = []

    all_keys = set(declared.keys()) | set(observed.keys())

    for key in sorted(all_keys):
        decl_list = declared.get(key, [])
        obs_list = observed.get(key, [])

        comparison = _compare_protocol_key(key, decl_list, obs_list)
        comparisons.append(comparison)

        if comparison.severity == "critical":
            critical_issues.append(comparison.message)

    # Calculate summary stats
    matched = sum(1 for c in comparisons if c.matched)
    mismatched = sum(1 for c in comparisons if not c.matched and c.declared_count > 0 and c.observed_count > 0)
    observed_only = sum(1 for c in comparisons if c.declared_count == 0 and c.observed_count > 0)
    declared_only = sum(1 for c in comparisons if c.observed_count == 0 and c.declared_count > 0)

    return ComparisonSummary(
        application_id="",  # Will be set by caller
        total_protocols=len(comparisons),
        matched=matched,
        mismatched=mismatched,
        observed_only=observed_only,
        declared_only=declared_only,
        comparisons=comparisons,
        critical_issues=critical_issues,
    )


def _protocol_key(detail: dict[str, Any]) -> str:
    """Generate a key for grouping protocols."""
    protocol = detail.get("protocol", "unknown")
    version = detail.get("version", "")
    return f"{protocol}:{version}" if version else protocol


def _compare_protocol_key(
    key: str,
    declared: list[CryptoArtefact],
    observed: list[CryptoArtefact],
) -> ProtocolComparison:
    """Compare declared vs observed for one protocol key."""
    protocol, _, version = key.partition(":")
    version = version or None

    decl_count = len(declared)
    obs_count = len(observed)

    # Determine match status and severity
    if decl_count > 0 and obs_count > 0:
        # Both declared and observed - this is a match
        matched = True
        severity = "info"
        message = f"{protocol} {version or ''} is configured and observed as expected"

    elif obs_count > 0 and decl_count == 0:
        # Observed but not declared - this is critical!
        # A load balancer or proxy is accepting a protocol the config forbids
        matched = False
        severity = "critical"
        message = (
            f"{protocol} {version or ''} is OBSERVED on the wire but NOT declared in configuration. "
            f"This indicates a load balancer or proxy is accepting protocols the backend forbids."
        )

        # Special handling for weak protocols
        if _is_weak_protocol(protocol, version):
            message += f" {protocol} {version or ''} is cryptographically weak."

    elif decl_count > 0 and obs_count == 0:
        # Declared but not observed - informational
        # Could mean the protocol is configured but not actively used
        matched = False
        severity = "info"
        message = f"{protocol} {version or ''} is declared in configuration but not observed in live traffic"

    else:
        # Should not happen
        matched = False
        severity = "info"
        message = f"{protocol} {version or ''} has no findings"

    return ProtocolComparison(
        protocol=protocol,
        version=version,
        declared_count=decl_count,
        observed_count=obs_count,
        matched=matched,
        severity=severity,
        message=message,
    )


def _is_weak_protocol(protocol: str, version: str | None) -> bool:
    """Check if a protocol version is known to be weak."""
    protocol = protocol.lower()

    if protocol == "tls":
        if version in ("1.0", "1.1"):
            return True
    elif protocol in ("ssl", "sslv3", "sslv2"):
        return True

    return False


def generate_comparison_report(summary: ComparisonSummary) -> dict[str, Any]:
    """Generate a detailed comparison report for API/UI consumption."""
    return {
        "application_id": summary.application_id,
        "summary": {
            "total_protocols": summary.total_protocols,
            "matched": summary.matched,
            "mismatched": summary.mismatched,
            "observed_only": summary.observed_only,
            "declared_only": summary.declared_only,
        },
        "critical_issues": summary.critical_issues,
        "comparisons": [
            {
                "protocol": c.protocol,
                "version": c.version,
                "declared_count": c.declared_count,
                "observed_count": c.observed_count,
                "matched": c.matched,
                "severity": c.severity,
                "message": c.message,
            }
            for c in summary.comparisons
        ],
    }
