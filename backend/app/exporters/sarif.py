"""SARIF v2.1.0 export for CI / code-scanning integration (plan task 7.7).

Each crypto artefact becomes a SARIF ``result`` with a rule, message and
physical location.  This allows GitHub Code Scanning, VS Code SARIF Viewer
and other IDE integrations to surface Trinetra findings inline.

Priority → SARIF level mapping:
  P0 → error
  P1 → warning
  P2 → note
  unscored → note
"""

from __future__ import annotations

import json
from typing import Any

from app.models.enums import Priority
from app.schemas.artefact import CryptoArtefact
from app.schemas.recommendation import PqcRecommendation
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)

_PRIORITY_TO_LEVEL: dict[Priority, str] = {
    Priority.P0: "error",
    Priority.P1: "warning",
    Priority.P2: "note",
    Priority.NONE: "note",
}


def export_sarif(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
) -> str:
    """Export findings as a SARIF v2.1.0 JSON string."""
    assessments = assessments or []
    recommendations = recommendations or []

    assessment_by_artefact = {a.artefact_id: a for a in assessments}
    recommendation_by_assessment = {r.assessment_id: r for r in recommendations}

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids_seen: set[str] = set()

    for artefact in scan_result.deduplicated():
        assessment = assessment_by_artefact.get(artefact.artefact_id)
        rec = (
            recommendation_by_assessment.get(assessment.assessment_id)
            if assessment
            else None
        )

        rule_id = _rule_id(artefact)
        if rule_id not in rule_ids_seen:
            rules.append(_build_rule(artefact, rule_id))
            rule_ids_seen.add(rule_id)

        results.append(_build_result(artefact, assessment, rec, rule_id))

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trinetra",
                        "version": scan_result.schema_version,
                        "informationUri": "https://trinetra.dev",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan_result.status.value
                        in {"succeeded", "partial"},
                        "startTimeUtc": scan_result.started_at.isoformat(),
                        "endTimeUtc": (
                            scan_result.finished_at.isoformat()
                            if scan_result.finished_at
                            else None
                        ),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, sort_keys=False, default=str)


def _rule_id(artefact: CryptoArtefact) -> str:
    """Derive a stable rule id from asset type and vulnerability status."""
    return (
        f"trinetra/{artefact.asset_type.value}/"
        f"{artefact.quantum_vulnerability.value}"
    )


def _build_rule(
    artefact: CryptoArtefact, rule_id: str
) -> dict[str, Any]:
    """Build a SARIF rule descriptor."""
    vuln = artefact.quantum_vulnerability.value.replace("_", " ")
    asset = artefact.asset_type.value.replace("_", " ")

    return {
        "id": rule_id,
        "shortDescription": {
            "text": f"Quantum-relevant {asset} ({vuln})",
        },
        "fullDescription": {
            "text": (
                f"A cryptographic {asset} was found with quantum "
                f"vulnerability status '{vuln}'. Post-quantum migration "
                f"may be required."
            ),
        },
        "helpUri": "https://trinetra.dev/docs/findings",
        "properties": {
            "tags": ["security", "cryptography", "quantum"],
        },
    }


def _build_result(
    artefact: CryptoArtefact,
    assessment: RiskAssessment | None,
    recommendation: PqcRecommendation | None,
    rule_id: str,
) -> dict[str, Any]:
    """Build a SARIF result for one artefact."""
    priority = assessment.priority if assessment else Priority.NONE
    level = _PRIORITY_TO_LEVEL.get(priority, "note")

    message_parts = [f"{artefact.name}"]
    if artefact.algorithm:
        message_parts.append(f"algorithm={artefact.algorithm}")
    message_parts.append(
        f"quantum_vulnerability={artefact.quantum_vulnerability.value}"
    )
    if assessment and assessment.final_score is not None:
        message_parts.append(f"risk_score={assessment.final_score}")
    if recommendation and recommendation.recommended_algorithm:
        message_parts.append(
            f"recommended={recommendation.recommended_algorithm}"
        )

    # Locations from evidence
    locations: list[dict[str, Any]] = []
    for ev in artefact.evidence:
        loc_dict: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": ev.location.path,
                    "uriBaseId": "%SRCROOT%",
                },
            }
        }
        region: dict[str, Any] = {}
        if ev.location.line is not None:
            region["startLine"] = ev.location.line
        if ev.location.column is not None:
            region["startColumn"] = ev.location.column
        if ev.location.end_line is not None:
            region["endLine"] = ev.location.end_line
        if region:
            loc_dict["physicalLocation"]["region"] = region
        if ev.snippet and not ev.redacted:
            loc_dict["physicalLocation"]["contextRegion"] = {
                "snippet": {"text": ev.snippet}
            }
        locations.append(loc_dict)

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": ", ".join(message_parts)},
        "locations": locations,
        "fingerprints": {
            "trinetra/artefact-id/v1": artefact.artefact_id,
        },
    }

    # Fixes (if recommendation exists)
    if recommendation and recommendation.recommended_algorithm:
        result["fixes"] = [
            {
                "description": {
                    "text": (
                        f"Migrate to {recommendation.recommended_algorithm}"
                        + (
                            f" ({recommendation.recommended_parameter_set})"
                            if recommendation.recommended_parameter_set
                            else ""
                        )
                    )
                },
            }
        ]

    return result


__all__ = ["export_sarif"]
