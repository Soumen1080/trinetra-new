"""Full-fidelity native JSON export (plan task 7.3).

Unlike CycloneDX or SPDX, this format preserves *everything* the platform
produces: risk assessments, Mosca tracks, resource tracks, PQC
recommendations, migration plans, deployment dimensions and all provenance.

The output carries a ``schema_version`` header so consumers can detect
breaking changes and a future API can serve the same shape.
"""

from __future__ import annotations

import json
from typing import Any

from app.schemas.recommendation import MigrationPlan, PqcRecommendation
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult

#: Version of the native export schema.
NATIVE_EXPORT_VERSION = "1.0"


def export_native_json(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
    *,
    migration_plan: MigrationPlan | None = None,
) -> str:
    """Export the complete Trinetra output as a single JSON document.

    This is the format that carries everything the standard formats cannot:
    risk scores, Mosca tracks, resource projections, PQC recommendations,
    migration waves and deployment dimensions.
    """
    assessments = assessments or []
    recommendations = recommendations or []

    assessment_by_artefact = {a.artefact_id: a for a in assessments}
    recommendation_by_assessment = {r.assessment_id: r for r in recommendations}

    enriched_artefacts: list[dict[str, Any]] = []
    for artefact in scan_result.deduplicated():
        entry: dict[str, Any] = artefact.model_dump(mode="json")
        assessment = assessment_by_artefact.get(artefact.artefact_id)
        if assessment:
            entry["risk_assessment"] = assessment.model_dump(mode="json")
            rec = recommendation_by_assessment.get(assessment.assessment_id)
            if rec:
                entry["recommendation"] = rec.model_dump(mode="json")
        enriched_artefacts.append(entry)

    output: dict[str, Any] = {
        "trinetra_export_version": NATIVE_EXPORT_VERSION,
        "scan": {
            "scan_id": scan_result.scan_id,
            "target": scan_result.target.model_dump(mode="json"),
            "status": scan_result.status.value,
            "started_at": scan_result.started_at.isoformat(),
            "finished_at": (
                scan_result.finished_at.isoformat()
                if scan_result.finished_at
                else None
            ),
            "scanners_run": [s.value for s in scan_result.scanners_run],
            "tool_versions": [
                tv.model_dump(mode="json") for tv in scan_result.tool_versions
            ],
            "schema_version": scan_result.schema_version,
            "coverage": scan_result.coverage.model_dump(mode="json"),
            "errors": [e.model_dump(mode="json") for e in scan_result.errors],
        },
        "artefacts": enriched_artefacts,
        "summary": {
            "total_artefacts": len(enriched_artefacts),
            "artefacts_by_type": scan_result.artefacts_by_type(),
            "quantum_vulnerable_count": sum(
                1 for a in scan_result.deduplicated() if a.is_quantum_vulnerable
            ),
            "assessed_count": len(assessments),
            "recommendations_count": len(recommendations),
        },
    }

    if migration_plan:
        output["migration_plan"] = migration_plan.model_dump(mode="json")

    return json.dumps(output, indent=2, sort_keys=False, default=str)


__all__ = ["export_native_json"]
