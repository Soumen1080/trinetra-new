"""PDF and HTML report generation (plan tasks 7.5, 7.6, 7.9).

Uses Jinja2 templates for layout and WeasyPrint for HTML → PDF conversion.
Two report types:

* **Executive**: posture summary, Mosca timeline, top risks, budget items.
  Written for a CISO.
* **Technical**: full inventory with file:line evidence and per-artefact risk
  breakdown with remediation steps. Written for an engineer.

WeasyPrint is an optional dependency (``pip install trinetra-backend[report]``).
The HTML variant works without it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from app.models.enums import AssessmentStatus, Priority
from app.schemas.artefact import AlgorithmDetail, CertificateDetail, CryptoArtefact
from app.schemas.recommendation import MigrationPlan, PqcRecommendation
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    """Create the Jinja2 environment pointing at the templates directory."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


# ---------------------------------------------------------------------------
# Context builders
# ---------------------------------------------------------------------------


def _executive_context(
    scan_result: ScanResult,
    assessments: list[RiskAssessment],
    recommendations: list[PqcRecommendation],
    migration_plan: MigrationPlan | None,
) -> dict[str, Any]:
    """Build the template context for the executive report."""
    deduped = scan_result.deduplicated()
    assessment_map = {a.artefact_id: a for a in assessments}
    rec_map = {r.assessment_id: r for r in recommendations}

    total = len(deduped)
    qv_count = sum(1 for a in deduped if a.is_quantum_vulnerable)
    qv_safe_pct = round((total - qv_count) / total * 100) if total else 0

    p0_count = sum(
        1 for a in assessments if a.priority is Priority.P0
    )
    p1_count = sum(
        1 for a in assessments if a.priority is Priority.P1
    )
    mosca_urgent = sum(
        1
        for a in assessments
        if a.mosca.is_urgent is True
    )

    # Top risks (up to 10, P0 first then P1, sorted by score desc)
    scored = [
        a for a in assessments if a.final_score is not None
    ]
    scored.sort(key=lambda a: (a.final_score or 0), reverse=True)
    top_risks: list[dict[str, Any]] = []
    for assessment in scored[:10]:
        artefact = _find_artefact(deduped, assessment.artefact_id)
        rec = rec_map.get(assessment.assessment_id)
        top_risks.append(
            {
                "name": artefact.name if artefact else assessment.artefact_id,
                "priority": assessment.priority.value,
                "score": assessment.final_score,
                "rationale": assessment.rationale or "—",
                "action": (
                    f"Migrate to {rec.recommended_algorithm}"
                    if rec and rec.recommended_algorithm
                    else "Manual review required"
                ),
            }
        )

    # Mosca artefacts
    mosca_artefacts: list[dict[str, Any]] = []
    for assessment in assessments:
        if assessment.mosca.x_years is not None or assessment.mosca.is_urgent is not None:
            artefact = _find_artefact(deduped, assessment.artefact_id)
            mosca_artefacts.append(
                {
                    "name": artefact.name if artefact else assessment.artefact_id,
                    "x": assessment.mosca.x_years,
                    "y": assessment.mosca.y_years,
                    "z": assessment.mosca.z_years,
                    "shortfall": assessment.mosca.shortfall_years,
                    "urgent": assessment.mosca.is_urgent,
                }
            )

    # Migration waves
    migration_waves: list[dict[str, Any]] = []
    if migration_plan:
        wave_map: dict[int, list[Any]] = {}
        for item in migration_plan.items:
            wave_map.setdefault(item.migration_wave, []).append(item)
        for wave_num in sorted(wave_map.keys()):
            items = wave_map[wave_num]
            deadlines = [
                i.mosca_deadline_year for i in items if i.mosca_deadline_year
            ]
            migration_waves.append(
                {
                    "number": wave_num,
                    "count": len(items),
                    "earliest_deadline": min(deadlines) if deadlines else None,
                }
            )

    # Coverage
    cov = scan_result.coverage
    coverage_pct = (
        round(cov.coverage_ratio * 100) if cov.coverage_ratio is not None else 0
    )

    return {
        "scan": scan_result,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": {
            "total_artefacts": total,
            "quantum_vulnerable": qv_count,
            "quantum_safe_pct": qv_safe_pct,
            "p0_count": p0_count,
            "p1_count": p1_count,
            "mosca_urgent_count": mosca_urgent,
        },
        "top_risks": top_risks,
        "mosca_artefacts": mosca_artefacts,
        "artefacts_by_type": scan_result.artefacts_by_type(),
        "coverage": {
            "files_scanned": cov.files_scanned,
            "files_discovered": cov.files_discovered,
            "coverage_pct": coverage_pct,
            "gaps": cov.gaps,
        },
        "migration_waves": migration_waves,
    }


def _technical_context(
    scan_result: ScanResult,
    assessments: list[RiskAssessment],
    recommendations: list[PqcRecommendation],
) -> dict[str, Any]:
    """Build the template context for the technical report."""
    deduped = scan_result.deduplicated()
    assessment_map = {a.artefact_id: a for a in assessments}
    rec_map = {r.assessment_id: r for r in recommendations}

    total = len(deduped)
    qv_count = sum(1 for a in deduped if a.is_quantum_vulnerable)
    assessed = sum(
        1 for a in assessments if a.status is AssessmentStatus.SCORED
    )
    needs_ctx = sum(
        1
        for a in assessments
        if a.status is AssessmentStatus.NEEDS_CONTEXT
    )

    # Inventory table rows
    inventory: list[dict[str, Any]] = []
    detailed: list[dict[str, Any]] = []

    for artefact in deduped:
        assessment = assessment_map.get(artefact.artefact_id)
        rec = (
            rec_map.get(assessment.assessment_id) if assessment else None
        )

        detail = artefact.detail
        key_size = getattr(detail, "key_size_bits", None) or getattr(
            detail, "size_bits", None
        )
        if key_size is None and isinstance(detail, CertificateDetail):
            key_size = detail.public_key_size_bits

        mode = (
            detail.mode.value
            if isinstance(detail, AlgorithmDetail) and detail.mode
            else None
        )

        row: dict[str, Any] = {
            "name": artefact.name,
            "asset_type": artefact.asset_type.value,
            "algorithm": artefact.algorithm,
            "key_size": key_size,
            "mode": mode,
            "quantum_vulnerability": artefact.quantum_vulnerability.value,
            "priority": assessment.priority.value if assessment else None,
            "score": assessment.final_score if assessment else None,
            "location": artefact.primary_location,
        }
        inventory.append(row)

        # Detailed card
        card: dict[str, Any] = {
            **row,
            "primitive": (
                artefact.primitive.value if artefact.primitive else None
            ),
            "evidence": [
                {
                    "location": ev.location.render(),
                    "method": ev.detection_method.value,
                    "confidence": ev.confidence.value,
                    "rule_id": ev.rule_id,
                    "snippet": ev.snippet if not ev.redacted else "[redacted]",
                }
                for ev in artefact.evidence
            ],
            "contributions": [],
            "recommendation": None,
        }

        if assessment:
            card["contributions"] = [
                {
                    "factor": c.factor,
                    "points": c.points,
                    "max_points": c.max_points,
                    "has_evidence": c.has_evidence,
                    "reason": c.reason,
                }
                for c in assessment.contributions
            ]

        if rec:
            card["recommendation"] = {
                "algorithm": rec.recommended_algorithm,
                "parameter_set": rec.recommended_parameter_set,
                "is_hybrid": rec.is_hybrid,
                "classical_partner": rec.classical_partner,
                "rationale": rec.rationale,
            }

        detailed.append(card)

    return {
        "scan": scan_result,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": {
            "total_artefacts": total,
            "quantum_vulnerable": qv_count,
            "assessed": assessed,
            "needs_context": needs_ctx,
        },
        "inventory": inventory,
        "detailed_artefacts": detailed,
    }


def _find_artefact(
    artefacts: list[CryptoArtefact], artefact_id: str
) -> CryptoArtefact | None:
    for a in artefacts:
        if a.artefact_id == artefact_id:
            return a
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_executive_html(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
    *,
    migration_plan: MigrationPlan | None = None,
) -> str:
    """Render the executive report as HTML."""
    assessments = assessments or []
    recommendations = recommendations or []
    ctx = _executive_context(
        scan_result, assessments, recommendations, migration_plan
    )
    template = _env().get_template("executive.html.j2")
    return template.render(**ctx)


def export_executive_pdf(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
    *,
    migration_plan: MigrationPlan | None = None,
) -> bytes:
    """Render the executive report as a PDF.

    Requires ``weasyprint`` (optional ``report`` dependency group).
    """
    html = export_executive_html(
        scan_result, assessments, recommendations,
        migration_plan=migration_plan,
    )
    return _html_to_pdf(html)


def export_technical_html(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
) -> str:
    """Render the technical report as HTML."""
    assessments = assessments or []
    recommendations = recommendations or []
    ctx = _technical_context(scan_result, assessments, recommendations)
    template = _env().get_template("technical.html.j2")
    return template.render(**ctx)


def export_technical_pdf(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
) -> bytes:
    """Render the technical report as a PDF.

    Requires ``weasyprint`` (optional ``report`` dependency group).
    """
    html = export_technical_html(scan_result, assessments, recommendations)
    return _html_to_pdf(html)


def _html_to_pdf(html: str) -> bytes:
    """Convert an HTML string to PDF bytes via WeasyPrint."""
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError as exc:
        raise ImportError(
            "PDF export requires 'weasyprint'. "
            "Install with: pip install trinetra-backend[report]"
        ) from exc

    return WeasyHTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf()


__all__ = [
    "export_executive_html",
    "export_executive_pdf",
    "export_technical_html",
    "export_technical_pdf",
]
