"""Standardised Reporting & Export (Phase 7).

Each exporter is a pure function: ``(data) → str | bytes``.  No database
access, no I/O beyond the return value.  The CLI or API layer handles file
writing.

Usage::

    from app.exporters import export, ExportFormat

    cbom_json = export(scan_result, assessments, recommendations, ExportFormat.CYCLONEDX)
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.schemas.recommendation import MigrationPlan, PqcRecommendation
    from app.schemas.risk import RiskAssessment
    from app.schemas.scan import ScanResult


class ExportFormat(str, Enum):
    """Supported export formats."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    NATIVE_JSON = "json"
    CSV = "csv"
    EXCEL = "xlsx"
    SARIF = "sarif"
    PDF_EXECUTIVE = "pdf-executive"
    PDF_TECHNICAL = "pdf-technical"
    HTML_TECHNICAL = "html-technical"


def export(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
    fmt: ExportFormat = ExportFormat.NATIVE_JSON,
    *,
    migration_plan: MigrationPlan | None = None,
    baseline: ScanResult | None = None,
    baseline_assessments: list[RiskAssessment] | None = None,
) -> str | bytes:
    """Dispatch to the appropriate exporter.

    Returns ``str`` for text formats (JSON, CSV, SARIF, HTML) and ``bytes``
    for binary formats (XLSX, PDF).
    """
    assessments = assessments or []
    recommendations = recommendations or []

    if fmt is ExportFormat.CYCLONEDX:
        from app.exporters.cyclonedx import export_cyclonedx

        return export_cyclonedx(scan_result, assessments, recommendations)

    if fmt is ExportFormat.SPDX:
        from app.exporters.spdx import export_spdx

        return export_spdx(scan_result, assessments, recommendations)

    if fmt is ExportFormat.NATIVE_JSON:
        from app.exporters.native_json import export_native_json

        return export_native_json(
            scan_result, assessments, recommendations,
            migration_plan=migration_plan,
        )

    if fmt is ExportFormat.CSV:
        from app.exporters.csv_excel import export_csv

        return export_csv(scan_result, assessments, recommendations)

    if fmt is ExportFormat.EXCEL:
        from app.exporters.csv_excel import export_excel

        return export_excel(scan_result, assessments, recommendations)

    if fmt is ExportFormat.SARIF:
        from app.exporters.sarif import export_sarif

        return export_sarif(scan_result, assessments, recommendations)

    if fmt is ExportFormat.PDF_EXECUTIVE:
        from app.exporters.pdf_report import export_executive_pdf

        return export_executive_pdf(
            scan_result, assessments, recommendations,
            migration_plan=migration_plan,
        )

    if fmt is ExportFormat.PDF_TECHNICAL:
        from app.exporters.pdf_report import export_technical_pdf

        return export_technical_pdf(
            scan_result, assessments, recommendations,
        )

    if fmt is ExportFormat.HTML_TECHNICAL:
        from app.exporters.pdf_report import export_technical_html

        return export_technical_html(
            scan_result, assessments, recommendations,
        )

    raise ValueError(f"unsupported export format: {fmt!r}")


__all__ = [
    "ExportFormat",
    "export",
]
