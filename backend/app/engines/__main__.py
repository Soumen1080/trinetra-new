"""Command-line boundary for scan-to-verdict and export (Phases 5-7).

Example::

    python -m app.engines --cbom scan.cbom.json --scan-target repo://patients \\
        --contexts contexts.json \\
        --planning-horizon 12 --assessed-at 2026-01-01T00:00:00+00:00

    # Phase 7 — export to CycloneDX:
    python -m app.engines --cbom scan.cbom.json --scan-target repo://patients \\
        --contexts contexts.json --assessed-at 2026-01-01T00:00:00+00:00 \\
        --format cyclonedx --output out.cbom.json

    # Phase 7 — diff against a baseline:
    python -m app.engines --cbom scan.cbom.json --scan-target repo://patients \\
        --contexts contexts.json --assessed-at 2026-01-01T00:00:00+00:00 \\
        --format json --output out.json --diff-baseline baseline.cbom.json

``contexts.json`` is either a list of ``ArtefactContext`` objects or an object
whose keys are artefact ids and whose values are context fields.  The command
does not invent business context: an artefact with missing evidence returns an
honest ``needs_context`` verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from app.engines.final_risk_engine import RiskSettings, classify_risk
from app.engines.profiles import load_pqc_evidence_profile, load_risk_profiles
from app.engines.recommendation_engine import (
    recommend_replacement,
    recommendation_id_for_assessment,
)
from app.exporters import ExportFormat, export
from app.exporters.diff import compute_diff, export_diff_json
from app.models.enums import ResourceScenario
from app.schemas.context import ArtefactContext
from app.schemas.recommendation import PqcRecommendation, RecommendationContext
from app.schemas.risk import RiskAssessment
from app.services.cbom_ingest import ingest_document

#: Formats that produce binary output (written in 'wb' mode).
_BINARY_FORMATS = {ExportFormat.EXCEL, ExportFormat.PDF_EXECUTIVE, ExportFormat.PDF_TECHNICAL}


def _json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read JSON file {path}: {error}") from error


def _contexts_by_artefact(payload: Any) -> dict[str, ArtefactContext]:
    if isinstance(payload, dict) and "contexts" in payload:
        payload = payload["contexts"]
    records: list[dict[str, Any]] = []
    if isinstance(payload, list):
        records = [item for item in payload if isinstance(item, dict)]
        if len(records) != len(payload):
            raise ValueError("each context list item must be an object")
    elif isinstance(payload, dict):
        for artefact_id, fields in payload.items():
            if not isinstance(fields, dict):
                raise ValueError("each context mapping value must be an object")
            records.append({"artefact_id": artefact_id, **fields})
    else:
        raise ValueError("contexts must be a list or an artefact-id mapping")

    contexts = [ArtefactContext.model_validate(record) for record in records]
    return {context.artefact_id: context for context in contexts}


def _assessed_at(raw: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("--assessed-at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("--assessed-at must include a UTC offset")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify a CycloneDX CBOM using Trinetra risk profiles "
        "and export to standard formats (Phase 7)."
    )
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument(
        "--scan-target",
        required=True,
        help="Stable scanner target identifier used to reproduce artefact ids.",
    )
    parser.add_argument("--contexts", type=Path, required=True)
    parser.add_argument("--planning-horizon", type=float, default=None)
    parser.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in ResourceScenario],
        default=ResourceScenario.BASELINE.value,
    )
    parser.add_argument(
        "--assessed-at",
        required=True,
        help="Explicit ISO-8601 timestamp; the engine never reads the clock.",
    )

    # Phase 7 — export flags
    parser.add_argument(
        "--format",
        choices=[f.value for f in ExportFormat],
        default=None,
        help="Export format. When omitted, raw assessment JSON is written to "
        "stdout (backward compatible with Phase 5).",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output file path. When omitted, text formats go to stdout.",
    )
    parser.add_argument(
        "--diff-baseline",
        type=Path,
        default=None,
        help="Path to a baseline CBOM for diff report (plan task 7.8).",
    )
    return parser


def _run_engines(
    ingested: Any,
    contexts: dict[str, ArtefactContext],
    profiles: Any,
    recommendation_profile: Any,
    settings: RiskSettings,
    assessed_at: datetime,
) -> tuple[list[RiskAssessment], list[PqcRecommendation]]:
    """Run risk classification and recommendation for all artefacts."""
    assessments: list[RiskAssessment] = []
    recommendations: list[PqcRecommendation] = []

    for artefact in ingested.artefacts:
        context = contexts.get(artefact.artefact_id)
        if context is None:
            context = ArtefactContext(artefact_id=artefact.artefact_id)

        assessment = classify_risk(
            artefact,
            context,
            profiles,
            settings,
            assessment_id=f"preview-{artefact.artefact_id}",
            assessed_at=assessed_at,
        )
        assessments.append(assessment)

        recommendation = recommend_replacement(
            RecommendationContext(
                recommendation_id=recommendation_id_for_assessment(
                    assessment.assessment_id
                ),
                artefact=artefact,
                assessment=assessment,
            ),
            recommendation_profile,
        )
        if recommendation is not None:
            recommendations.append(recommendation)

    return assessments, recommendations


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = _json_file(args.cbom)
        contexts = _contexts_by_artefact(_json_file(args.contexts))
        ingested = ingest_document(document, scan_target=args.scan_target)
        profiles = load_risk_profiles()
        recommendation_profile = load_pqc_evidence_profile()
        settings = RiskSettings(
            planning_horizon_years=args.planning_horizon,
            scenario=ResourceScenario(args.scenario),
        )
        assessed_at = _assessed_at(args.assessed_at)

        assessments, recommendations = _run_engines(
            ingested, contexts, profiles, recommendation_profile,
            settings, assessed_at,
        )

        # ── Phase 7 export path ──────────────────────────────────
        if args.format is not None:
            fmt = ExportFormat(args.format)

            # Diff report: compute delta before exporting
            if args.diff_baseline is not None:
                baseline_doc = _json_file(args.diff_baseline)
                baseline_ingested = ingest_document(
                    baseline_doc, scan_target=args.scan_target
                )
                diff = compute_diff(baseline_ingested, ingested)
                diff_output = export_diff_json(diff)

                # If the requested format is JSON, inject diff into output
                if fmt is ExportFormat.NATIVE_JSON:
                    native = export(
                        ingested, assessments, recommendations, fmt,
                    )
                    # Merge diff into native JSON
                    combined = json.loads(native)
                    combined["diff"] = json.loads(diff_output)
                    output = json.dumps(
                        combined, indent=2, sort_keys=False, default=str
                    )
                    _write_output(output, args.output, binary=False)
                    return 0

            output = export(
                ingested, assessments, recommendations, fmt,
            )
            binary = fmt in _BINARY_FORMATS
            _write_output(output, args.output, binary=binary)
            return 0

        # ── Legacy Phase 5 JSON path (backward compatible) ───────
        legacy_output = []
        rec_map = {r.assessment_id: r for r in recommendations}
        for assessment in assessments:
            rec = rec_map.get(assessment.assessment_id)
            legacy_output.append(
                {
                    **assessment.model_dump(mode="json"),
                    "recommendation": (
                        rec.model_dump(mode="json")
                        if rec is not None
                        else None
                    ),
                }
            )
        json.dump(legacy_output, sys.stdout, indent=2, sort_keys=True)
        print()

    except ValueError as error:
        print(f"trinetra risk: {error}", file=sys.stderr)
        return 2

    return 0


def _write_output(
    content: str | bytes, output_path: Path | None, *, binary: bool
) -> None:
    """Write content to a file or stdout."""
    if output_path is not None:
        mode = "wb" if binary else "w"
        encoding = None if binary else "utf-8"
        output_path.write_bytes(content) if binary else output_path.write_text(
            content, encoding="utf-8"  # type: ignore[arg-type]
        )
        print(f"trinetra: wrote {output_path}", file=sys.stderr)
    elif binary:
        sys.stdout.buffer.write(content)  # type: ignore[arg-type]
    else:
        sys.stdout.write(content)  # type: ignore[arg-type]
        print()


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
