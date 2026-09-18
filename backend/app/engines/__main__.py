"""Command-line boundary for Phase 5's scan-to-verdict vertical slice.

Example::

    python -m app.engines --cbom scan.cbom.json --scan-target repo://patients \
        --contexts contexts.json \
        --planning-horizon 12 --assessed-at 2026-01-01T00:00:00+00:00

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
from app.engines.profiles import load_risk_profiles
from app.models.enums import ResourceScenario
from app.schemas.context import ArtefactContext
from app.services.cbom_ingest import ingest_document


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
        description="Classify a CycloneDX CBOM using Trinetra Phase-5 risk profiles."
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = _json_file(args.cbom)
        contexts = _contexts_by_artefact(_json_file(args.contexts))
        ingested = ingest_document(document, scan_target=args.scan_target)
        profiles = load_risk_profiles()
        settings = RiskSettings(
            planning_horizon_years=args.planning_horizon,
            scenario=ResourceScenario(args.scenario),
        )
        assessed_at = _assessed_at(args.assessed_at)
        assessments = []
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
            assessments.append(assessment.model_dump(mode="json"))
    except ValueError as error:
        print(f"trinetra risk: {error}", file=sys.stderr)
        return 2

    json.dump(assessments, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
