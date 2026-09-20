"""Trinetra Unified CLI.

Provides command-line operations for CI/CD integration, scanning gates,
accuracy benchmarking, and report exports.

Usage::

    # Scan and fail CI pipeline if critical/P0 risks are found:
    trinetra scan --cbom path/to/cbom.json --fail-on critical --sarif-output results.sarif
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.engines.__main__ import _contexts_by_artefact, _json_file
from app.engines.final_risk_engine import RiskSettings, classify_risk
from app.engines.profiles import load_pqc_evidence_profile, load_risk_profiles
from app.engines.recommendation_engine import (
    recommend_replacement,
    recommendation_id_for_assessment,
)
from app.exporters import ExportFormat, export
from app.models.enums import AssessmentStatus, Priority, ResourceScenario
from app.schemas.context import ArtefactContext
from app.schemas.recommendation import PqcRecommendation, RecommendationContext
from app.schemas.risk import RiskAssessment
from app.schemas.scan import CoverageStats, ScanResult, ScanTarget
from app.services.cbom_ingest import ingest_document

PRIORITY_RANK = {
    "critical": 0,
    "p0": 0,
    "high": 1,
    "p1": 1,
    "medium": 2,
    "p2": 2,
    "low": 3,
    "none": 4,
}


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trinetra",
        description="Trinetra PQC Cryptographic Bill of Materials Analytics CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan", help="Ingest a CBOM, score quantum risks, recommend PQC alternatives, and evaluate CI gating"
    )
    scan_parser.add_argument(
        "--cbom",
        type=Path,
        required=True,
        help="Path to the CycloneDX 1.6 CBOM JSON file.",
    )
    scan_parser.add_argument(
        "--scan-target",
        default="local-target",
        help="Target identifier used for deterministic artefact identity.",
    )
    scan_parser.add_argument(
        "--contexts",
        type=Path,
        default=None,
        help="Optional path to business context JSON.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "p0", "p1", "p2"],
        default=None,
        help="Fail with exit code 1 if findings meet or exceed this risk priority.",
    )
    scan_parser.add_argument(
        "--format",
        choices=["sarif", "cyclonedx", "json", "csv"],
        default="sarif",
        help="Export format for the scan results.",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="File path to write exported findings.",
    )
    scan_parser.add_argument(
        "--sarif-output",
        type=Path,
        default=None,
        help="Shortcut to write SARIF format to a specific file (e.g. for GitHub code scanning).",
    )
    scan_parser.add_argument(
        "--planning-horizon",
        type=float,
        default=8.0,
        help="Planning horizon in years (Z basis).",
    )

    # version subcommand
    subparsers.add_parser("version", help="Print Trinetra version")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    cbom_data = _json_file(args.cbom)
    ingested = ingest_document(cbom_data, scan_target=args.scan_target)

    contexts = _contexts_by_artefact(_json_file(args.contexts)) if args.contexts else {}

    profiles = load_risk_profiles()
    pqc_profile = load_pqc_evidence_profile()
    settings = RiskSettings(
        planning_horizon_years=args.planning_horizon,
        scenario=ResourceScenario.BASELINE,
    )
    now = datetime.now(UTC)

    assessments: list[RiskAssessment] = []
    recommendations: list[PqcRecommendation] = []

    for artefact in ingested.artefacts:
        ctx = contexts.get(artefact.artefact_id) or ArtefactContext(
            artefact_id=artefact.artefact_id
        )
        assessment = classify_risk(
            artefact,
            ctx,
            profiles,
            settings,
            assessment_id=f"assessment-{artefact.artefact_id}",
            assessed_at=now,
        )
        assessments.append(assessment)

        rec = recommend_replacement(
            RecommendationContext(
                recommendation_id=recommendation_id_for_assessment(assessment.assessment_id),
                artefact=artefact,
                assessment=assessment,
            ),
            pqc_profile,
        )
        if rec:
            recommendations.append(rec)

    # Reconstruct ScanResult envelope
    from app.models.enums import ScanStatus, ScanTargetKind
    scan_result = ScanResult(
        scan_id=f"scan-{now.strftime('%Y%m%d%H%M%S')}",
        target=ScanTarget(
            kind=ScanTargetKind.LOCAL_PATH,
            identifier=args.scan_target,
        ),
        status=ScanStatus.SUCCEEDED,
        started_at=now,
        finished_at=now,
        scanners_run=[],
        tool_versions=ingested.tools,
        schema_version="1.0",
        artefacts=ingested.artefacts,
        coverage=CoverageStats(
            files_discovered=0,
            files_scanned=0,
            files_skipped=ingested.skipped_components,
            bytes_scanned=0,
            languages_detected=[],
            gaps=ingested.gaps,
        ),
        errors=[],
    )

    fmt = ExportFormat(args.format)
    if args.sarif_output:
        fmt = ExportFormat.SARIF

    rendered = export(scan_result, assessments, recommendations, fmt=fmt)

    out_path = args.sarif_output or args.output
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(rendered, bytes):
            out_path.write_bytes(rendered)
        else:
            out_path.write_text(rendered, encoding="utf-8")
        print(f"Export written to {out_path}")
    else:
        if isinstance(rendered, str):
            print(rendered)
        else:
            sys.stdout.buffer.write(rendered)

    # Evaluate CI failure gate
    if args.fail_on:
        threshold_rank = PRIORITY_RANK[args.fail_on.lower()]
        violating: list[tuple[str, str]] = []
        for a in assessments:
            if a.status is AssessmentStatus.SCORED:
                prio = a.priority.value.lower()
                if PRIORITY_RANK.get(prio, 99) <= threshold_rank:
                    violating.append((a.artefact_id, a.priority.value))

        if violating:
            print(
                f"\n[POLICY FAILURE] --fail-on={args.fail_on} exceeded: "
                f"{len(violating)} findings at or above threshold:",
                file=sys.stderr,
            )
            for art_id, prio in violating:
                print(f"  - {art_id}: {prio.upper()}", file=sys.stderr)
            return 1
        else:
            print(f"\n[POLICY PASS] No findings exceeded --fail-on={args.fail_on}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "version":
        print("trinetra 0.1.0")
        return 0
    elif args.subcommand == "scan":
        return run_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
