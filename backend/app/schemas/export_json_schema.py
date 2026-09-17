"""Export the artefact contract as JSON Schema (plan task 1.12).

The Go scanners validate against these files before writing a CBOM, and Python
validates again on ingest. Schema drift on either side is then caught at the
boundary rather than three layers deep.

Run as ``python -m app.schemas.export_json_schema``; CI re-runs it and fails if
the checked-in files differ, so the contract cannot drift from the code silently.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.schemas import SCHEMA_VERSION
from app.schemas.artefact import CryptoArtefact
from app.schemas.context import Application, ArtefactContext, DependencyEdge
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult

#: Written relative to the repository root.
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[3] / "contracts"

_EXPORTS: dict[str, type] = {
    "crypto-artefact": CryptoArtefact,
    "scan-result": ScanResult,
    "artefact-context": ArtefactContext,
    "risk-assessment": RiskAssessment,
    "application": Application,
    "dependency-edge": DependencyEdge,
}


def build_schema(model: type, name: str) -> dict[str, Any]:
    schema = model.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://trinetra.local/contracts/{name}-{SCHEMA_VERSION}.json"
    schema["x-trinetra-schema-version"] = SCHEMA_VERSION
    return schema


def _render(schema: dict[str, Any]) -> str:
    """Serialise deterministically so the files diff meaningfully."""
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def export(output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in _EXPORTS.items():
        path = output_dir / f"{name}.schema.json"
        path.write_text(_render(build_schema(model, name)), encoding="utf-8")
        written.append(path)
    return written


def check(output_dir: Path) -> list[Path]:
    """Return the paths whose on-disk content differs from the code."""
    stale: list[Path] = []
    for name, model in _EXPORTS.items():
        path = output_dir / f"{name}.schema.json"
        expected = _render(build_schema(model, name))
        if not path.exists() or path.read_text(encoding="utf-8") != expected:
            stale.append(path)
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the checked-in schemas are stale.",
    )
    args = parser.parse_args(argv)

    if args.check:
        stale = check(args.output_dir)
        if stale:
            print("Schema files are stale; re-run without --check:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"{len(_EXPORTS)} schema files are up to date.")
        return 0

    for path in export(args.output_dir):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
