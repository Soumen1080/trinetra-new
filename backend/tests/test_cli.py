"""Tests for Trinetra Unified CLI (11.6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cli import main
from app.services.cbom_ingest import ingest_document

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPO_ROOT / "tests" / "golden" / "positive-fixtures.cbom.json"


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["version"])
    assert code == 0
    captured = capsys.readouterr()
    assert "trinetra 0.1.0" in captured.out


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_scan_sarif_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    if not GOLDEN.exists():
        pytest.skip(f"Golden CBOM not found: {GOLDEN}")

    sarif_file = tmp_path / "results.sarif"
    code = main([
        "scan",
        "--cbom", str(GOLDEN),
        "--sarif-output", str(sarif_file),
    ])
    assert code == 0
    assert sarif_file.exists()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) > 0


def test_cli_scan_fail_on_policy_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    if not GOLDEN.exists():
        pytest.skip(f"Golden CBOM not found: {GOLDEN}")

    doc = json.loads(GOLDEN.read_text(encoding="utf-8"))
    artefacts = ingest_document(doc, scan_target="https://git.example.org/test").artefacts
    contexts = {
        artefact.artefact_id: {
            "data_category": "aadhaar_pii",
            "data_classification": "internal",
            "business_criticality": "critical",
            "exposure": "internet",
            "migration_time_years": 4,
            "provenance": {
                "data_category": {"tier": "scanner_evidence"},
                "migration_time_years": {"tier": "user"},
            },
        }
        for artefact in artefacts
    }
    context_file = tmp_path / "contexts.json"
    context_file.write_text(json.dumps(contexts), encoding="utf-8")

    out_file = tmp_path / "out.json"
    # Findings score P1 (high), so --fail-on high or --fail-on p1 must trigger exit 1
    code = main([
        "scan",
        "--cbom", str(GOLDEN),
        "--scan-target", "https://git.example.org/test",
        "--contexts", str(context_file),
        "--fail-on", "high",
        "--output", str(out_file),
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "[POLICY FAILURE]" in captured.err
    assert out_file.exists()


def test_cli_scan_fail_on_policy_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Valid CycloneDX 1.6 CBOM with safe primitive
    valid_cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "tools": [{"vendor": "Trinetra", "name": "scanner", "version": "1.0"}],
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "sha256-hash",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "hash",
                    },
                },
            }
        ],
    }
    cbom_file = tmp_path / "sha256.cbom.json"
    cbom_file.write_text(json.dumps(valid_cbom), encoding="utf-8")

    out_file = tmp_path / "out.json"
    code = main([
        "scan",
        "--cbom", str(cbom_file),
        "--fail-on", "critical",
        "--output", str(out_file),
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert "[POLICY PASS]" in captured.out
