"""Diff reports: scan N vs scan N−1 (plan task 7.8).

Compares two ``ScanResult`` objects by artefact identity (deterministic id)
and produces a structured delta: what appeared, what was fixed, what changed,
and posture-level statistics.

The output is a ``DiffReport`` which can be serialised to JSON or injected
into the PDF/HTML report templates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.schemas.artefact import CryptoArtefact
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult


@dataclass
class ArtefactChange:
    """Field-level changes for a single artefact between two scans."""

    artefact_id: str
    name: str
    changes: dict[str, tuple[Any, Any]]  # field -> (old, new)


@dataclass
class PostureDelta:
    """High-level posture shift between two scans."""

    total_before: int = 0
    total_after: int = 0
    quantum_vulnerable_before: int = 0
    quantum_vulnerable_after: int = 0
    added_count: int = 0
    removed_count: int = 0
    changed_count: int = 0


@dataclass
class DiffReport:
    """The complete diff between two scans."""

    baseline_scan_id: str
    current_scan_id: str
    added: list[CryptoArtefact] = field(default_factory=list)
    removed: list[CryptoArtefact] = field(default_factory=list)
    changed: list[ArtefactChange] = field(default_factory=list)
    unchanged_count: int = 0
    posture: PostureDelta = field(default_factory=PostureDelta)


def compute_diff(
    baseline: ScanResult,
    current: ScanResult,
    baseline_assessments: list[RiskAssessment] | None = None,
    current_assessments: list[RiskAssessment] | None = None,
) -> DiffReport:
    """Compare two scan results and produce a structured delta."""
    baseline_assessments = baseline_assessments or []
    current_assessments = current_assessments or []

    baseline_map = {a.artefact_id: a for a in baseline.deduplicated()}
    current_map = {a.artefact_id: a for a in current.deduplicated()}

    baseline_assessment_map = {a.artefact_id: a for a in baseline_assessments}
    current_assessment_map = {a.artefact_id: a for a in current_assessments}

    baseline_ids = set(baseline_map.keys())
    current_ids = set(current_map.keys())

    added_ids = current_ids - baseline_ids
    removed_ids = baseline_ids - current_ids
    common_ids = baseline_ids & current_ids

    added = [current_map[aid] for aid in sorted(added_ids)]
    removed = [baseline_map[rid] for rid in sorted(removed_ids)]

    changed: list[ArtefactChange] = []
    unchanged_count = 0

    for cid in sorted(common_ids):
        old = baseline_map[cid]
        new = current_map[cid]
        old_assessment = baseline_assessment_map.get(cid)
        new_assessment = current_assessment_map.get(cid)

        changes = _compare_artefact(old, new, old_assessment, new_assessment)
        if changes:
            changed.append(
                ArtefactChange(
                    artefact_id=cid, name=new.name, changes=changes
                )
            )
        else:
            unchanged_count += 1

    posture = PostureDelta(
        total_before=len(baseline_map),
        total_after=len(current_map),
        quantum_vulnerable_before=sum(
            1 for a in baseline_map.values() if a.is_quantum_vulnerable
        ),
        quantum_vulnerable_after=sum(
            1 for a in current_map.values() if a.is_quantum_vulnerable
        ),
        added_count=len(added),
        removed_count=len(removed),
        changed_count=len(changed),
    )

    return DiffReport(
        baseline_scan_id=baseline.scan_id,
        current_scan_id=current.scan_id,
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
        posture=posture,
    )


def _compare_artefact(
    old: CryptoArtefact,
    new: CryptoArtefact,
    old_assessment: RiskAssessment | None,
    new_assessment: RiskAssessment | None,
) -> dict[str, tuple[Any, Any]]:
    """Return field-level diffs between two versions of the same artefact."""
    changes: dict[str, tuple[Any, Any]] = {}

    # Core fields
    _diff_field(changes, "name", old.name, new.name)
    _diff_field(changes, "algorithm", old.algorithm, new.algorithm)
    _diff_field(
        changes,
        "quantum_vulnerability",
        old.quantum_vulnerability.value,
        new.quantum_vulnerability.value,
    )
    _diff_field(
        changes,
        "nist_security_level",
        old.nist_security_level.value,
        new.nist_security_level.value,
    )
    _diff_field(
        changes,
        "primitive",
        old.primitive.value if old.primitive else None,
        new.primitive.value if new.primitive else None,
    )

    # Assessment fields
    if old_assessment and new_assessment:
        _diff_field(
            changes,
            "risk_score",
            old_assessment.final_score,
            new_assessment.final_score,
        )
        _diff_field(
            changes,
            "priority",
            old_assessment.priority.value,
            new_assessment.priority.value,
        )
        _diff_field(
            changes,
            "mosca_urgent",
            old_assessment.mosca.is_urgent,
            new_assessment.mosca.is_urgent,
        )
    elif old_assessment or new_assessment:
        # Assessment appeared or disappeared
        old_score = old_assessment.final_score if old_assessment else None
        new_score = new_assessment.final_score if new_assessment else None
        if old_score != new_score:
            changes["risk_score"] = (old_score, new_score)

    return changes


def _diff_field(
    changes: dict[str, tuple[Any, Any]],
    field_name: str,
    old_value: Any,
    new_value: Any,
) -> None:
    if old_value != new_value:
        changes[field_name] = (old_value, new_value)


def export_diff_json(diff: DiffReport) -> str:
    """Serialise a diff report to JSON."""
    output: dict[str, Any] = {
        "baseline_scan_id": diff.baseline_scan_id,
        "current_scan_id": diff.current_scan_id,
        "posture": {
            "total_before": diff.posture.total_before,
            "total_after": diff.posture.total_after,
            "quantum_vulnerable_before": diff.posture.quantum_vulnerable_before,
            "quantum_vulnerable_after": diff.posture.quantum_vulnerable_after,
            "added_count": diff.posture.added_count,
            "removed_count": diff.posture.removed_count,
            "changed_count": diff.posture.changed_count,
        },
        "unchanged_count": diff.unchanged_count,
        "added": [
            {"artefact_id": a.artefact_id, "name": a.name, "asset_type": a.asset_type.value}
            for a in diff.added
        ],
        "removed": [
            {"artefact_id": a.artefact_id, "name": a.name, "asset_type": a.asset_type.value}
            for a in diff.removed
        ],
        "changed": [
            {
                "artefact_id": c.artefact_id,
                "name": c.name,
                "changes": {
                    k: {"old": v[0], "new": v[1]}
                    for k, v in c.changes.items()
                },
            }
            for c in diff.changed
        ],
    }
    return json.dumps(output, indent=2, sort_keys=False, default=str)


__all__ = [
    "ArtefactChange",
    "DiffReport",
    "PostureDelta",
    "compute_diff",
    "export_diff_json",
]
