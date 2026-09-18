"""Pure migration-wave planning; it does not turn planning observations into risk."""

from __future__ import annotations

import math
from collections.abc import Iterable

from app.models.enums import Priority
from app.schemas.artefact import HardwareModuleDetail
from app.schemas.context import DependencyEdge
from app.schemas.recommendation import (
    MigrationCandidate,
    MigrationPlan,
    MigrationPlanItem,
)


def _mosca_deadline_year(candidate: MigrationCandidate) -> int | None:
    """Return a conservative year representation of Z, without inventing a date."""
    z_years = candidate.assessment.mosca.z_years
    if z_years is None:
        return None
    return candidate.assessment.assessed_at.year + math.floor(z_years)


def _hardware_action(candidate: MigrationCandidate) -> tuple[str, list[str]]:
    detail = candidate.artefact.detail
    if not isinstance(detail, HardwareModuleDetail):
        return "none", []
    if detail.supports_pqc is False:
        return (
            "hardware_purchase",
            [
                "The observed HSM firmware is not PQC-capable: plan a hardware "
                "purchase, not a code-only change. Its cost remains unmeasured."
            ],
        )
    if detail.supports_pqc is None:
        return (
            "verify_firmware",
            [
                "HSM PQC firmware support is unmeasured; verify the vendor's "
                "supported upgrade path before scheduling the migration."
            ],
        )
    return "none", []


def _agility_notes(candidate: MigrationCandidate) -> list[str]:
    observation = candidate.crypto_agility
    if observation.status == "hardcoded":
        return [
            "Crypto agility is observed as hardcoded; moving the algorithm into "
            "a config-driven provider will reduce the next migration cost. "
            f"{observation.evidence}"
        ]
    if observation.status == "config_driven":
        return [
            f"Crypto agility is observed as config-driven. {observation.evidence}"
        ]
    return [
        "Crypto-agility implementation style is unmeasured; do not assume a "
        "hardcoded constant or a configurable provider."
    ]


def _waves(
    candidates: dict[str, MigrationCandidate], dependencies: Iterable[DependencyEdge]
) -> dict[str, set[str]]:
    """Map a consumer to in-scope prerequisites (the edge target goes first)."""
    prerequisites = {artefact_id: set() for artefact_id in candidates}
    for edge in dependencies:
        if edge.source_id in candidates and edge.target_id in candidates:
            prerequisites[edge.source_id].add(edge.target_id)
    return prerequisites


def plan_migration_waves(
    candidates: Iterable[MigrationCandidate],
    dependencies: Iterable[DependencyEdge] = (),
) -> MigrationPlan:
    """Plan dependency-first waves, ordered by the earliest Mosca deadline.

    Independent items share a wave and are then ordered by their deadline. A
    dependency cycle cannot safely be given an automatic sequence, so it raises
    rather than returning a plausible but wrong plan.
    """
    candidate_list = list(candidates)
    candidate_by_artefact = {
        candidate.artefact.artefact_id: candidate for candidate in candidate_list
    }
    if len(candidate_by_artefact) != len(candidate_list):
        raise ValueError("migration planning accepts one candidate per artefact")

    for candidate in candidate_by_artefact.values():
        assessment = candidate.assessment
        if assessment.priority not in {Priority.P0, Priority.P1}:
            raise ValueError("migration planning accepts actionable recommendations only")

    prerequisite_ids = _waves(candidate_by_artefact, dependencies)
    wave_by_artefact: dict[str, int] = {}
    visiting: set[str] = set()

    def wave_for(artefact_id: str) -> int:
        known = wave_by_artefact.get(artefact_id)
        if known is not None:
            return known
        if artefact_id in visiting:
            raise ValueError("dependency cycle requires manual migration sequencing")
        visiting.add(artefact_id)
        prerequisite_waves = [
            wave_for(prerequisite_id)
            for prerequisite_id in prerequisite_ids[artefact_id]
        ]
        visiting.remove(artefact_id)
        result = 1 + max(prerequisite_waves, default=0)
        wave_by_artefact[artefact_id] = result
        return result

    for artefact_id in candidate_by_artefact:
        wave_for(artefact_id)

    items: list[MigrationPlanItem] = []
    for artefact_id, candidate in candidate_by_artefact.items():
        hardware_action, hardware_notes = _hardware_action(candidate)
        notes = _agility_notes(candidate) + hardware_notes
        if candidate.recommendation.requires_manual_review:
            notes.append("The replacement itself requires manual review.")
        items.append(
            MigrationPlanItem(
                recommendation_id=candidate.recommendation.recommendation_id,
                assessment_id=candidate.assessment.assessment_id,
                artefact_id=artefact_id,
                migration_wave=wave_by_artefact[artefact_id],
                mosca_deadline_year=_mosca_deadline_year(candidate),
                dependency_ids=sorted(prerequisite_ids[artefact_id]),
                hardware_action=hardware_action,
                crypto_agility=candidate.crypto_agility,
                notes=notes,
            )
        )

    return MigrationPlan(
        items=sorted(
            items,
            key=lambda item: (
                item.migration_wave,
                item.mosca_deadline_year is None,
                item.mosca_deadline_year or 0,
                item.artefact_id,
            ),
        )
    )


__all__ = ["plan_migration_waves"]
