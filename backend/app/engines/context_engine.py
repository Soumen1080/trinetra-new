"""Pure context enrichment used before a Phase-5 assessment."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping

from app.models.enums import BusinessCriticality, ProvenanceTier
from app.schemas.common import Provenance
from app.schemas.context import ArtefactContext, DependencyEdge

_CRITICALITY_RANK = {
    BusinessCriticality.CRITICAL: 4,
    BusinessCriticality.HIGH: 3,
    BusinessCriticality.MEDIUM: 2,
    BusinessCriticality.LOW: 1,
    BusinessCriticality.UNKNOWN: 0,
}


def inherit_dependency_criticality(
    contexts: Iterable[ArtefactContext],
    edges: Iterable[DependencyEdge],
    *,
    application_criticalities: Mapping[str, BusinessCriticality] | None = None,
) -> dict[str, ArtefactContext]:
    """Fill unknown artefact criticality from the owning dependency graph.

    Criticality flows in an edge's declared direction (application -> library
    -> algorithm).  A directly supplied artefact value is never overwritten;
    among inherited paths, the highest known criticality governs.  The derived
    value retains provenance so an analyst can see which dependency root made
    an otherwise unknown algorithm business-critical.
    """
    resolved = {
        context.artefact_id: context.model_copy(deep=True) for context in contexts
    }
    graph: dict[str, list[str]] = {}
    for edge in edges:
        graph.setdefault(edge.source_id, []).append(edge.target_id)

    candidates: dict[str, tuple[BusinessCriticality, str]] = {}
    for context in resolved.values():
        if context.business_criticality is not BusinessCriticality.UNKNOWN:
            candidates[context.artefact_id] = (
                context.business_criticality,
                context.artefact_id,
            )
    for application_id, criticality in (application_criticalities or {}).items():
        if criticality is not BusinessCriticality.UNKNOWN:
            candidates[application_id] = (criticality, application_id)

    queue = deque(candidates.items())
    inherited: dict[str, tuple[BusinessCriticality, str]] = {}
    while queue:
        source_id, (criticality, root_id) = queue.popleft()
        for target_id in graph.get(source_id, []):
            existing = candidates.get(target_id)
            existing_rank = _CRITICALITY_RANK[existing[0]] if existing else -1
            if existing_rank >= _CRITICALITY_RANK[criticality]:
                continue
            candidates[target_id] = (criticality, root_id)
            inherited[target_id] = (criticality, root_id)
            queue.append((target_id, (criticality, root_id)))

    for artefact_id, context in resolved.items():
        inherited_value = inherited.get(artefact_id)
        if (
            context.business_criticality is not BusinessCriticality.UNKNOWN
            or inherited_value is None
        ):
            continue
        criticality, root_id = inherited_value
        context.business_criticality = criticality
        context.provenance["business_criticality"] = Provenance(
            tier=ProvenanceTier.ORG_PRESET,
            source_detail=f"inherited from dependency root {root_id}",
        )
    return resolved


__all__ = ["inherit_dependency_criticality"]
