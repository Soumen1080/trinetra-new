"""SPDX 3.0 export (plan task 7.2, secondary format).

Produces an SPDX 3.0 JSON-LD document from a ``ScanResult``.  SPDX 3.0
models software artefacts as ``Package`` or ``Snippet`` elements with
relationships; crypto findings are carried as annotations and extension
properties since the crypto profile is still maturing.

This exporter targets the ``Software`` and ``Security`` profiles of SPDX 3.0.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.models.enums import AssetType
from app.schemas.artefact import CryptoArtefact
from app.schemas.recommendation import PqcRecommendation
from app.schemas.risk import RiskAssessment
from app.schemas.scan import ScanResult

SPDX_SPEC_VERSION = "3.0.1"
SPDX_NAMESPACE = "https://spdx.org/rdf/3.0.1/terms"
TRINETRA_NAMESPACE = "https://trinetra.dev/spdx-extension/1.0"


def export_spdx(
    scan_result: ScanResult,
    assessments: list[RiskAssessment] | None = None,
    recommendations: list[PqcRecommendation] | None = None,
) -> str:
    """Export a scan result as an SPDX 3.0 JSON-LD string."""
    assessments = assessments or []
    recommendations = recommendations or []

    assessment_by_artefact = {a.artefact_id: a for a in assessments}
    recommendation_by_assessment = {r.assessment_id: r for r in recommendations}

    now = datetime.now(UTC).isoformat()
    doc_id = f"urn:spdx:trinetra-{scan_result.scan_id}"

    elements: list[dict[str, Any]] = []

    # Creation info — shared across all elements
    creation_info = {
        "specVersion": SPDX_SPEC_VERSION,
        "created": now,
        "createdBy": [f"urn:spdx:tool-trinetra-{scan_result.schema_version}"],
        "profile": ["software", "security"],
    }

    # Document element
    doc_element: dict[str, Any] = {
        "@type": "SpdxDocument",
        "@id": doc_id,
        "name": f"Trinetra CBOM — {scan_result.target.identifier}",
        "creationInfo": creation_info,
        "element": [],
        "rootElement": [doc_id],
    }

    # Target as a Package
    target_id = f"urn:spdx:package-{scan_result.scan_id}"
    target_pkg: dict[str, Any] = {
        "@type": "software_Package",
        "@id": target_id,
        "name": scan_result.target.display_name
        or scan_result.target.identifier,
        "creationInfo": creation_info,
        "software_downloadLocation": scan_result.target.identifier,
    }
    if scan_result.target.reference:
        target_pkg["software_packageVersion"] = scan_result.target.reference

    elements.append(target_pkg)
    doc_element["element"].append(target_id)

    # Each artefact as a Snippet with annotations
    for artefact in scan_result.deduplicated():
        assessment = assessment_by_artefact.get(artefact.artefact_id)
        rec = (
            recommendation_by_assessment.get(assessment.assessment_id)
            if assessment
            else None
        )
        snippet, relationships = _artefact_to_snippet(
            artefact, assessment, rec, creation_info, target_id,
        )
        elements.append(snippet)
        elements.extend(relationships)
        doc_element["element"].append(snippet["@id"])
        for rel in relationships:
            doc_element["element"].append(rel["@id"])

    doc_element["element"] = list(dict.fromkeys(doc_element["element"]))
    elements.insert(0, doc_element)

    # Wrap in JSON-LD context
    output: dict[str, Any] = {
        "@context": SPDX_NAMESPACE,
        "@graph": elements,
    }

    return json.dumps(output, indent=2, sort_keys=False, default=str)


def _artefact_to_snippet(
    artefact: CryptoArtefact,
    assessment: RiskAssessment | None,
    recommendation: PqcRecommendation | None,
    creation_info: dict[str, Any],
    target_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Map a crypto artefact to an SPDX Snippet + relationships."""
    snippet_id = f"urn:spdx:snippet-{artefact.artefact_id[:16]}"

    snippet: dict[str, Any] = {
        "@type": "software_Snippet",
        "@id": snippet_id,
        "name": artefact.name,
        "creationInfo": creation_info,
        "description": _artefact_description(artefact),
    }

    # Location via snippet range
    primary = artefact.evidence[0].location
    snippet["software_snippetFromFile"] = primary.path
    if primary.line is not None:
        snippet["software_lineRange"] = {
            "startPointer": {"lineNumber": primary.line},
        }
        if primary.end_line is not None:
            snippet["software_lineRange"]["endPointer"] = {
                "lineNumber": primary.end_line,
            }

    # Annotations for crypto properties
    annotations: list[dict[str, Any]] = []

    annotations.append(
        _annotation(
            snippet_id,
            "REVIEW",
            f"Asset type: {artefact.asset_type.value}",
            creation_info,
        )
    )
    annotations.append(
        _annotation(
            snippet_id,
            "REVIEW",
            f"Quantum vulnerability: {artefact.quantum_vulnerability.value}",
            creation_info,
        )
    )

    if assessment and assessment.final_score is not None:
        annotations.append(
            _annotation(
                snippet_id,
                "REVIEW",
                f"Risk score: {assessment.final_score}, "
                f"Priority: {assessment.priority.value}",
                creation_info,
            )
        )

    if recommendation and recommendation.recommended_algorithm:
        annotations.append(
            _annotation(
                snippet_id,
                "REVIEW",
                f"Recommended replacement: "
                f"{recommendation.recommended_algorithm}",
                creation_info,
            )
        )

    snippet["annotation"] = annotations

    # Extension properties for full crypto detail
    ext_props: dict[str, Any] = {
        "@type": "trinetra:CryptoProperties",
        "trinetra:assetType": artefact.asset_type.value,
        "trinetra:quantumVulnerability": artefact.quantum_vulnerability.value,
    }
    if artefact.algorithm:
        ext_props["trinetra:algorithm"] = artefact.algorithm
    if artefact.primitive:
        ext_props["trinetra:primitive"] = artefact.primitive.value

    snippet["extension"] = ext_props

    # Relationship to target
    rel_id = f"urn:spdx:rel-{uuid.uuid4().hex[:12]}"
    relationship: dict[str, Any] = {
        "@type": "Relationship",
        "@id": rel_id,
        "relationshipType": "contains",
        "from": target_id,
        "to": [snippet_id],
        "creationInfo": creation_info,
    }

    return snippet, [relationship]


def _annotation(
    subject_id: str,
    annotation_type: str,
    statement: str,
    creation_info: dict[str, Any],
) -> dict[str, Any]:
    return {
        "@type": "Annotation",
        "@id": f"urn:spdx:ann-{uuid.uuid4().hex[:12]}",
        "annotationType": annotation_type,
        "subject": subject_id,
        "statement": statement,
        "creationInfo": creation_info,
    }


def _artefact_description(artefact: CryptoArtefact) -> str:
    """Build a human-readable description of the artefact."""
    parts = [f"Cryptographic artefact: {artefact.name}"]
    parts.append(f"Type: {artefact.asset_type.value}")
    if artefact.algorithm:
        parts.append(f"Algorithm: {artefact.algorithm}")
    if artefact.primitive:
        parts.append(f"Primitive: {artefact.primitive.value}")
    parts.append(
        f"Quantum status: {artefact.quantum_vulnerability.value}"
    )
    parts.append(f"Location: {artefact.primary_location}")
    return ". ".join(parts)


__all__ = ["export_spdx"]
